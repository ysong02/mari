/**
 * @file
 * @ingroup     app
 * @brief       Related-work Gateway NET core — EDHOC subtype routing for the
 *              Initiator-on-node design.
 *
 *
 * @author Geovane Fedrecheski <geovane.fedrecheski@inria.fr>
 * @author Alexandre Abadie <alexandre.abadie@inria.fr>
 * @author Yuxuan Song <yuxuan.song@inria.fr>
 * @copyright Inria, 2025
 */
#include <nrf.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ipc.h"

#include "mr_device.h"
#include "mr_timer_hf.h"
#include "mr_radio.h"
#include "mac.h"
#include "association.h"
#include "scheduler.h"
#include "mari.h"
#include "packet.h"
#include "models.h"

#include "metrics.h"

#include "models.h"
#include "queue.h"

//=========================== defines =========================================

#define MAURA_APP_TIMER_DEV 1

// Unacked broadcast: send several copies, spaced out, so a short burst of
// interference around round-transition time can't make a node miss all of
// them and keep running as a zombie from the previous round. Kept tight
// (~1 slotframe apart) so this doesn't eat much of the round's time budget --
// the seq-based dedup in the node (GPREGRET) is what actually prevents a
// node that already rebooted from resetting again on a later copy.
#define REBOOT_BROADCAST_COPIES               8
#define REBOOT_REBROADCAST_INTERVAL_SLOTFRAMES 1

typedef struct {
    bool uart_to_radio_packet_ready;
    bool to_uart_gateway_loop_ready;
} gateway_vars_t;

typedef struct {
    bool     ready;
    uint64_t node_id;
    uint8_t  data[MARI_EDHOC_MAX_MSG_LEN];
    uint8_t  len;
} edhoc_pending_t;

// A single slot loses events to a race if a second one arrives before the main loop drains the first (already hit msg1/uplink/NODE_LEFT); a ring removes that whole bug class.
#define EVENT_RING_SIZE 4

typedef struct {
    mr_event_t      event;
    mr_event_data_t event_data;
} gw_event_t;

//=========================== variables =======================================

static gateway_vars_t   _app_vars        = {0};
static edhoc_pending_t  _edhoc_msg1_pend = {0};

// Uplink EDHOC (the attest tag) needs its own slot for the same reason msg1
// does -- see the comment in _mari_event_callback().
static edhoc_pending_t _edhoc_uplink_pend = {0};

typedef struct {
    bool     ready;
    uint64_t node_id;
    uint8_t  joined;
    uint8_t  len;
} craft_diag_pending_t;

// Relays uplink-RX diagnostics over IPC/UART instead of RTT, which perturbs the timing being diagnosed.
static craft_diag_pending_t _craft_diag_pend = {0};

// Lock-free SPSC ring: producer (IRQ) writes head, consumer (main loop) writes tail.
static gw_event_t       _event_ring[EVENT_RING_SIZE];
static volatile uint8_t _event_ring_head = 0;
static volatile uint8_t _event_ring_tail = 0;

// Count of events dropped because the ring was full (main loop fell behind).
static volatile uint32_t _dropped_events = 0;

static uint64_t _reboot_cleanup_asn = 0;  ///< ASN when the post-reboot wipe is due (0 = none pending)
static uint64_t _reboot_issued_asn  = 0;  ///< ASN the reboot was issued at; nodes heard from since must survive the wipe
static uint8_t  _reboot_broadcasts_remaining = 0;  ///< remaining spaced-out rebroadcast copies (0 = none pending)
static uint64_t _next_reboot_tx_asn          = 0;  ///< ASN the next spaced-out rebroadcast copy is due

extern schedule_t schedule_tiny, schedule_medium, schedule_big, schedule_huge;
static schedule_t *schedule_app = &schedule_huge;

volatile __attribute__((section(".shared_data"))) ipc_shared_data_t ipc_shared_data;

static uint8_t _ipc_tx_buf[UINT8_MAX];

// Same seq for every repeated copy of one reboot_all campaign, so the node can
// tell a late duplicate apart from a genuinely new reboot instruction.
static uint8_t _reboot_seq = 0;

static void _send_reboot_broadcast(void) {
    uint8_t reboot_buf[sizeof(mr_packet_header_t) + 2];
    memset(reboot_buf, 0, sizeof(reboot_buf));
    mr_packet_header_t *hdr = (mr_packet_header_t *)reboot_buf;
    hdr->version    = 2;
    hdr->type       = MARI_PACKET_DATA;
    hdr->network_id = mr_assoc_get_network_id();
    hdr->dst        = MARI_BROADCAST_ADDRESS;
    hdr->src        = mr_device_id();
    reboot_buf[sizeof(mr_packet_header_t)]     = MARI_REBOOT_PAYLOAD_TAG;
    reboot_buf[sizeof(mr_packet_header_t) + 1] = _reboot_seq;
    mari_tx(reboot_buf, sizeof(reboot_buf));
}

static void _mari_event_callback(mr_event_t event, mr_event_data_t event_data) {
    if (event == MARI_EDHOC_MSG2) {
        // printf("[GW] connect request (MSG2 raw event) from 0x%016llX, %u B\n",
        //        (unsigned long long)event_data.data.edhoc.node_id, (unsigned)event_data.data.edhoc.len);
        _edhoc_msg1_pend.node_id = event_data.data.edhoc.node_id;
        _edhoc_msg1_pend.len     = event_data.data.edhoc.len;
        memcpy(_edhoc_msg1_pend.data, event_data.data.edhoc.data, event_data.data.edhoc.len);
        _edhoc_msg1_pend.ready = true;
        return;
    }

    if (event == MARI_CRAFT_DIAG_UPLINK_RX) {
        _craft_diag_pend.node_id = event_data.data.edhoc.node_id;
        _craft_diag_pend.len     = event_data.data.edhoc.len;
        _craft_diag_pend.joined  = (uint8_t)event_data.tag;
        _craft_diag_pend.ready   = true;
        return;
    }

    // Attest tag arrives as a plain MARI_NEW_PACKET; give it its own slot too, same reason as msg1.
    if (event == MARI_NEW_PACKET) {
        const mari_packet_t *p = &event_data.data.new_packet;
        if (p->payload_len >= 2 && p->payload[0] == MARI_EDHOC_PAYLOAD_TAG) {
            uint8_t elen = p->payload[1];
            if (elen > 0 && elen <= MARI_EDHOC_MAX_MSG_LEN &&
                (uint8_t)(2u + elen) <= p->payload_len) {
                _edhoc_uplink_pend.node_id = p->header->src;
                _edhoc_uplink_pend.len     = elen;
                memcpy(_edhoc_uplink_pend.data, p->payload + 2, elen);
                _edhoc_uplink_pend.ready = true;
                return;
            }
            CRAFT_DIAG_PRINTF("[DIAG-GW] malformed uplink EDHOC: elen=%u payload_len=%u\n",
                              (unsigned)elen, (unsigned)p->payload_len);
        }
    }

    uint8_t head      = _event_ring_head;
    uint8_t next_head = (uint8_t)((head + 1) % EVENT_RING_SIZE);
    if (next_head == _event_ring_tail) {
        _dropped_events++;  // ring full -- main loop hasn't caught up
        return;
    }
    _event_ring[head].event      = event;
    _event_ring[head].event_data = event_data;
    __DMB();  // event contents must be visible before head publishes them
    _event_ring_head = next_head;
}

static void _to_uart_gateway_loop(void) {
    _app_vars.to_uart_gateway_loop_ready = true;
}

static void _ipc_send_to_app(const uint8_t *data, uint8_t len) {
    uint32_t timeout = 200000;
    while (!ipc_shared_data.radio_to_uart_free && timeout--) { __NOP(); }
    ipc_shared_data.radio_to_uart_free = false;
    memcpy((void *)ipc_shared_data.radio_to_uart, data, len);
    ipc_shared_data.radio_to_uart_len  = len;
    __DSB();
    NRF_IPC_NS->TASKS_SEND[IPC_CHAN_RADIO_TO_UART] = 1;
}

static void _init_ipc(void) {
    NRF_IPC_NS->INTENSET                            = (1 << IPC_CHAN_UART_TO_RADIO);
    NRF_IPC_NS->SEND_CNF[IPC_CHAN_RADIO_TO_UART]    = (1 << IPC_CHAN_RADIO_TO_UART);
    NRF_IPC_NS->RECEIVE_CNF[IPC_CHAN_UART_TO_RADIO] = (1 << IPC_CHAN_UART_TO_RADIO);
    NVIC_EnableIRQ(IPC_IRQn);
    NVIC_ClearPendingIRQ(IPC_IRQn);
    NVIC_SetPriority(IPC_IRQn, IPC_IRQ_PRIORITY);
}

int main(void) {
    printf("Hello mari gateway net core\n");

    mr_timer_hf_init(MAURA_APP_TIMER_DEV);
    _init_ipc();

    mari_init(MARI_GATEWAY, 0xa3, schedule_app, &_mari_event_callback);

    mr_timer_hf_set_periodic_us(MAURA_APP_TIMER_DEV, 3, mr_scheduler_get_duration_us(), &_to_uart_gateway_loop);

    ipc_shared_data.net_ready = true;

    while (1) {
        __WFE();

        // Spaced-out reboot rebroadcast: fire the next copy once its ASN is due.
        if (_reboot_broadcasts_remaining > 0 && mr_mac_get_asn() >= _next_reboot_tx_asn) {
            _send_reboot_broadcast();
            _reboot_broadcasts_remaining--;
            _next_reboot_tx_asn += REBOOT_REBROADCAST_INTERVAL_SLOTFRAMES *
                                    mr_scheduler_get_active_schedule_slot_count();
        }

        // Post-reboot association wipe, deferred until the broadcast copies are out.
        if (_reboot_cleanup_asn != 0 && mr_mac_get_asn() >= _reboot_cleanup_asn) {
            _reboot_cleanup_asn = 0;
            CRAFT_DIAG_PRINTF("[DIAG-GW] reboot cleanup: wiping association table\n");
            mr_assoc_gateway_remove_all_nodes(_reboot_issued_asn);
            mr_queue_gateway_reset_edhoc_state();
        }

        while (_event_ring_tail != _event_ring_head) {
            mr_event_t      event      = _event_ring[_event_ring_tail].event;
            mr_event_data_t event_data = _event_ring[_event_ring_tail].event_data;
            __DMB();  // finish reading the slot before publishing tail (frees it for the producer)
            _event_ring_tail = (uint8_t)((_event_ring_tail + 1) % EVENT_RING_SIZE);

            bool    send_to_uart = false;
            uint8_t send_len     = 0;

            switch (event) {
                case MARI_NEW_PACKET:
                {
                    if (metrics_is_probe(event_data.data.new_packet.payload,
                                         event_data.data.new_packet.payload_len)) {
                        metrics_handle_rx_probe(event_data.data.new_packet.header->src,
                                                event_data.data.new_packet.payload);
                    }

                    // Uplink EDHOC (attest tag) is intercepted in
                    // _mari_event_callback() and drained from its own slot
                    // below -- it never reaches this switch.

                    send_len       = event_data.data.new_packet.len + 1;
                    _ipc_tx_buf[0] = MARI_EDGE_DATA;
                    memcpy(_ipc_tx_buf + 1, event_data.data.new_packet.header,
                           event_data.data.new_packet.len);
                    send_to_uart = true;
                    break;
                }
                case MARI_KEEPALIVE:
                    send_len       = 1 + sizeof(uint64_t);
                    _ipc_tx_buf[0] = MARI_EDGE_KEEPALIVE;
                    memcpy(_ipc_tx_buf + 1, &event_data.data.node_info.node_id, sizeof(uint64_t));
                    send_to_uart = true;
                    break;
                case MARI_NODE_JOINED:
                    CRAFT_DIAG_PRINTF("[DIAG-GW] NODE_JOINED 0x%08X%08X\n",
                                      CRAFT_DIAG_ID_HI(event_data.data.node_info.node_id),
                                      CRAFT_DIAG_ID_LO(event_data.data.node_info.node_id));
                    metrics_add_node(event_data.data.node_info.node_id);
                    send_len       = 1 + sizeof(uint64_t);
                    _ipc_tx_buf[0] = MARI_EDGE_NODE_JOINED;
                    memcpy(_ipc_tx_buf + 1, &event_data.data.node_info.node_id, sizeof(uint64_t));
                    send_to_uart = true;
                    break;
                case MARI_NODE_LEFT:
                    CRAFT_DIAG_PRINTF("[DIAG-GW] NODE_LEFT 0x%08X%08X tag=%d\n",
                                      CRAFT_DIAG_ID_HI(event_data.data.node_info.node_id),
                                      CRAFT_DIAG_ID_LO(event_data.data.node_info.node_id),
                                      (int)event_data.tag);
                    metrics_clear_node(event_data.data.node_info.node_id);
                    // Reason tag appended after node_id so the edge knows WHY, not just that it left (see mr_event_tag_t in models.h).
                    send_len       = 1 + sizeof(uint64_t) + 1;
                    _ipc_tx_buf[0] = MARI_EDGE_NODE_LEFT;
                    memcpy(_ipc_tx_buf + 1, &event_data.data.node_info.node_id, sizeof(uint64_t));
                    _ipc_tx_buf[1 + sizeof(uint64_t)] = (uint8_t)event_data.tag;
                    send_to_uart = true;
                    break;
                default:
                    break;
            }

            if (send_to_uart) {
                _ipc_send_to_app(_ipc_tx_buf, send_len);
            }
        }

        // Drain the uplink attest tag (own slot, see _mari_event_callback)
        if (_edhoc_uplink_pend.ready) {
            _edhoc_uplink_pend.ready = false;
            uint64_t src  = _edhoc_uplink_pend.node_id;
            uint8_t  elen = _edhoc_uplink_pend.len;
            uint8_t  pos  = 0;
            _ipc_tx_buf[pos++] = MARI_EDGE_EDHOC;
            _ipc_tx_buf[pos++] = MARI_EDHOC_SUBTYPE_MSG3;
            memcpy(_ipc_tx_buf + pos, &src, sizeof(uint64_t));
            pos += sizeof(uint64_t);
            memcpy(_ipc_tx_buf + pos, _edhoc_uplink_pend.data, elen);
            pos += elen;
            CRAFT_DIAG_PRINTF("[DIAG-GW] uplink EDHOC(MSG3) from 0x%08X%08X %u B -> edge\n",
                              CRAFT_DIAG_ID_HI(src), CRAFT_DIAG_ID_LO(src), (unsigned)elen);
            _ipc_send_to_app(_ipc_tx_buf, pos);
        }

        // Drain pending msg1 from join request (stored separately to avoid MARI_NODE_JOINED race)
        if (_edhoc_msg1_pend.ready) {
            _edhoc_msg1_pend.ready = false;
            uint64_t src  = _edhoc_msg1_pend.node_id;
            uint8_t  elen = _edhoc_msg1_pend.len;
            uint8_t  pos  = 0;
            _ipc_tx_buf[pos++] = MARI_EDGE_EDHOC;
            _ipc_tx_buf[pos++] = MARI_EDHOC_SUBTYPE_MSG1;
            memcpy(_ipc_tx_buf + pos, &src, sizeof(uint64_t));
            pos += sizeof(uint64_t);
            memcpy(_ipc_tx_buf + pos, _edhoc_msg1_pend.data, elen);
            pos += elen;
            CRAFT_DIAG_PRINTF("[DIAG-GW] uplink EDHOC(MSG1) from 0x%08X%08X %u B -> edge\n",
                              CRAFT_DIAG_ID_HI(src), CRAFT_DIAG_ID_LO(src), (unsigned)elen);
            _ipc_send_to_app(_ipc_tx_buf, pos);
        }

        // Drain the debug-free uplink RX diagnostic; not gated behind CRAFT_DIAG since it's a cheap IPC send, not RTT.
        if (_craft_diag_pend.ready) {
            _craft_diag_pend.ready = false;
            uint64_t src = _craft_diag_pend.node_id;
            _ipc_tx_buf[0] = MARI_EDGE_CRAFT_DIAG;
            memcpy(_ipc_tx_buf + 1, &src, sizeof(uint64_t));
            _ipc_tx_buf[1 + sizeof(uint64_t)] = _craft_diag_pend.joined;
            _ipc_tx_buf[2 + sizeof(uint64_t)] = _craft_diag_pend.len;
            _ipc_send_to_app(_ipc_tx_buf, 3 + sizeof(uint64_t));
        }

        if (_app_vars.uart_to_radio_packet_ready) {
            _app_vars.uart_to_radio_packet_ready = false;
            uint8_t packet_type = ipc_shared_data.uart_to_radio_tx[0];

            if (packet_type == MARI_EDGE_REBOOT_ALL) {
                if (ipc_shared_data.uart_to_radio_len >= 2) {
                    _reboot_seq = ipc_shared_data.uart_to_radio_tx[1];
                }
                CRAFT_DIAG_PRINTF("[DIAG-GW] RX reboot_all from edge (seq=%u) -- broadcasting %u copies over time\n",
                                  (unsigned)_reboot_seq, (unsigned)REBOOT_BROADCAST_COPIES);
                _send_reboot_broadcast();

                // Spread the remaining copies out (see REBOOT_REBROADCAST_INTERVAL_SLOTFRAMES)
                // instead of firing them all in one burst, so a short-lived interference
                // window can't make a node miss every single copy.
                _reboot_issued_asn           = mr_mac_get_asn();
                _reboot_broadcasts_remaining = REBOOT_BROADCAST_COPIES - 1;
                _next_reboot_tx_asn          = _reboot_issued_asn +
                                               REBOOT_REBROADCAST_INTERVAL_SLOTFRAMES *
                                                   mr_scheduler_get_active_schedule_slot_count();

                // Defer the association wipe until after the whole broadcast campaign
                // (plus one extra slotframe of margin), so it can't run ahead of the
                // last copies still being sent.
                _reboot_cleanup_asn = _reboot_issued_asn +
                                      (REBOOT_BROADCAST_COPIES * REBOOT_REBROADCAST_INTERVAL_SLOTFRAMES + 1) *
                                          mr_scheduler_get_active_schedule_slot_count();
                continue;
            }

            // kick node requested by edge (attestation failure)
            if (packet_type == MARI_EDGE_KICK_NODE) {
                if (ipc_shared_data.uart_to_radio_len >= 1 + (uint8_t)sizeof(uint64_t)) {
                    uint64_t node_id;
                    memcpy(&node_id, (uint8_t *)ipc_shared_data.uart_to_radio_tx + 1,
                           sizeof(uint64_t));
                    mr_assoc_gateway_remove_node(node_id);
                }
                continue;
            }

            if (packet_type == MARI_EDGE_EDHOC) {
                uint8_t  subtype  = ipc_shared_data.uart_to_radio_tx[1];
                uint8_t *body     = (uint8_t *)ipc_shared_data.uart_to_radio_tx + 2;
                uint8_t  body_len = (uint8_t)(ipc_shared_data.uart_to_radio_len - 2);

                // MSG2 from edge → put in join response for the addressed node
                if (subtype == MARI_EDHOC_SUBTYPE_MSG2 && body_len > sizeof(uint64_t)) {
                    uint64_t node_id;
                    memcpy(&node_id, body, sizeof(uint64_t));
                    uint8_t *msg2_data = body + sizeof(uint64_t);
                    uint8_t  msg2_len  = body_len - (uint8_t)sizeof(uint64_t);
                    CRAFT_DIAG_PRINTF("[DIAG-GW] RX connect reply from edge for 0x%08X%08X (%u B)\n",
                                      CRAFT_DIAG_ID_HI(node_id), CRAFT_DIAG_ID_LO(node_id), (unsigned)msg2_len);
                    // Reuse mr_queue_set_edhoc_msg3: finalizes the pending join response
                    mr_queue_set_edhoc_msg3(node_id, msg2_data, msg2_len);
                }
                continue;
            }

            if (packet_type != MARI_EDGE_DATA) { continue; }

            uint8_t *mari_frame     = (uint8_t *)ipc_shared_data.uart_to_radio_tx + 1;
            uint8_t  mari_frame_len = ipc_shared_data.uart_to_radio_len - 1;
            mr_packet_header_t *header = (mr_packet_header_t *)mari_frame;
            header->src        = mr_device_id();
            header->network_id = mr_assoc_get_network_id();
            uint8_t *payload     = mari_frame + sizeof(mr_packet_header_t);
            uint8_t  payload_len = mari_frame_len - (uint8_t)sizeof(mr_packet_header_t);
            if (metrics_is_probe(payload, payload_len)) {
                metrics_handle_tx_probe(header->dst, payload);
            }
            mari_tx(mari_frame, mari_frame_len);
        }

        if (_app_vars.to_uart_gateway_loop_ready) {
            _app_vars.to_uart_gateway_loop_ready = false;
#if CRAFT_DIAG
            // Report only on change: once per slotframe would be far too noisy.
            {
                static uint32_t last_reported_drops = 0;
                if (_dropped_events != last_reported_drops) {
                    last_reported_drops = _dropped_events;
                    CRAFT_DIAG_PRINTF("[DIAG-GW] events dropped, ring full (depth %u): %u\n",
                                      (unsigned)EVENT_RING_SIZE, (unsigned)last_reported_drops);
                }
            }
#endif
            _ipc_tx_buf[0] = MARI_EDGE_GATEWAY_INFO;
            size_t len     = mr_build_uart_packet_gateway_info(_ipc_tx_buf + 1);
            _ipc_send_to_app(_ipc_tx_buf, 1 + (uint8_t)len);
        }

        mari_event_loop();
    }
}

void IPC_IRQHandler(void) {
    if (NRF_IPC_NS->EVENTS_RECEIVE[IPC_CHAN_UART_TO_RADIO]) {
        NRF_IPC_NS->EVENTS_RECEIVE[IPC_CHAN_UART_TO_RADIO] = 0;
        _app_vars.uart_to_radio_packet_ready               = true;
    }
}
