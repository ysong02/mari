/**
 * @file
 * @ingroup     app
 *
 * @brief       Mari Gateway application (radio side)
 *
 * @author Geovane Fedrecheski <geovane.fedrecheski@inria.fr>
 * @author Alexandre Abadie <alexandre.abadie@inria.fr>
 *
 * @copyright Inria, 2025-now
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

//=========================== defines ==========================================

#define MARI_APP_NET_CONFIG_START_ADDRESS (0x0103f800)  // start of the last page (2KB) of the flash (0x01000000 + 0x00040000 - 0x800)
#define MARI_APP_CONFIG_MAGIC_VALUE       (0x5753524D)  // "SWRM"

#define MARI_APP_TIMER_DEV 1

typedef struct {
    mr_event_t      mari_event;
    mr_event_data_t mari_event_data;
    bool            mari_event_ready;
    bool            uart_to_radio_packet_ready;
    bool            to_uart_gateway_loop_ready;
    uint32_t        tx_count;
    uint32_t        rx_count;
} gateway_vars_t;

// Dedicated buffer for EDHOC msg2: fired from interrupt alongside MARI_NODE_JOINED,
// so the single-slot event system would overwrite it before the main loop can read it.
typedef struct {
    bool     ready;
    uint64_t node_id;
    uint8_t  data[MARI_EDHOC_MAX_MSG_LEN];
    uint8_t  len;
} edhoc_msg2_pending_t;

typedef struct __attribute__((packed)) {
    uint32_t magic;       // to detect if config is valid (must equal MARI_APP_CONFIG_MAGIC_VALUE)
    uint32_t has_net_id;  // 1 if net_id is provisioned; otherwise fall back to the default
    uint32_t net_id;      // Mari network ID, meaningful only when has_net_id == 1
} mari_app_config_t;

//=========================== variables ========================================

gateway_vars_t       _app_vars        = { 0 };
edhoc_msg2_pending_t _edhoc_msg2_pend = { 0 };

extern schedule_t schedule_tiny, schedule_medium, schedule_big, schedule_huge;
schedule_t       *schedule_app = &schedule_huge;

volatile __attribute__((section(".shared_data"))) ipc_shared_data_t ipc_shared_data;

// Staging buffer: build IPC payloads here before calling _ipc_send_to_app().
// Avoids writing directly to shared memory while the APP core may still be reading it.
static uint8_t _ipc_tx_buf[UINT8_MAX];

static void _mari_event_callback(mr_event_t event, mr_event_data_t event_data) {
    if (event == MARI_EDHOC_MSG2) {
        // store in dedicated buffer: MARI_NODE_JOINED fires right after in the same interrupt
        // and would overwrite the single-slot event before the main loop can read it
        _edhoc_msg2_pend.node_id = event_data.data.edhoc.node_id;
        _edhoc_msg2_pend.len     = event_data.data.edhoc.len;
        memcpy(_edhoc_msg2_pend.data, event_data.data.edhoc.data, event_data.data.edhoc.len);
        _edhoc_msg2_pend.ready = true;
        return;
    }
    _app_vars.mari_event = event;
    memcpy(&_app_vars.mari_event_data, &event_data, sizeof(mr_event_data_t));
    _app_vars.mari_event_ready = true;
}

static void _to_uart_gateway_loop(void) {
    _app_vars.to_uart_gateway_loop_ready = true;
}

// Send a buffer to the APP core via IPC.
// Waits until the APP core has consumed the previous message (radio_to_uart_free == true)
// before overwriting the shared buffer. This prevents IPC race conditions where a second
// write clobbers data before the APP core's interrupt handler finishes copying it.
static void _ipc_send_to_app(const uint8_t *data, uint8_t len) {
    // Spin-wait for APP core to mark buffer free (~2µs typical; hard timeout prevents lockup).
    uint32_t timeout = 200000;
    while (!ipc_shared_data.radio_to_uart_free && timeout--) {
        __NOP();
    }
    ipc_shared_data.radio_to_uart_free = false;
    memcpy((void *)ipc_shared_data.radio_to_uart, data, len);
    ipc_shared_data.radio_to_uart_len = len;
    __DSB();  // ensure writes are visible before the IPC signal fires
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
    // printf("Hello Mari Gateway Net Core %016llX\n", mr_device_id());
    mr_timer_hf_init(MARI_APP_TIMER_DEV);
    _init_ipc();

    mari_init(MARI_GATEWAY, 0xa3, schedule_app, &_mari_event_callback);

    // NOTE: to send the stats every slotframe, we need to use the duration of the slotframe

    mr_timer_hf_set_periodic_us(MARI_APP_TIMER_DEV, 3, mr_scheduler_get_duration_us(), &_to_uart_gateway_loop);

    // Unlock the application core
    ipc_shared_data.net_ready = true;

    while (1) {
        __WFE();

        if (_app_vars.mari_event_ready) {
            _app_vars.mari_event_ready = false;

            mr_event_t      event      = _app_vars.mari_event;
            mr_event_data_t event_data = _app_vars.mari_event_data;

            bool    send_to_uart = false;
            uint8_t send_len     = 0;

            switch (event) {
                case MARI_NEW_PACKET:
                {
                    // handle metrics probe
                    if (metrics_is_probe(event_data.data.new_packet.payload, event_data.data.new_packet.payload_len)) {
                        metrics_handle_rx_probe(event_data.data.new_packet.header->src, event_data.data.new_packet.payload);
                    }

                    // check for EDHOC msg4 in payload (starts with EDHOC tag)
                    if (event_data.data.new_packet.payload_len >= 2 &&
                        event_data.data.new_packet.payload[0] == MARI_EDHOC_PAYLOAD_TAG) {
                        uint8_t edhoc_len = event_data.data.new_packet.payload[1];
                        if (edhoc_len > 0 && (uint8_t)(2 + edhoc_len) <= event_data.data.new_packet.payload_len) {
                            uint64_t  src    = event_data.data.new_packet.header->src;
                            uint64_t  asn_dl = 0;
                            mr_assoc_gateway_get_attest_dl_asn(src, &asn_dl);
                            uint64_t  asn_ul = mr_mac_get_asn();
                            uint8_t   pos    = 0;
                            _ipc_tx_buf[pos++] = MARI_EDGE_EDHOC;
                            _ipc_tx_buf[pos++] = MARI_EDHOC_SUBTYPE_MSG4;
                            memcpy(_ipc_tx_buf + pos, &src, sizeof(uint64_t));
                            pos += sizeof(uint64_t);
                            memcpy(_ipc_tx_buf + pos, &asn_dl, sizeof(uint64_t));
                            pos += sizeof(uint64_t);
                            memcpy(_ipc_tx_buf + pos, &asn_ul, sizeof(uint64_t));
                            pos += sizeof(uint64_t);
                            memcpy(_ipc_tx_buf + pos, event_data.data.new_packet.payload + 2, edhoc_len);
                            pos += edhoc_len;
                            send_to_uart = true;
                            send_len     = pos;
                        }
                        break;  // don't forward as regular data
                    }

                    send_len            = event_data.data.new_packet.len + 1;
                    _ipc_tx_buf[0]      = MARI_EDGE_DATA;
                    memcpy(_ipc_tx_buf + 1, event_data.data.new_packet.header, event_data.data.new_packet.len);
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
                    // printf("%d New node joined: %016llX  (%d nodes connected)\n", now_ts_s, event_data.data.node_info.node_id, mari_gateway_count_nodes());
                    metrics_add_node(event_data.data.node_info.node_id);
                    send_len       = 1 + sizeof(uint64_t);
                    _ipc_tx_buf[0] = MARI_EDGE_NODE_JOINED;
                    memcpy(_ipc_tx_buf + 1, &event_data.data.node_info.node_id, sizeof(uint64_t));
                    send_to_uart = true;
                    break;
                case MARI_NODE_LEFT:
                    // printf("%d Node left: %016llX, reason: %u  (%d nodes connected)\n", now_ts_s, event_data.data.node_info.node_id, event_data.tag, mari_gateway_count_nodes());
                    metrics_clear_node(event_data.data.node_info.node_id);
                    send_len       = 1 + sizeof(uint64_t);
                    _ipc_tx_buf[0] = MARI_EDGE_NODE_LEFT;
                    memcpy(_ipc_tx_buf + 1, &event_data.data.node_info.node_id, sizeof(uint64_t));
                    send_to_uart = true;
                    break;
                case MARI_EDHOC_MSG2:
                {
                    // forward EDHOC msg2 to edge: [EDHOC=6][MSG2=2][node_id: 8 bytes][data...]
                    uint64_t  src  = event_data.data.edhoc.node_id;
                    uint8_t   elen = event_data.data.edhoc.len;
                    uint8_t   pos  = 0;
                    _ipc_tx_buf[pos++] = MARI_EDGE_EDHOC;
                    _ipc_tx_buf[pos++] = MARI_EDHOC_SUBTYPE_MSG2;
                    memcpy(_ipc_tx_buf + pos, &src, sizeof(uint64_t));
                    pos += sizeof(uint64_t);
                    memcpy(_ipc_tx_buf + pos, event_data.data.edhoc.data, elen);
                    pos += elen;
                    send_to_uart = true;
                    send_len     = pos;
                    break;
                }
                case MARI_ERROR:
                    // printf("Error, reason: %u\n", event_data.tag);
                    break;
                default:
                    break;
            }

            if (send_to_uart) {
                _ipc_send_to_app(_ipc_tx_buf, send_len);
            }
        }

        // drain pending EDHOC msg2 (stored separately to avoid being overwritten by MARI_NODE_JOINED)
        if (_edhoc_msg2_pend.ready) {
            _edhoc_msg2_pend.ready = false;
            uint64_t  src  = _edhoc_msg2_pend.node_id;
            uint8_t   elen = _edhoc_msg2_pend.len;
            uint8_t   pos  = 0;
            _ipc_tx_buf[pos++] = MARI_EDGE_EDHOC;
            _ipc_tx_buf[pos++] = MARI_EDHOC_SUBTYPE_MSG2;
            memcpy(_ipc_tx_buf + pos, &src, sizeof(uint64_t));
            pos += sizeof(uint64_t);
            memcpy(_ipc_tx_buf + pos, _edhoc_msg2_pend.data, elen);
            pos += elen;
            _ipc_send_to_app(_ipc_tx_buf, pos);
        }

        if (_app_vars.uart_to_radio_packet_ready) {
            _app_vars.uart_to_radio_packet_ready = false;
            uint8_t packet_type                  = ipc_shared_data.uart_to_radio_tx[0];

            // broadcast reboot to all nodes and clear association table
            if (packet_type == MARI_EDGE_REBOOT_ALL) {
                uint8_t reboot_buf[sizeof(mr_packet_header_t) + 1];
                memset(reboot_buf, 0, sizeof(reboot_buf));
                mr_packet_header_t *hdr = (mr_packet_header_t *)reboot_buf;
                hdr->version    = 2;
                hdr->type       = MARI_PACKET_DATA;
                hdr->network_id = mr_assoc_get_network_id();
                hdr->dst        = MARI_BROADCAST_ADDRESS;
                hdr->src        = mr_device_id();
                reboot_buf[sizeof(mr_packet_header_t)] = MARI_REBOOT_PAYLOAD_TAG;
                mari_tx(reboot_buf, sizeof(reboot_buf));
                mr_assoc_gateway_remove_all_nodes();
                continue;
            }

            // kick node requested by edge (attestation failure)
            if (packet_type == MARI_EDGE_KICK_NODE) {
                if (ipc_shared_data.uart_to_radio_len >= 1 + (uint8_t)sizeof(uint64_t)) {
                    uint64_t node_id;
                    memcpy(&node_id, (uint8_t *)ipc_shared_data.uart_to_radio_tx + 1, sizeof(uint64_t));
                    mr_assoc_gateway_remove_node(node_id);
                }
                continue;
            }

            // handle EDHOC messages from edge
            if (packet_type == MARI_EDGE_EDHOC) {
                uint8_t         subtype   = ipc_shared_data.uart_to_radio_tx[1];
                uint8_t        *body      = (uint8_t *)ipc_shared_data.uart_to_radio_tx + 2;
                uint8_t         body_len  = (uint8_t)(ipc_shared_data.uart_to_radio_len - 2);
                if (subtype == MARI_EDHOC_SUBTYPE_MSG1 && body_len > 0) {
                    // msg1 has no node_id prefix (broadcast), body is msg1 bytes
                    mr_queue_set_edhoc_msg1(body, body_len);
                } else if (subtype == MARI_EDHOC_SUBTYPE_MSG3 && body_len > sizeof(uint64_t)) {
                    // msg3 has [node_id: 8 bytes][msg3_bytes...]
                    uint64_t node_id;
                    memcpy(&node_id, body, sizeof(uint64_t));
                    uint8_t *msg3_data = body + sizeof(uint64_t);
                    uint8_t  msg3_len  = body_len - (uint8_t)sizeof(uint64_t);
                    // Store msg3; mr_queue_set_edhoc_msg3 immediately finalizes the pending
                    // join response so it is queued in the FIFO before the next downlink slot.
                    mr_queue_set_edhoc_msg3(node_id, msg3_data, msg3_len);
                }
                continue;
            }

            if (packet_type != MARI_EDGE_DATA) {
                // printf("Invalid UART packet type: %02X\n", packet_type);
                continue;
            }

            uint8_t *mari_frame     = (uint8_t *)ipc_shared_data.uart_to_radio_tx + 1;
            uint8_t  mari_frame_len = ipc_shared_data.uart_to_radio_len - 1;
            // attestation verification response handling (disabled, pure EDHOC only)
            // if (mari_frame_len > sizeof(mr_packet_header_t)) { ... }

            mr_packet_header_t *header = (mr_packet_header_t *)mari_frame;
            header->src                = mr_device_id();
            header->network_id         = mr_assoc_get_network_id();
            // handle metrics probe
            uint8_t *payload     = mari_frame + sizeof(mr_packet_header_t);
            uint8_t  payload_len = mari_frame_len - sizeof(mr_packet_header_t);
            if (metrics_is_probe(payload, payload_len)) {
                metrics_handle_tx_probe(header->dst, payload);
            }
            mari_tx(mari_frame, mari_frame_len);
        }

        if (_app_vars.to_uart_gateway_loop_ready) {
            _app_vars.to_uart_gateway_loop_ready = false;
            _ipc_tx_buf[0] = MARI_EDGE_GATEWAY_INFO;
            size_t len     = mr_build_uart_packet_gateway_info(_ipc_tx_buf + 1);
            _ipc_send_to_app(_ipc_tx_buf, 1 + len);
        }

        // best to keep this at the end of the main loop
        mari_event_loop();
    }
}

void IPC_IRQHandler(void) {
    if (NRF_IPC_NS->EVENTS_RECEIVE[IPC_CHAN_UART_TO_RADIO]) {
        NRF_IPC_NS->EVENTS_RECEIVE[IPC_CHAN_UART_TO_RADIO] = 0;
        _app_vars.uart_to_radio_packet_ready               = true;
    }
}
