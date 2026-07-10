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

#define MAURA_APP_NET_CONFIG_START_ADDRESS (0x0103f800)
#define MAURA_APP_CONFIG_MAGIC_VALUE       (0x5753524D)  // "SWRM"

#define MAURA_APP_TIMER_DEV 1

typedef struct {
    mr_event_t      mari_event;
    mr_event_data_t mari_event_data;
    bool            mari_event_ready;
    bool            uart_to_radio_packet_ready;
    bool            to_uart_gateway_loop_ready;
    uint32_t        tx_count;
    uint32_t        rx_count;
} gateway_vars_t;

typedef struct {
    bool     ready;
    uint64_t node_id;
    uint8_t  data[MARI_EDHOC_MAX_MSG_LEN];
    uint8_t  len;
} edhoc_msg1_pending_t;

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t has_net_id;
    uint32_t net_id;
} maura_app_config_t;

//=========================== variables =======================================

static gateway_vars_t       _app_vars        = {0};
static edhoc_msg1_pending_t _edhoc_msg1_pend = {0};

extern schedule_t schedule_tiny, schedule_medium, schedule_big, schedule_huge;
static schedule_t *schedule_app = &schedule_huge;

volatile __attribute__((section(".shared_data"))) ipc_shared_data_t ipc_shared_data;

static uint8_t _ipc_tx_buf[UINT8_MAX];

static void _mari_event_callback(mr_event_t event, mr_event_data_t event_data) {
    if (event == MARI_EDHOC_MSG2) {
        _edhoc_msg1_pend.node_id = event_data.data.edhoc.node_id;
        _edhoc_msg1_pend.len     = event_data.data.edhoc.len;
        memcpy(_edhoc_msg1_pend.data, event_data.data.edhoc.data, event_data.data.edhoc.len);
        _edhoc_msg1_pend.ready = true;
        return;
    }
    _app_vars.mari_event = event;
    memcpy(&_app_vars.mari_event_data, &event_data, sizeof(mr_event_data_t));
    _app_vars.mari_event_ready = true;
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
    mr_timer_hf_init(MAURA_APP_TIMER_DEV);
    _init_ipc();

    mari_init(MARI_GATEWAY, 0xa3, schedule_app, &_mari_event_callback);

    mr_timer_hf_set_periodic_us(MAURA_APP_TIMER_DEV, 3, mr_scheduler_get_duration_us(), &_to_uart_gateway_loop);

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
                    if (metrics_is_probe(event_data.data.new_packet.payload,
                                         event_data.data.new_packet.payload_len)) {
                        metrics_handle_rx_probe(event_data.data.new_packet.header->src,
                                                event_data.data.new_packet.payload);
                    }

                    // Uplink EDHOC: node sends msg3 (with EAD_3 containing COSE_Sign1 token)
                    if (event_data.data.new_packet.payload_len >= 2 &&
                        event_data.data.new_packet.payload[0] == MARI_EDHOC_PAYLOAD_TAG) {
                        uint8_t edhoc_len = event_data.data.new_packet.payload[1];
                        if (edhoc_len > 0 &&
                            (uint8_t)(2u + edhoc_len) <= event_data.data.new_packet.payload_len) {
                            uint64_t src = event_data.data.new_packet.header->src;
                            uint8_t  pos = 0;
                            _ipc_tx_buf[pos++] = MARI_EDGE_EDHOC;
                            _ipc_tx_buf[pos++] = MARI_EDHOC_SUBTYPE_MSG3;  // MSG3 in new design
                            memcpy(_ipc_tx_buf + pos, &src, sizeof(uint64_t));
                            pos += sizeof(uint64_t);
                            memcpy(_ipc_tx_buf + pos,
                                   event_data.data.new_packet.payload + 2, edhoc_len);
                            pos += edhoc_len;
                            send_to_uart = true;
                            send_len     = pos;
                        break;
                    }

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
                    metrics_add_node(event_data.data.node_info.node_id);
                    send_len       = 1 + sizeof(uint64_t);
                    _ipc_tx_buf[0] = MARI_EDGE_NODE_JOINED;
                    memcpy(_ipc_tx_buf + 1, &event_data.data.node_info.node_id, sizeof(uint64_t));
                    send_to_uart = true;
                    break;
                case MARI_NODE_LEFT:
                    metrics_clear_node(event_data.data.node_info.node_id);
                    send_len       = 1 + sizeof(uint64_t);
                    _ipc_tx_buf[0] = MARI_EDGE_NODE_LEFT;
                    memcpy(_ipc_tx_buf + 1, &event_data.data.node_info.node_id, sizeof(uint64_t));
                    send_to_uart = true;
                    break;
                case MARI_EDHOC_MSG2:
                {
                    // Forward join-request EDHOC as MSG1 (node sent msg1, not msg2)
                    uint64_t src  = event_data.data.edhoc.node_id;
                    uint8_t  elen = event_data.data.edhoc.len;
                    uint8_t  pos  = 0;
                    _ipc_tx_buf[pos++] = MARI_EDGE_EDHOC;
                    _ipc_tx_buf[pos++] = MARI_EDHOC_SUBTYPE_MSG1;  // MSG1 in new design
                    memcpy(_ipc_tx_buf + pos, &src, sizeof(uint64_t));
                    pos += sizeof(uint64_t);
                    memcpy(_ipc_tx_buf + pos, event_data.data.edhoc.data, elen);
                    pos += elen;
                    send_to_uart = true;
                    send_len     = pos;
                    break;
                }
                case MARI_ERROR:
                    break;
                default:
                    break;
            }

            if (send_to_uart) {
                _ipc_send_to_app(_ipc_tx_buf, send_len);
            }
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

        if (_app_vars.uart_to_radio_packet_ready) {
            _app_vars.uart_to_radio_packet_ready = false;
            uint8_t packet_type = ipc_shared_data.uart_to_radio_tx[0];

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
                mr_queue_gateway_reset_edhoc_state();
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
