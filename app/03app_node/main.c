/**
 * @file
 * @ingroup     app
 * @brief       Related-work Node — EDHOC Initiator + Attestation over Mari
 *
 * Role reversal from the swarm design (this repo's mari/app/03app_node when built
 * from the measurement-edhoc-mari-attestation branch):
 *   - Node = EDHOC Initiator (sends msg1 in join request, msg3 in uplink)
 *   - Edge = EDHOC Responder (sends msg2 in join response)
 *
 * EDHOC flow:
 *   1. Startup/disconnect: generate msg1 with EAD_1=[258], append to join request.
 *   2. Join response (MARI_EDHOC_MSG3 event): contains msg2 from edge.
 *   3. Main loop drains pending msg2: parse, verify, extract nonce from EAD_2,
 *      compute COSE_Sign1 token with attestation binder, prepare msg3 with EAD_3.
 *   4. Send msg3 on the next uplink slot, retransmitting (bounded by MSG3_MAX_RETRIES)
 *      until the edge acks it (MAURA_MSG3_ACK_TAG) or the retry budget is exhausted,
 *      in which case reboot to rejoin from scratch.
 *
 * @author Geovane Fedrecheski <geovane.fedrecheski@inria.fr>
 * @author Alexandre Abadie <alexandre.abadie@inria.fr>
 * @author Yuxuan Song <yuxuan.song@inria.fr>
 * @copyright Inria, 2026
 */

#include <nrf.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include "mr_gpio.h"
#include "mr_device.h"
#include "mr_radio.h"
#include "mr_rng.h"
#include "mr_timer_hf.h"
#include "mari.h"
#include "packet.h"
#include "models.h"
#include "mac.h"
#include "queue.h"

#include "board.h"
#include "C:/Users/yusong/Downloads/lakers/target/include/lakers.h"
#include "attestation.h"

//=========================== defines =========================================

#define MAURA_APP_NET_ID      MARI_NET_ID_DEFAULT
#define MAURA_APP_TIMER_DEV   1

#define MSG2_TIMEOUT_SLOTS    600  
#define MAURA_MSG3_ACK_TAG    0xAC
#define MSG3_MAX_RETRIES      10

#define DEFAULT_PAYLOAD_SIZE (MARI_PACKET_MAX_SIZE - (uint8_t)sizeof(mr_packet_header_t) - 2u)
#define MAURA_MSG_BUF_LEN    220u  // generous buffer for msg3 with EAD_3

typedef struct __attribute__((packed)) {
    uint8_t type;
    uint8_t value[DEFAULT_PAYLOAD_SIZE];
} default_payload_t;

typedef struct {
    mr_event_t      event;
    mr_event_data_t event_data;
    bool            event_ready;
    bool            led_blink_state;
    bool            send_status_ready;

    bool     edhoc_started;    ///< msg1 generated and appended to join request
    bool     edhoc_msg3_ready; ///< msg3 with EAD_3 ready to transmit
    bool     edhoc_completed;  ///< EDHOC exchange done
    bool     msg3_acked;       ///< edge confirmed msg3 receipt -- stop retransmitting
    uint8_t  msg3_tx_count;    ///< number of times msg3 has been transmitted (capped by MSG3_MAX_RETRIES)
    uint64_t conn_asn_dl;      ///< ASN when join response arrived
} node_vars_t;

// Dedicated buffer for pending msg2 from join response.
// MARI_EDHOC_MSG3 fires in interrupt context alongside MARI_CONNECTED — storing
// separately prevents the single-slot event from being overwritten before main loop reads it.
typedef struct {
    bool    ready;
    uint8_t data[MARI_EDHOC_MAX_MSG_LEN];
    uint8_t len;
} msg2_pending_t;

typedef struct __attribute__((packed)) {
    uint64_t marilib_timestamp;
    uint32_t rx_counter;
    uint32_t tx_counter;
} node_stats_t;

//=========================== variables =======================================

static node_vars_t   _node_vars   = {0};
static node_stats_t  _node_stats  = {0};
static msg2_pending_t _msg2_pend  = {0};

extern schedule_t schedule_minuscule, schedule_tiny, schedule_huge;
static schedule_t *schedule_app = &schedule_huge;

static uint8_t _status_pkt[4] = {
    0x80,  // swarmit notification status
    1,     // SWRMT_DEVICE_TYPE_DOTBOTV3
    1,     // SWRMT_APPLICATION_RUNNING
    80,    // battery level
};

// Node = EDHOC Initiator.
// Reuse the same credential pair as the swarm mari_edge.py initiator so the
// edge (now responder) can authenticate the node with its known CRED_I.
static const BytesP256ElemLen I = {
    0x1f, 0x7e, 0x4a, 0xe4, 0x29, 0x3a, 0x34, 0x8b, 0xf2, 0xb1, 0x36, 0x5c, 0xe0, 0x98, 0xaa, 0x49,
    0xc2, 0x07, 0xbd, 0x1b, 0xa7, 0xdd, 0xde, 0xcd, 0xfa, 0xd6, 0x0c, 0xad, 0xe8, 0x2e, 0x9e, 0xf5
};

// CRED_I = node's credential (initiator; 117 bytes)
static const uint8_t CRED_I_BYTES[117] = {
    0xa2, 0x02, 0x78, 0x20, 0x38, 0x35, 0x43, 0x31, 0x45, 0x43, 0x32, 0x31, 0x46, 0x32, 0x36, 0x46,
    0x34, 0x31, 0x45, 0x37, 0x41, 0x33, 0x30, 0x41, 0x38, 0x41, 0x38, 0x37, 0x42, 0x44, 0x42, 0x45,
    0x46, 0x32, 0x33, 0x43, 0x08, 0xa1, 0x01, 0xa5, 0x01, 0x02, 0x02, 0x41, 0x01, 0x20, 0x01, 0x21,
    0x58, 0x20, 0x52, 0x7c, 0x4d, 0x4c, 0x08, 0x9f, 0x9f, 0xe3, 0x33, 0x56, 0xaa, 0x97, 0xa1, 0xd6,
    0x72, 0xda, 0x32, 0xc1, 0x60, 0x08, 0x24, 0x4f, 0xef, 0x37, 0xf0, 0x71, 0x54, 0xe0, 0x70, 0xe6,
    0x6d, 0x1f, 0x22, 0x58, 0x20, 0x32, 0xe4, 0x6c, 0x45, 0xc4, 0xdd, 0xcb, 0x6d, 0x6c, 0x52, 0x4f,
    0x37, 0x9d, 0x57, 0x15, 0x9d, 0x64, 0x2d, 0xd7, 0xf0, 0x27, 0x9c, 0x45, 0x50, 0xe3, 0x44, 0x48,
    0xda, 0xc4, 0x19, 0x53, 0x2c
};

// CRED_R = expected edge/responder credential (95 bytes)
static const uint8_t CRED_R_BYTES[95] = {
    0xa2, 0x02, 0x6b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x65, 0x64, 0x75, 0x08, 0xa1,
    0x01, 0xa5, 0x01, 0x02, 0x02, 0x41, 0x32, 0x20, 0x01, 0x21, 0x58, 0x20, 0xbb, 0xc3, 0x49, 0x60,
    0x52, 0x6e, 0xa4, 0xd3, 0x2e, 0x94, 0x0c, 0xad, 0x2a, 0x23, 0x41, 0x48, 0xdd, 0xc2, 0x17, 0x91,
    0xa1, 0x2a, 0xfb, 0xcb, 0xac, 0x93, 0x62, 0x20, 0x46, 0xdd, 0x44, 0xf0, 0x22, 0x58, 0x20, 0x45,
    0x19, 0xe2, 0x57, 0x23, 0x6b, 0x2a, 0x0c, 0xe2, 0x02, 0x3f, 0x09, 0x31, 0xf1, 0xf3, 0x86, 0xca,
    0x7a, 0xfd, 0xa6, 0x4f, 0xcd, 0xe0, 0x10, 0x8c, 0x22, 0x4c, 0x51, 0xea, 0xbf, 0x60, 0x72
};

// EDHOC Initiator state
static EdhocInitiator     _initiator   = {0};
static CredentialC        _cred_i      = {0};
static CredentialC        _cred_r      = {0};
static CredentialC        _fetched_r   = {0};
static IdCred             _id_cred_r   = {0};
static EdhocMessageBuffer _msg1        = {0};
static EdhocMessageBuffer _msg3        = {0};
static EADItemC           _ead_2_out   = {0};
static EADItemC           _ead_3_out   = {0};
static uint8_t            _c_r         = 0;
static uint8_t            _prk_out[32] = {0};
static uint8_t            _nonce[MAURA_NONCE_SIZE]  = {0};
static uint8_t            _nonce_len                = 0;

//=========================== private =========================================

static void _led_blink_cb(void) {
    if (!mari_node_is_connected()) {
        board_set_led_mari(_node_vars.led_blink_state ? OFF : BLUE);
        _node_vars.led_blink_state = !_node_vars.led_blink_state;
    }
}

static void _send_status_cb(void) {
    _node_vars.send_status_ready = true;
}


static void _reset_edhoc_state(void) {
    _node_vars.edhoc_started    = false;
    _node_vars.edhoc_msg3_ready = false;
    _node_vars.edhoc_completed  = false;
    _node_vars.msg3_acked       = false;
    _node_vars.msg3_tx_count    = 0;
    _node_vars.conn_asn_dl      = 0;
    _msg2_pend.ready            = false;
    memset(&_initiator, 0, sizeof(_initiator));
    memset(&_msg1, 0, sizeof(_msg1));
    memset(&_msg3, 0, sizeof(_msg3));
    memset(&_ead_2_out, 0, sizeof(_ead_2_out));
    memset(&_ead_3_out, 0, sizeof(_ead_3_out));
    memset(_nonce, 0, sizeof(_nonce));
    _nonce_len = 0;
}

/**
 * @brief Start a fresh EDHOC session: generate msg1 with EAD_1=[258] and
 *        append to the pending join request so it is sent when the node joins.
 */
static void _start_edhoc_session(void) {
    if (initiator_new(&_initiator) != 0) {
        printf("[MAURA] initiator_new failed\n");
        return;
    }

    EADItemC ead_1 = {0};
    maura_prepare_ead_1(&ead_1, 1, false);

    if (initiator_prepare_message_1(&_initiator, NULL, &ead_1, &_msg1) != 0) {
        printf("[MAURA] prepare_message_1 failed\n");
        return;
    }

    mr_queue_append_edhoc_to_join_request(_msg1.content, (uint8_t)_msg1.len);
    _node_vars.edhoc_started = true;
}

static void _mari_event_cb(mr_event_t event, mr_event_data_t event_data) {
    if (event == MARI_EDHOC_MSG3) {
        // Join response contains msg2 from edge. Store separately:
        // MARI_CONNECTED fires immediately after in the same call chain and would
        // overwrite the single-slot event before the main loop can read it.
        uint8_t len = event_data.data.edhoc.len;
        if (len > MARI_EDHOC_MAX_MSG_LEN) { len = MARI_EDHOC_MAX_MSG_LEN; }
        memcpy(_msg2_pend.data, event_data.data.edhoc.data, len);
        _msg2_pend.len   = len;
        _msg2_pend.ready = true;
        return;
    }
    memcpy(&_node_vars.event, &event, sizeof(mr_event_t));
    memcpy(&_node_vars.event_data, &event_data, sizeof(mr_event_data_t));
    _node_vars.event_ready = true;
}

//=========================== main ============================================

int main(void) {
    mr_timer_hf_init(MAURA_APP_TIMER_DEV);
    board_init();
    board_set_led_mari(BLUE);

    if (credential_new(&_cred_i, CRED_I_BYTES, sizeof(CRED_I_BYTES)) != 0) { while (1); }
    if (credential_new(&_cred_r, CRED_R_BYTES, sizeof(CRED_R_BYTES)) != 0) { while (1); }

    // Random backoff to spread join requests across beacon rounds
    mr_rng_init();
    uint8_t rand_val = 0;
    mr_rng_read_u8(&rand_val);
    for (uint32_t unit = 0; unit < (uint32_t)rand_val; unit++) {
        for (volatile uint32_t i = 0; i < 64000; i++) { __NOP(); }
    }

    mari_init(MARI_NODE, 0xa3, schedule_app, &_mari_event_cb);

    mr_timer_hf_set_periodic_us(MAURA_APP_TIMER_DEV, 0, 100 * 1000, &_led_blink_cb);
    mr_timer_hf_set_periodic_us(MAURA_APP_TIMER_DEV, 1, 500 * 1000, &_send_status_cb);

    board_set_led_mari(OFF);

    // Generate msg1 now so it is ready when the node first joins
    _start_edhoc_session();

    while (1) {
        __SEV();
        __WFE();
        __WFE();

        if (_node_vars.event_ready) {
            _node_vars.event_ready = false;

            mr_event_t      event      = _node_vars.event;
            mr_event_data_t event_data = _node_vars.event_data;

            switch (event) {
                case MARI_NEW_PACKET:
                {
                    mari_packet_t pkt = event_data.data.new_packet;
                    if (pkt.payload_len >= 1 && pkt.payload[0] == MARI_REBOOT_PAYLOAD_TAG) {
                        NVIC_SystemReset();
                    } else if (pkt.payload_len >= 1 && pkt.payload[0] == MAURA_MSG3_ACK_TAG) {
                        // Edge confirmed msg3 receipt -- stop retransmitting.
                        _node_vars.msg3_acked      = true;
                        _node_vars.edhoc_msg3_ready = false;
                    } else if (pkt.payload_len >= 2 && pkt.payload[0] == MARI_EDHOC_PAYLOAD_TAG) {
                        // msg2 delivered as downlink data packet (retry after join)
                        uint8_t len = pkt.payload[1];
                        if (len > 0 && len <= MAX_MESSAGE_SIZE_LEN &&
                            (uint8_t)(2u + len) <= pkt.payload_len &&
                            !_msg2_pend.ready && !_node_vars.edhoc_completed) {
                            uint8_t capped = (len < MARI_EDHOC_MAX_MSG_LEN) ? len : MARI_EDHOC_MAX_MSG_LEN;
                            memcpy(_msg2_pend.data, pkt.payload + 2, capped);
                            _msg2_pend.len   = capped;
                            _msg2_pend.ready = true;
                        }
                    } else if (pkt.payload_len == sizeof(mr_metrics_payload_t) &&
                               pkt.payload[0] == MARI_PAYLOAD_TYPE_METRICS_PROBE) {
                        mr_metrics_payload_t *mp = (mr_metrics_payload_t *)pkt.payload;
                        mp->node_rx_count        = ++_node_stats.rx_counter;
                        mp->node_rx_asn          = mr_mac_get_asn();
                        mp->node_tx_count        = ++_node_stats.tx_counter;
                        mp->node_tx_enqueued_asn = mr_mac_get_asn();
                        mp->rssi_at_node         = mr_radio_rssi();
                        mari_node_tx_payload((uint8_t *)mp, sizeof(mr_metrics_payload_t));
                    }
                    break;
                }
                case MARI_CONNECTED:
                {
                    uint64_t gw_id = event_data.data.gateway_info.gateway_id;
                    board_set_led_mari_gateway(gw_id);
                    board_set_led_mari(YELLOW);
                    _node_vars.conn_asn_dl = mr_mac_get_asn();
                    break;
                }
                case MARI_DISCONNECTED:
                {
                    board_set_led_mari(OFF);
                    _reset_edhoc_state();
                    // Start fresh EDHOC session for the next join attempt
                    _start_edhoc_session();
                    break;
                }
                default:
                    break;
            }
        }

        // Drain pending msg2 from join response (stored separately to avoid race with MARI_CONNECTED)
        if (_msg2_pend.ready) {
            _msg2_pend.ready = false;

            EdhocMessageBuffer msg2 = {0};
            uint8_t            len  = _msg2_pend.len;
            if (len > MAX_MESSAGE_SIZE_LEN) { len = (uint8_t)MAX_MESSAGE_SIZE_LEN; }
            memcpy(msg2.content, _msg2_pend.data, len);
            msg2.len = len;

            // Parse msg2: extracts c_r, id_cred_r, ead_2
            if (initiator_parse_message_2(&_initiator, &msg2, &_c_r, &_id_cred_r, &_ead_2_out) != 0) {
                printf("[MAURA] parse_message_2 failed\n");
                goto msg2_done;
            }

            // Fetch/verify edge credential
            if (credential_check_or_fetch(&_cred_r, &_id_cred_r, &_fetched_r) != 0) {
                printf("[MAURA] credential_check_or_fetch failed\n");
                goto msg2_done;
            }
            if (initiator_verify_message_2(&_initiator, &I, &_cred_i, &_fetched_r) != 0) {
                printf("[MAURA] verify_message_2 failed\n");
                goto msg2_done;
            }

            // Decode EAD_2 to get verifier nonce
            uint32_t ev_type = 0;
            if (maura_decode_ead_2(_ead_2_out.value.content, &ev_type, _nonce, &_nonce_len) != 0) {
                printf("[MAURA] decode_ead_2 failed\n");
                goto msg2_done;
            }
            printf("[MAURA] EAD_2 ev_type=%u\n", (unsigned)ev_type);

            // Compute EAD_3: COSE_Sign1 with attestation_binder in external_aad
            maura_prepare_ead_3(&_ead_3_out, 1, false,
                                 _nonce, _nonce_len,
                                 _msg1.content, (uint8_t)_msg1.len,
                                 msg2.content, (uint8_t)msg2.len);

            // Prepare msg3 with EAD_3
            if (initiator_prepare_message_3(&_initiator, ByReference, &_ead_3_out, &_msg3, &_prk_out) != 0) {
                printf("[MAURA] prepare_message_3 failed\n");
                goto msg2_done;
            }

            _node_vars.edhoc_msg3_ready = true;
            _node_vars.edhoc_completed  = true;
            _node_vars.msg3_acked       = false;
            _node_vars.msg3_tx_count    = 0;
            board_set_led_mari(GREEN);
            printf("[MAURA] msg3 (%u B) ready\n", (unsigned)_msg3.len);

            msg2_done:;
        }

        if (_node_vars.send_status_ready) {
            _node_vars.send_status_ready = false;

            // Timeout: connected but msg2 never arrived → reset and retry
            if (mari_node_is_connected() && _node_vars.edhoc_started && !_node_vars.edhoc_completed) {
                if (_node_vars.conn_asn_dl > 0 &&
                    (mr_mac_get_asn() - _node_vars.conn_asn_dl) > MSG2_TIMEOUT_SLOTS) {
                    NVIC_SystemReset();
                }
            }

            if (_node_vars.edhoc_msg3_ready && !_node_vars.msg3_acked) {
                // Retransmit msg3 until the edge acks it (MAURA_MSG3_ACK_TAG, handled
                // above in MARI_NEW_PACKET) or we hit MSG3_MAX_RETRIES. This is smarter
                // than either extreme: a single unacknowledged shot can't tell success
                // from failure (any one lost packet permanently fails the round), while
                // blindly retrying a fixed number of times regardless of outcome just
                // floods the air/UART even after the edge already has it. The ack lets
                // us stop the instant delivery is confirmed.
                uint8_t buf[2 + MAURA_MSG_BUF_LEN];
                uint8_t pos   = 0;
                buf[pos++]    = MARI_EDHOC_PAYLOAD_TAG;
                buf[pos++]    = (uint8_t)_msg3.len;
                memcpy(buf + pos, _msg3.content, _msg3.len);
                pos += (uint8_t)_msg3.len;
                mari_node_tx_payload(buf, pos);
                _node_vars.msg3_tx_count++;
                if (_node_vars.msg3_tx_count >= MSG3_MAX_RETRIES) {
                    NVIC_SystemReset();
                }
            } else {
                mari_node_tx_payload(_status_pkt, sizeof(_status_pkt));
            }
        }

        mari_event_loop();
    }
}
