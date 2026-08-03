/**
 * @file
 * @ingroup     app
 * @brief       CRAFT node -- connect + SEDA attest over Mari.
 *
 * Node sends the connect request in the join request; the edge replies with
 * a connect reply + piggybacked SEDA challenge in the join response; the node
 * verifies it, computes the attest HMAC tag, and sends it on its assigned
 * uplink slot.
 *
 * @Yuxuan Song <yuxuan.song@inria.fr>
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
#include "attestation.h"

//=========================== defines =========================================

#define CRAFT_APP_NET_ID    MARI_NET_ID_DEFAULT
#define CRAFT_APP_TIMER_DEV 1

// Must stay above the gateway's JOINRESP_WAIT_TIMEOUT_SLOTS (queue.c).
#define CONNECT_REPLY_TIMEOUT_SLOTS 6000
// Fire-and-forget (matches SALSA-native): retry this many times (500ms apart), then give up without resetting.
#define ATTEST_MAX_RETRIES          5

#define DEFAULT_PAYLOAD_SIZE (MARI_PACKET_MAX_SIZE - (uint8_t)sizeof(mr_packet_header_t) - 2u)

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

    bool     connect_started;    ///< connect request built and appended to join request
    bool     attest_ready;       ///< attest tag ready to transmit (cleared once ATTEST_MAX_RETRIES is reached)
    bool     connect_completed;  ///< connect reply verified, k_ij derived, challenge stored
    uint8_t  attest_tx_count;    ///< number of times the attest tag has been transmitted (capped by ATTEST_MAX_RETRIES)
    uint64_t conn_asn_dl;        ///< ASN when join response arrived
} node_vars_t;

// Separate from _node_vars.event since MARI_EDHOC_MSG3 fires alongside
// MARI_CONNECTED and would otherwise overwrite that single-slot event.
typedef struct {
    bool    ready;
    uint8_t data[MARI_EDHOC_MAX_MSG_LEN];
    uint8_t len;
} connect_reply_pending_t;

// Own slot like connect_reply_pending_t: a lost MARI_DISCONNECTED left the node thinking it was still connected after the MAC had already dropped back to scanning.
typedef struct {
    bool           ready;
    mr_event_tag_t tag;
} disconnect_pending_t;

typedef struct __attribute__((packed)) {
    uint64_t marilib_timestamp;
    uint32_t rx_counter;
    uint32_t tx_counter;
} node_stats_t;

//=========================== variables =======================================

static node_vars_t             _node_vars      = {0};
static node_stats_t            _node_stats     = {0};
static connect_reply_pending_t _reply_pend     = {0};
static disconnect_pending_t    _disconnect_pend = {0};

extern schedule_t schedule_minuscule, schedule_tiny, schedule_huge;
static schedule_t *schedule_app = &schedule_huge;

static uint8_t _status_pkt[4] = {
    0x80,  // swarmit notification status
    1,     // SWRMT_DEVICE_TYPE_DOTBOTV3
    1,     // SWRMT_APPLICATION_RUNNING
    80,    // battery level
};

static uint8_t _connect_request[CRAFT_CONNECT_SIZE] = { 0 };
static uint8_t _pk_edge[CRAFT_X25519_KEY_SIZE]       = { 0 };
static uint8_t _challenge[CRAFT_CHALLENGE_SIZE]      = { 0 };
static uint8_t _k_ij[CRAFT_X25519_KEY_SIZE]          = { 0 };  // derived for connect protocol fidelity, unused downstream (beat dropped)
static uint8_t _attest_tag[CRAFT_ATTEST_TAG_SIZE]    = { 0 };

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

static void _reset_craft_state(void) {
    _node_vars.connect_started   = false;
    _node_vars.attest_ready      = false;
    _node_vars.connect_completed = false;
    _node_vars.attest_tx_count   = 0;
    _node_vars.conn_asn_dl       = 0;
    _reply_pend.ready            = false;
    memset(_pk_edge, 0, sizeof(_pk_edge));
    memset(_challenge, 0, sizeof(_challenge));
    memset(_k_ij, 0, sizeof(_k_ij));
    memset(_attest_tag, 0, sizeof(_attest_tag));
}

/**
 * @brief Build the connect request and append it to the pending join request
 *        so it is sent when the node first joins.
 */
static void _start_connect(void) {
    uint8_t len = craft_build_connect_request(_connect_request);
    mr_queue_append_edhoc_to_join_request(_connect_request, len);
    _node_vars.connect_started = true;
}

static void _mari_event_cb(mr_event_t event, mr_event_data_t event_data) {
    if (event == MARI_EDHOC_MSG3) {
        // Connect reply + challenge from the join response.
        uint8_t len = event_data.data.edhoc.len;
        if (len > MARI_EDHOC_MAX_MSG_LEN) { len = MARI_EDHOC_MAX_MSG_LEN; }
        memcpy(_reply_pend.data, event_data.data.edhoc.data, len);
        _reply_pend.len   = len;
        _reply_pend.ready = true;
        return;
    }
    if (event == MARI_DISCONNECTED) {
        _disconnect_pend.tag   = event_data.tag;
        _disconnect_pend.ready = true;
        return;
    }
    memcpy(&_node_vars.event, &event, sizeof(mr_event_t));
    memcpy(&_node_vars.event_data, &event_data, sizeof(mr_event_data_t));
    _node_vars.event_ready = true;
}

//=========================== main ============================================

int main(void) {
    mr_timer_hf_init(CRAFT_APP_TIMER_DEV);
    board_init();
    board_set_led_mari(BLUE);

    // Random backoff to spread join requests across beacon rounds
    mr_rng_init();
    uint8_t rand_val = 0;
    mr_rng_read_u8(&rand_val);
    for (uint32_t unit = 0; unit < (uint32_t)rand_val; unit++) {
        for (volatile uint32_t i = 0; i < 64000; i++) { __NOP(); }
    }

    mari_init(MARI_NODE, 0xa3, schedule_app, &_mari_event_cb);

    mr_timer_hf_set_periodic_us(CRAFT_APP_TIMER_DEV, 0, 100 * 1000, &_led_blink_cb);
    mr_timer_hf_set_periodic_us(CRAFT_APP_TIMER_DEV, 1, 500 * 1000, &_send_status_cb);

    board_set_led_mari(OFF);

    // Build connect request now so it is ready when the node first joins
    _start_connect();

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
                        printf("[CRAFT] RX reboot command -- resetting\n");
                        NVIC_SystemReset();
                    } else if (pkt.payload_len >= 2 && pkt.payload[0] == MARI_EDHOC_PAYLOAD_TAG) {
                        // connect reply delivered as downlink data packet (retry after join)
                        uint8_t len = pkt.payload[1];
                        if (len > 0 && len <= MARI_EDHOC_MAX_MSG_LEN &&
                            (uint8_t)(2u + len) <= pkt.payload_len &&
                            !_reply_pend.ready && !_node_vars.connect_completed) {
                            memcpy(_reply_pend.data, pkt.payload + 2, len);
                            _reply_pend.len   = len;
                            _reply_pend.ready = true;
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
                    printf("[CRAFT] RX join response -- connected to gateway 0x%08lX%08lX\n",
                           (unsigned long)(gw_id >> 32), (unsigned long)(gw_id & 0xFFFFFFFF));
                    board_set_led_mari_gateway(gw_id);
                    board_set_led_mari(YELLOW);
                    _node_vars.conn_asn_dl = mr_mac_get_asn();
                    break;
                }
                default:
                    break;
            }
        }

        if (_disconnect_pend.ready) {
            _disconnect_pend.ready = false;

            // tag: 1=handover 2=out_of_sync 5=peer_lost_timeout
            //      6=peer_lost_bloom 7=handover_failed
            printf("[CRAFT] disconnected (tag=%d)\n", (int)_disconnect_pend.tag);
            board_set_led_mari(OFF);
            _reset_craft_state();
            // Build a fresh connect request for the next join attempt
            _start_connect();
        }

        if (_reply_pend.ready) {
            _reply_pend.ready = false;

            craft_status_t status = craft_process_connect_reply(
                _reply_pend.data, _reply_pend.len, _pk_edge, _challenge, _k_ij);

            if (status != CRAFT_OK) {
                printf("[CRAFT] connect reply verification failed: %d\n", (int)status);
                goto reply_done;
            }

            craft_compute_attest_tag(_challenge, _attest_tag);

            _node_vars.attest_ready      = true;
            _node_vars.connect_completed = true;
            _node_vars.attest_tx_count   = 0;
            board_set_led_mari(GREEN);

            reply_done:;
        }

        if (_node_vars.send_status_ready) {
            _node_vars.send_status_ready = false;

            // Timeout: connected but connect reply never arrived -> reset and retry
            if (mari_node_is_connected() && _node_vars.connect_started && !_node_vars.connect_completed) {
                if (_node_vars.conn_asn_dl > 0 &&
                    (mr_mac_get_asn() - _node_vars.conn_asn_dl) > CONNECT_REPLY_TIMEOUT_SLOTS) {
                    NVIC_SystemReset();
                }
            }

            if (_node_vars.attest_ready) {
                uint8_t buf[2 + CRAFT_ATTEST_TAG_SIZE];
                uint8_t pos   = 0;
                buf[pos++]    = MARI_EDHOC_PAYLOAD_TAG;
                buf[pos++]    = CRAFT_ATTEST_TAG_SIZE;
                memcpy(buf + pos, _attest_tag, CRAFT_ATTEST_TAG_SIZE);
                pos += CRAFT_ATTEST_TAG_SIZE;
                mari_node_tx_payload(buf, pos);
                _node_vars.attest_tx_count++;
                if (_node_vars.attest_tx_count >= ATTEST_MAX_RETRIES) {
                    printf("[CRAFT] attest tag never acked -- giving up after %u tries, staying connected\n",
                           (unsigned)ATTEST_MAX_RETRIES);
                    // Fire-and-forget like SALSA: give up and fall back to status packets, no reset either way.
                    _node_vars.attest_ready = false;
                }
            } else {
                mari_node_tx_payload(_status_pkt, sizeof(_status_pkt));
            }
        }

        mari_event_loop();
    }
}
