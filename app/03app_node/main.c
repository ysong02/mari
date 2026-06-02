/**
 * @file
 * @ingroup     app
 *
 * @brief       Mari Node application example
 *
 * @author Geovane Fedrecheski <geovane.fedrecheski@inria.fr>
 *
 * @copyright Inria, 2025
 */
#include <nrf.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include "mr_gpio.h"
#include "mr_device.h"
#include "mr_radio.h"
#include "mr_timer_hf.h"
#include "mari.h"
#include "packet.h"
#include "models.h"
#include "mac.h"
#include "queue.h"

#include "board.h"
#include "C:/Users/yusong/Downloads/lakers/target/include/lakers.h"
#include "attestation.h"

//=========================== defines ==========================================

#define MARI_APP_NET_ID MARI_NET_ID_DEFAULT

#define MARI_APP_TIMER_DEV 1

#define MSG4_MAX_RETRIES 5

// -2 is for the type and needs_ack fields
#define DEFAULT_PAYLOAD_SIZE MARI_PACKET_MAX_SIZE - sizeof(mr_packet_header_t) - 2

typedef struct __attribute__((packed)) {
    uint8_t type;
    uint8_t value[DEFAULT_PAYLOAD_SIZE];
} default_payload_t;

typedef struct {
    mr_event_t      event;
    mr_event_data_t event_data;
    bool            event_ready;
    bool            led_blink_state;  // for blinking when not connected
    bool            send_status_ready;

    // bool attest_active;           // true after receiving MARI_ATTESTATION
    // bool attest_evidence_queued;  // true once we enqueued evidence
    // edhoc
    bool    edhoc_started;      ///< true once msg1 has been processed; prevents reprocessing on every beacon
    bool    edhoc_msg4_ready;   ///< msg4 generated and ready to send
    bool    edhoc_completed;    ///< EDHOC exchange completed
    uint8_t msg4_tx_count;      ///< number of times msg4 has been transmitted
} node_vars_t;

// Dedicated buffer for EDHOC msg3: fired from interrupt alongside MARI_CONNECTED,
// so the single-slot event system would overwrite it before the main loop can read it.
typedef struct {
    bool     ready;
    uint8_t  data[MARI_EDHOC_MAX_MSG_LEN];
    uint8_t  len;
    uint64_t asn_dl;  ///< ASN recorded when join response (msg3) was received
} edhoc_msg3_pending_t;

typedef struct __attribute__((packed)) {
    uint64_t marilib_timestamp;
    uint32_t rx_counter;
    uint32_t tx_counter;
} node_stats_t;

//=========================== variables ========================================

node_vars_t          node_vars         = { 0 };
node_stats_t         node_stats        = { 0 };
edhoc_msg3_pending_t _edhoc_msg3_pend  = { 0 };

extern schedule_t schedule_minuscule, schedule_tiny, schedule_huge;
schedule_t       *schedule_app = &schedule_huge;

// example status packet, to use as periodic uplink packet
uint8_t status_packet_mock[4] = {
    0x80,  // swarmit notification status
    1,     // SWRMT_DEVICE_TYPE_DOTBOTV3
    1,     // SWRMT_APPLICATION_RUNNING
    80,    // battery level
};

// EDHOC credentials (Responder = node, Initiator = edge/mari_edge)
// R = Responder's static private DH key
static const BytesP256ElemLen R = {
    0x72, 0xcc, 0x47, 0x61, 0xdb, 0xd4, 0xc7, 0x8f, 0x75, 0x89, 0x31, 0xaa, 0x58, 0x9d, 0x34, 0x8d,
    0x1e, 0xf8, 0x74, 0xa7, 0xe3, 0x03, 0xed, 0xe2, 0xf1, 0x40, 0xdc, 0xf3, 0xe6, 0xaa, 0x4a, 0xac
};
// CRED_R = Responder's credential (CCS with public key corresponding to R)
static const uint8_t CRED_R_BYTES[95] = {
    0xa2, 0x02, 0x6b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x65, 0x64, 0x75, 0x08, 0xa1,
    0x01, 0xa5, 0x01, 0x02, 0x02, 0x41, 0x32, 0x20, 0x01, 0x21, 0x58, 0x20, 0xbb, 0xc3, 0x49, 0x60,
    0x52, 0x6e, 0xa4, 0xd3, 0x2e, 0x94, 0x0c, 0xad, 0x2a, 0x23, 0x41, 0x48, 0xdd, 0xc2, 0x17, 0x91,
    0xa1, 0x2a, 0xfb, 0xcb, 0xac, 0x93, 0x62, 0x20, 0x46, 0xdd, 0x44, 0xf0, 0x22, 0x58, 0x20, 0x45,
    0x19, 0xe2, 0x57, 0x23, 0x6b, 0x2a, 0x0c, 0xe2, 0x02, 0x3f, 0x09, 0x31, 0xf1, 0xf3, 0x86, 0xca,
    0x7a, 0xfd, 0xa6, 0x4f, 0xcd, 0xe0, 0x10, 0x8c, 0x22, 0x4c, 0x51, 0xea, 0xbf, 0x60, 0x72
};
// CRED_I = Initiator's credential (edge/mari_edge public key)
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

// EDHOC Responder state
static EdhocResponder  edhoc_responder = {0};
static CredentialC     cred_r          = {0};
static CredentialC     cred_i          = {0};
static EdhocMessageBuffer edhoc_message_2 = {0};
static EdhocMessageBuffer edhoc_message_4 = {0};
static EADItemC        ead_1_out       = {0};
static EADItemC        ead_3_out       = {0};
static EADItemC        ead_4_out       = {0};
static IdCred          id_cred_i_out   = {0};
static uint8_t         edhoc_c_r       = 0;
static uint8_t         edhoc_prk_out[32] = {0};

//used during execution of attestation
//static EADItemC  ead_2 = {0};
//=========================== private ==========================================

static void _led_blink_callback(void) {
    if (!mari_node_is_connected()) {
        // not connected: blink blue (alternate between OFF and BLUE every 10ms)
        board_set_led_mari(node_vars.led_blink_state ? OFF : BLUE);
        node_vars.led_blink_state = !node_vars.led_blink_state;
    }
}

static void mari_event_callback(mr_event_t event, mr_event_data_t event_data) {
    if (event == MARI_EDHOC_MSG3) {
        // store in dedicated buffer: MARI_CONNECTED fires right after in the same call chain
        // and would overwrite the single-slot event before the main loop can read it
        _edhoc_msg3_pend.len    = event_data.data.edhoc.len;
        _edhoc_msg3_pend.asn_dl = mr_mac_get_asn();  // record when join response (msg3) arrived
        memcpy(_edhoc_msg3_pend.data, event_data.data.edhoc.data, event_data.data.edhoc.len);
        _edhoc_msg3_pend.ready = true;
        return;
    }
    memcpy(&node_vars.event, &event, sizeof(mr_event_t));
    memcpy(&node_vars.event_data, &event_data, sizeof(mr_event_data_t));
    node_vars.event_ready = true;
}

static void handle_metrics_payload(mr_metrics_payload_t *metrics_payload) {
    // update metrics probe
    metrics_payload->node_rx_count        = ++node_stats.rx_counter;
    metrics_payload->node_rx_asn          = mr_mac_get_asn();
    metrics_payload->node_tx_count        = ++node_stats.tx_counter;
    metrics_payload->node_tx_enqueued_asn = mr_mac_get_asn();
    metrics_payload->rssi_at_node         = mr_radio_rssi();

    // send metrics probe to gateway
    mari_node_tx_payload((uint8_t *)metrics_payload, sizeof(mr_metrics_payload_t));
}

static void _send_status_packet_callback(void) {
    node_vars.send_status_ready = true;
}

//=========================== main =============================================

int main(void) {
    // printf("Hello Mari Node %016llX\n", mr_device_id());
    mr_timer_hf_init(MARI_APP_TIMER_DEV);

    board_init();
    board_set_led_mari(BLUE);

    credential_new(&cred_r, CRED_R_BYTES, sizeof(CRED_R_BYTES));
    credential_new(&cred_i, CRED_I_BYTES, sizeof(CRED_I_BYTES));

    mari_init(MARI_NODE, 0xa3, schedule_app, &mari_event_callback);

    // blink blue every 100ms
    mr_timer_hf_set_periodic_us(MARI_APP_TIMER_DEV, 0, 100 * 1000, &_led_blink_callback);

    // send status packet every 500ms
    mr_timer_hf_set_periodic_us(MARI_APP_TIMER_DEV, 1, 500 * 1000, &_send_status_packet_callback);

    board_set_led_mari(OFF);

    while (1) {
        __SEV();
        __WFE();
        __WFE();

        if (node_vars.event_ready) {
            node_vars.event_ready = false;

            mr_event_t      event      = node_vars.event;
            mr_event_data_t event_data = node_vars.event_data;

            switch (event) {
                case MARI_NEW_PACKET:
                {
                    mari_packet_t packet = event_data.data.new_packet;

                    if (packet.payload_len >= 2 && packet.payload[0] == MARI_EDHOC_PAYLOAD_TAG) {
                        // EDHOC msg3 delivered as downlink data packet
                        uint8_t m3_len = packet.payload[1];
                        if (m3_len > 0 && m3_len <= MAX_MESSAGE_SIZE_LEN &&
                            (uint8_t)(2 + m3_len) <= packet.payload_len) {
                            EdhocMessageBuffer msg3 = {0};
                            memcpy(msg3.content, packet.payload + 2, m3_len);
                            msg3.len = m3_len;
                            if (responder_parse_message_3(&edhoc_responder, &msg3, &id_cred_i_out, &ead_3_out) != 0) { break; }
                            if (responder_verify_message_3(&edhoc_responder, &cred_i, &edhoc_prk_out) != 0) { break; }
                            uint8_t evidence_cbor[MAX_EVIDENCE];
                            uint8_t evidence_len = 0;
                            mr_attestation_evidence_generation(mr_mac_get_asn(), edhoc_responder.processed_m3.prk_exporter, evidence_cbor, &evidence_len);
                            ead_4_out.label       = 1;
                            ead_4_out.is_critical = false;
                            memcpy(ead_4_out.value.content, evidence_cbor, evidence_len);
                            ead_4_out.value.len   = evidence_len;
                            if (responder_prepare_message_4(&edhoc_responder, &ead_4_out, &edhoc_message_4) != 0) { break; }
                            node_vars.edhoc_msg4_ready = true;
                            node_vars.edhoc_completed  = true;
                            node_vars.msg4_tx_count    = 0;
                        }
                    } else if (packet.payload_len == sizeof(mr_metrics_payload_t) && packet.payload[0] == MARI_PAYLOAD_TYPE_METRICS_PROBE) {
                        handle_metrics_payload((mr_metrics_payload_t *)packet.payload);
                    } else {
                        // TBD custom application logic
                    }

                    break;
                }
                case MARI_CONNECTED:
                {
                    uint64_t gateway_id = event_data.data.gateway_info.gateway_id;
                    board_set_led_mari_gateway(gateway_id);
                    board_set_led_mari(YELLOW);
                    break;
                }
                case MARI_DISCONNECTED:
                {
                    board_set_led_mari(OFF);
                    node_vars.edhoc_started    = false;
                    node_vars.edhoc_msg4_ready = false;
                    node_vars.edhoc_completed  = false;
                    node_vars.msg4_tx_count    = 0;
                    _edhoc_msg3_pend.ready     = false;
                    break;
                }
                // case MARI_ATTESTATION: (disabled, pure EDHOC only)
                case MARI_EDHOC_MSG1:
                {
                    // only process msg1 once; every beacon carries msg1 so without this guard
                    // the responder state would be reset on each beacon, causing msg3 to mismatch
                    if (node_vars.edhoc_started) { break; }

                    // process msg1 and generate msg2, append to pending join request
                    EdhocMessageBuffer msg1 = {0};
                    uint8_t            m1_len = event_data.data.edhoc.len;
                    if (m1_len > MAX_MESSAGE_SIZE_LEN) { m1_len = MAX_MESSAGE_SIZE_LEN; }
                    memcpy(msg1.content, event_data.data.edhoc.data, m1_len);
                    msg1.len = m1_len;

                    // initialize responder (generates ephemeral key pair)
                    if (responder_new(&edhoc_responder) != 0) { break; }
                    // process msg1
                    uint8_t c_i_out = 0;
                    if (responder_process_message_1(&edhoc_responder, &msg1, &c_i_out, &ead_1_out) != 0) { break; }
                    // build EAD_2: CBOR array [node_id, asn] for Mari context binding
                    EADItemC ead_2_item = {0};
                    ead_2_item.label       = 2;
                    ead_2_item.is_critical = false;
                    {
                        uint8_t *p = ead_2_item.value.content;
                        uint8_t  n = 0;
                        p[n++] = 0x82;  // CBOR array(2)
                        uint64_t nid = mr_device_id();
                        p[n++] = 0x1b;
                        for (int s = 7; s >= 0; s--) { p[n++] = (nid >> (s * 8)) & 0xFF; }
                        uint64_t asn = mr_mac_get_asn();
                        p[n++] = 0x1b;
                        for (int s = 7; s >= 0; s--) { p[n++] = (asn >> (s * 8)) & 0xFF; }
                        ead_2_item.value.len = n;
                    }
                    // prepare msg2
                    if (responder_prepare_message_2(&edhoc_responder, &cred_r, &R,
                                                    ByReference, &ead_2_item,
                                                    &edhoc_message_2, &edhoc_c_r) != 0) { break; }
                    // lock in this EDHOC session before appending msg2 to join request
                    node_vars.edhoc_started = true;
                    mr_queue_append_edhoc_to_join_request(edhoc_message_2.content, (uint8_t)edhoc_message_2.len);
                    printf("[EDHOC] msg2 (%u B): ", (unsigned)edhoc_message_2.len);
                    for (size_t i = 0; i < edhoc_message_2.len; i++) { printf("%02x", edhoc_message_2.content[i]); }
                    printf("\n");
                    break;
                }
                default:
                    break;
            }
        }

        // drain pending EDHOC msg3 (stored separately to avoid being overwritten by MARI_CONNECTED)
        if (_edhoc_msg3_pend.ready) {
            _edhoc_msg3_pend.ready = false;
            EdhocMessageBuffer msg3   = {0};
            uint8_t            m3_len = _edhoc_msg3_pend.len;
            uint64_t           asn_dl = _edhoc_msg3_pend.asn_dl;
            if (m3_len > MAX_MESSAGE_SIZE_LEN) { m3_len = MAX_MESSAGE_SIZE_LEN; }
            memcpy(msg3.content, _edhoc_msg3_pend.data, m3_len);
            msg3.len = m3_len;
            if (responder_parse_message_3(&edhoc_responder, &msg3, &id_cred_i_out, &ead_3_out) != 0) { goto msg3_done; }
            if (responder_verify_message_3(&edhoc_responder, &cred_i, &edhoc_prk_out) != 0) { goto msg3_done; }
            {
                uint8_t evidence_cbor[MAX_EVIDENCE];
                uint8_t evidence_len = 0;
                mr_attestation_evidence_generation(asn_dl, edhoc_responder.processed_m3.prk_exporter, evidence_cbor, &evidence_len);
                ead_4_out.label       = 1;
                ead_4_out.is_critical = false;
                memcpy(ead_4_out.value.content, evidence_cbor, evidence_len);
                ead_4_out.value.len   = evidence_len;
            }
            if (responder_prepare_message_4(&edhoc_responder, &ead_4_out, &edhoc_message_4) != 0) { goto msg3_done; }
            node_vars.edhoc_msg4_ready = true;
            node_vars.edhoc_completed  = true;
            node_vars.msg4_tx_count    = 0;
            msg3_done:;
        }

        if (node_vars.send_status_ready) {
            node_vars.send_status_ready = false;
            if (node_vars.edhoc_msg4_ready) {
                uint8_t msg4_buf[2 + MARI_EDHOC_MAX_MSG_LEN];
                uint8_t pos       = 0;
                msg4_buf[pos++]   = MARI_EDHOC_PAYLOAD_TAG;
                msg4_buf[pos++]   = (uint8_t)edhoc_message_4.len;
                memcpy(msg4_buf + pos, edhoc_message_4.content, edhoc_message_4.len);
                pos += (uint8_t)edhoc_message_4.len;
                printf("[EDHOC] msg4 tx#%u EDHOC=%u B: ", (unsigned)(node_vars.msg4_tx_count + 1), (unsigned)edhoc_message_4.len);
                for (uint8_t i = 0; i < pos; i++) { printf("%02x", msg4_buf[i]); }
                printf("\n");
                mari_node_tx_payload(msg4_buf, pos);
                board_set_led_mari(GREEN);
                node_vars.msg4_tx_count++;
                if (node_vars.msg4_tx_count >= MSG4_MAX_RETRIES) {
                    node_vars.edhoc_msg4_ready = false;  // stop retrying after max attempts
                }
            } else {
                mari_node_tx_payload((uint8_t *)status_packet_mock, sizeof(status_packet_mock));
            }
        }

        mari_event_loop();
    }
}
