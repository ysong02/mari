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

#include "board.h"

#include "attestation.h"

//=========================== defines ==========================================

#define MARI_APP_NET_ID MARI_NET_ID_DEFAULT

#define MARI_APP_TIMER_DEV 1

// -2 is for the type and needs_ack fields
#define DEFAULT_PAYLOAD_SIZE MARI_PACKET_MAX_SIZE - sizeof(mr_packet_header_t) - 2

typedef enum {
    PAYLOAD_TYPE_APPLICATION      = 1,
    PAYLOAD_TYPE_METRICS_REQUEST  = 128,
    PAYLOAD_TYPE_METRICS_RESPONSE = 129,
    PAYLOAD_TYPE_METRICS_LOAD     = 130,
} default_payload_type_t;

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
} node_vars_t;

typedef struct __attribute__((packed)) {
    uint64_t marilib_timestamp;
    uint32_t rx_counter;
    uint32_t tx_counter;
} node_stats_t;

//=========================== variables ========================================

node_vars_t  node_vars  = { 0 };
node_stats_t node_stats = { 0 };

extern schedule_t schedule_minuscule, schedule_tiny, schedule_huge;
schedule_t       *schedule_app = &schedule_huge;

// example status packet, to use as periodic uplink packet
uint8_t status_packet_mock[4] = {
    0x90,  // swarmit notification status
    1,     // SWRMT_DEVICE_TYPE_DOTBOTV3
    1,     // SWRMT_APPLICATION_RUNNING
    80,    // battery level
};

//=========================== private ==========================================

static void _led_blink_callback(void) {
    if (!mari_node_is_connected()) {
        // not connected: blink blue (alternate between OFF and BLUE every 10ms)
        board_set_led_mari(node_vars.led_blink_state ? OFF : BLUE);
        node_vars.led_blink_state = !node_vars.led_blink_state;
    }
}

static void mari_event_callback(mr_event_t event, mr_event_data_t event_data) {
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
    printf("Hello Mari Node %016llX\n", mr_device_id());
    mr_timer_hf_init(MARI_APP_TIMER_DEV);

    board_init();
    board_set_led_mari(RED);

    mari_init(MARI_NODE, MARI_APP_NET_ID, schedule_app, &mari_event_callback);

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

                    if (packet.payload_len == sizeof(mr_metrics_payload_t) && packet.payload[0] == MARI_PAYLOAD_TYPE_METRICS_PROBE) {
                        handle_metrics_payload((mr_metrics_payload_t *)packet.payload);
                    } else {
                        // TBD custom application logic
                    }

                    break;
                }
                case MARI_CONNECTED:
                {
                    uint64_t gateway_id = event_data.data.gateway_info.gateway_id;
                    printf("Connected to gateway %016llX\n", gateway_id);
                    board_set_led_mari_gateway(gateway_id);
                    break;
                }
                case MARI_DISCONNECTED:
                {
                    uint64_t gateway_id = event_data.data.gateway_info.gateway_id;
                    printf("Disconnected from gateway %016llX, reason: %u\n", gateway_id, event_data.tag);
                    board_set_led_mari(OFF);
                    break;
                }
                case MARI_ATTESTATION:
                {
                    uint8_t payload[MAX_EVIDENCE];
                    uint8_t payload_len = 0;
                    payload[payload_len ++] = 0xE1;

                    uint64_t asn_dl = mari_node_get_last_asn_dl();
                    mr_attestation_evidence_generation(asn_dl, payload, &payload_len);
                    
                    mari_node_tx_payload(payload, payload_len);
                    break;
                }
                default:
                    break;
            }
        }

        if (node_vars.send_status_ready) {
            node_vars.send_status_ready = false;
            mari_node_tx_payload((uint8_t *)status_packet_mock, sizeof(status_packet_mock));
        }

        mari_event_loop();
    }
}
