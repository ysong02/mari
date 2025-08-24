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

#include "board.h"

#include "attestation.h"

//=========================== defines ==========================================

#define MARI_APP_TIMER_DEV 1

#define LATENCY_MAGIC_BYTE_1 0x4C
#define LATENCY_MAGIC_BYTE_2 0x54
#define LOAD_PACKET_BYTE     'L'

static const uint8_t NORMAL_DATA_PAYLOAD[] = "NORMAL_APP_DATA";

typedef struct {
    mr_event_t      event;
    mr_event_data_t event_data;
    bool            event_ready;
    bool            led_blink_state;  // for blinking when not connected
} node_vars_t;

typedef struct __attribute__((packed)) {
    uint32_t rx_app_packets;
    uint32_t tx_app_packets;
} node_stats_t;

//=========================== variables ========================================

node_vars_t  node_vars  = { 0 };
node_stats_t node_stats = { 0 };

extern schedule_t schedule_minuscule, schedule_tiny, schedule_huge;

schedule_t *schedule_app = &schedule_huge;

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

//=========================== main =============================================

int main(void) {
    printf("Hello Mari Node %016llX\n", mr_device_id());
    mr_timer_hf_init(MARI_APP_TIMER_DEV);

    board_init();
    board_set_led_mari(BLUE);

    mari_init(MARI_NODE, MARI_NET_ID_PATTERN_ANY, schedule_app, &mari_event_callback);

    mr_timer_hf_set_periodic_us(MARI_APP_TIMER_DEV, 0, 100 * 1000, &_led_blink_callback);

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

                    if (packet.payload_len >= 2 &&
                        packet.payload[0] == LATENCY_MAGIC_BYTE_1 &&
                        packet.payload[1] == LATENCY_MAGIC_BYTE_2) {
                        mari_node_tx_payload(packet.payload, packet.payload_len);
                    } else if (packet.payload_len == sizeof(NORMAL_DATA_PAYLOAD) - 1 &&
                               strncmp((char *)packet.payload, (char *)NORMAL_DATA_PAYLOAD, sizeof(NORMAL_DATA_PAYLOAD) - 1) == 0) {
                        node_stats.rx_app_packets++;
                        mari_node_tx_payload((uint8_t *)&node_stats, sizeof(node_stats_t));
                        node_stats.tx_app_packets++;
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
                    uint8_t payload_len    = 0;
                    payload[payload_len++] = MARI_ATTEST_EVIDENCE_PAYLOAD_TAG;

                    uint64_t asn_dl = mari_node_get_last_asn_dl();
                    mr_attestation_evidence_generation(asn_dl, payload, &payload_len);

                    mari_node_tx_payload(payload, payload_len);
                    break;
                }
                default:
                    break;
            }
        }

        mari_event_loop();
    }
}
