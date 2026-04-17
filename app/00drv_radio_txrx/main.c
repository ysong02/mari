/**
 * @file
 * @ingroup     net_maclow
 *
 * @brief       Example on how to use the maclow driver
 *
 * @author Geovane Fedrecheski <geovane.fedrecheski@inria.fr>
 *
 * @copyright Inria, 2024
 */
#include <nrf.h>
#include <stdio.h>
#include <stdlib.h>

#include "mr_device.h"
#include "mr_radio.h"
#include "mr_timer_hf.h"
#include "packet.h"
#include "scheduler.h"
#include "mac.h"

//=========================== debug ============================================

#include "mr_gpio.h"
mr_gpio_t pin0 = { .port = 1, .pin = 2 };  // variable names reflect the logic analyzer channels
mr_gpio_t pin1 = { .port = 1, .pin = 3 };
mr_gpio_t pin2 = { .port = 1, .pin = 4 };
mr_gpio_t pin3 = { .port = 1, .pin = 5 };
#define DEBUG_GPIO_TOGGLE(pin) mr_gpio_toggle(pin)
#define DEBUG_GPIO_SET(pin)    mr_gpio_set(pin)
#define DEBUG_GPIO_CLEAR(pin)  mr_gpio_clear(pin)

//=========================== defines =========================================

typedef struct {
    uint64_t asn;
} txrx_vars_t;

//=========================== variables =======================================

txrx_vars_t txrx_vars = { 0 };

extern schedule_t schedule_only_beacons, schedule_huge;

//=========================== prototypes ======================================

static void send_beacon_prepare(void);
static void send_beacon_dispatch(void);

static void isr_radio_start_frame(uint32_t ts);
static void isr_radio_end_frame(uint32_t ts);

//=========================== main ============================================

int main(void) {
    mr_timer_hf_init(MARI_TIMER_DEV);
    mr_gpio_init(&pin0, MR_GPIO_OUT);
    mr_gpio_init(&pin1, MR_GPIO_OUT);

    mr_radio_init(&isr_radio_start_frame, &isr_radio_end_frame, MR_RADIO_BLE_2MBit);
    mr_radio_set_channel(MARI_FIXED_SCAN_CHANNEL);

    printf("MARI_FIXED_SCAN_CHANNEL = %d\n", MARI_FIXED_SCAN_CHANNEL);

    mr_timer_hf_set_periodic_us(MARI_TIMER_DEV, 0, 5000, send_beacon_prepare);  // 5 ms

    while (1) {
        __WFE();
    }
}

//=========================== private =========================================

static void send_beacon_prepare(void) {
    printf("Sending beacon from %llx\n", mr_device_id());
    uint8_t packet[MARI_PACKET_MAX_SIZE] = { 0 };
    size_t  len                          = mr_build_packet_beacon(packet, txrx_vars.asn++, 10, schedule_huge.id);
    mr_radio_disable();
    mr_radio_tx_prepare(packet, len);
    DEBUG_GPIO_SET(&pin0);
    // give 100 us for radio to ramp up
    mr_timer_hf_set_oneshot_us(MARI_TIMER_DEV, 1, 100, &send_beacon_dispatch);
}

static void send_beacon_dispatch(void) {
    mr_radio_tx_dispatch();
    // DEBUG_GPIO_CLEAR(&pin0);

    // beacon = 20 bytes = TOA 80 us
    // schedule radio for RX in 200 us
    mr_timer_hf_set_oneshot_us(MARI_TIMER_DEV, 1, 200, mr_radio_rx);
}

static void isr_radio_start_frame(uint32_t ts) {
    DEBUG_GPIO_SET(&pin1);
    printf("Start frame at %d\n", ts);
}

static void isr_radio_end_frame(uint32_t ts) {
    DEBUG_GPIO_CLEAR(&pin1);
    printf("End frame at %d\n", ts);

    if (mr_radio_pending_rx_read()) {  // interrupt came from RX
        uint8_t packet[MARI_PACKET_MAX_SIZE];
        uint8_t length;
        mr_radio_get_rx_packet(packet, &length);
        printf("Received packet of length %d\n", length);
        for (size_t i = 0; i < length; i++) {
            printf("%02x ", packet[i]);
        }
        puts("");
    } else {  // interrupt came from TX
        // handle, if needed
    }
}
