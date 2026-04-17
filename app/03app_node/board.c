/**
 * @file
 * @brief       Board-specific implementations.
 * @details
 *
 */

#include "board.h"
#include "board_config.h"
#include "mr_gpio.h"
#include <nrf.h>

// --- PIN DEFINITIONS ---

#ifdef MARI_BOARD_MINIMOTE
static mr_gpio_t _r_led_pin = { .port = 0, .pin = 28 };
static mr_gpio_t _g_led_pin = { .port = 0, .pin = 2 };
static mr_gpio_t _b_led_pin = { .port = 0, .pin = 3 };
#endif

#ifdef MARI_BOARD_NRF52840_DONGLE
// Mari Status LED
static mr_gpio_t _r_led_pin = { .port = 0, .pin = 8 };   // LED 2 Red
static mr_gpio_t _g_led_pin = { .port = 1, .pin = 9 };   // LED 2 Green
static mr_gpio_t _b_led_pin = { .port = 0, .pin = 12 };  // LED 2 Blue

// App Status LED
static mr_gpio_t _app_led_pin = { .port = 0, .pin = 6 };  // LED 1 Green
#endif

void board_init(void) {
#ifdef MARI_BOARD_MINIMOTE
    // Make sure the mini-mote is running at 3.0v
    if (NRF_UICR->REGOUT0 != UICR_REGOUT0_VOUT_3V0) {
        NRF_NVMC->CONFIG = NVMC_CONFIG_WEN_Wen << NVMC_CONFIG_WEN_Pos;
        while (NRF_NVMC->READY == NVMC_READY_READY_Busy) {}
        NRF_UICR->REGOUT0 = UICR_REGOUT0_VOUT_3V0;
        NRF_NVMC->CONFIG  = NVMC_CONFIG_WEN_Ren << NVMC_CONFIG_WEN_Pos;
        while (NRF_NVMC->READY == NVMC_READY_READY_Busy) {}
    }
#endif
    mr_gpio_init(&_r_led_pin, MR_GPIO_OUT);
    mr_gpio_init(&_g_led_pin, MR_GPIO_OUT);
    mr_gpio_init(&_b_led_pin, MR_GPIO_OUT);
    board_set_led_mari(OFF);

#ifdef MARI_BOARD_NRF52840_DONGLE
    mr_gpio_init(&_app_led_pin, MR_GPIO_OUT);
    board_set_led_app(OFF);
#endif

    mr_gpio_t _reg_pin = { .port = 0, .pin = 30 };
    // Turn ON the DotBot board regulator if provided
    mr_gpio_init(&_reg_pin, MR_GPIO_OUT);
    mr_gpio_set(&_reg_pin);
}

static led_color_t _get_color_for_gateway(uint64_t gateway_id) {
    switch (gateway_id) {
        case 0x1B5B306C3D7542D0:  // 2024, Yinghao
            return GREEN;
        case 0xD5A813E7177DD598:  // 2025, TBD
            return PINK;
        case 0x7D4ADB2FBBA3797F:  // 2025, Geovane
            return YELLOW;
        case 0x6850EE16F49FB570:
            return RED;
        default:
            return BLUE;
    }
}

void board_set_led_mari_gateway(uint64_t gateway_id) {
    led_color_t color = _get_color_for_gateway(gateway_id);
    board_set_led_mari(color);
}

void board_set_led_mari(led_color_t color) {
    // clear = ON, set = OFF
    switch (color) {
        case RED:
            mr_gpio_clear(&_r_led_pin);
            mr_gpio_set(&_g_led_pin);
            mr_gpio_set(&_b_led_pin);
            break;
        case GREEN:
            mr_gpio_set(&_r_led_pin);
            mr_gpio_clear(&_g_led_pin);
            mr_gpio_set(&_b_led_pin);
            break;
        case BLUE:
            mr_gpio_set(&_r_led_pin);
            mr_gpio_set(&_g_led_pin);
            mr_gpio_clear(&_b_led_pin);
            break;
        case PINK:
            mr_gpio_clear(&_r_led_pin);
            mr_gpio_set(&_g_led_pin);
            mr_gpio_clear(&_b_led_pin);
            break;
        case YELLOW:
            mr_gpio_clear(&_r_led_pin);
            mr_gpio_clear(&_g_led_pin);
            mr_gpio_set(&_b_led_pin);
            break;
        case CYAN:
            mr_gpio_set(&_r_led_pin);
            mr_gpio_clear(&_g_led_pin);
            mr_gpio_clear(&_b_led_pin);
            break;
        default:
            mr_gpio_set(&_r_led_pin);
            mr_gpio_set(&_g_led_pin);
            mr_gpio_set(&_b_led_pin);
            break;
    }
}

void board_set_led_app(led_color_t color) {
#ifdef MARI_BOARD_NRF52840_DONGLE
    // Controls the green LED (LED1) on the dongle.
    if (color == GREEN) {
        mr_gpio_clear(&_app_led_pin);
    } else {
        mr_gpio_set(&_app_led_pin);
    }
#endif
#ifdef MARI_BOARD_MINIMOTE
#endif
}
