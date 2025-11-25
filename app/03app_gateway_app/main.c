/**
 * @file
 * @ingroup     app
 *
 * @brief       Mari Gateway application (uart side)
 *
 * @author Geovane Fedrecheski <geovane.fedrecheski@inria.fr>
 * @author Alexandre Abadie <alexandre.abadie@inria.fr>
 *
 * @copyright Inria, 2025-now
 */
#include <nrf.h>
#include <stdio.h>
#include <string.h>

#include "ipc.h"

#include "mr_clock.h"
#include "mr_device.h"
#include "hdlc.h"
#include "uart.h"

#include "mr_gpio.h"
mr_gpio_t pin_hdlc_error        = { .port = 1, .pin = 5 };
mr_gpio_t pin_hdlc_ready_decode = { .port = 1, .pin = 10 };
mr_gpio_t pin_dbg_ipc           = { .port = 1, .pin = 3 };
mr_gpio_t pin_dbg_timer         = { .port = 1, .pin = 7 };
mr_gpio_t pin_dbg_uart          = { .port = 1, .pin = 8 };
// mr_gpio_t pin_dbg_uart_write = { .port = 1, .pin = 9 };
mr_gpio_t pin_dbg_uart_new = { .port = 1, .pin = 9 };

//=========================== defines ==========================================

#define MR_UART_INDEX    (1)          ///< Index of UART peripheral to use
#define MR_UART_BAUDRATE (1000000UL)  ///< UART baudrate used by the gateway

#define TX_QUEUE_SIZE 32

typedef struct {
    uint8_t buffer[256];
    size_t  length;
} tx_frame_t;

typedef struct {
    bool    uart_buffer_received;
    uint8_t uart_buffer[256];
    size_t  uart_buffer_length;

    uint8_t hdlc_encode_buffer[1024];  // Should be large enough
    bool    tx_pending;                // Flag for deferred TX (legacy)
    size_t  tx_frame_len;              // Length of frame to transmit

    // TX queue
    tx_frame_t tx_queue[TX_QUEUE_SIZE];
    uint8_t    tx_queue_head;
    uint8_t    tx_queue_tail;
    uint8_t    tx_queue_count;
} gateway_app_vars_t;

//=========================== variables ======================================== 

// UART RX and TX pins
static const mr_gpio_t _mr_uart_tx_pin = { .port = 1, .pin = 1 };
static const mr_gpio_t _mr_uart_rx_pin = { .port = 1, .pin = 0 };

static gateway_app_vars_t                                           _app_vars = { 0 };
volatile __attribute__((section(".shared_data"))) ipc_shared_data_t ipc_shared_data;

static void _setup_debug_pins(void) {
    // Assign P0.28 to P0.31 to the network core (for debugging association.c via LEDs)
    NRF_P0_S->PIN_CNF[28] = GPIO_PIN_CNF_MCUSEL_NetworkMCU << GPIO_PIN_CNF_MCUSEL_Pos;
    NRF_P0_S->PIN_CNF[29] = GPIO_PIN_CNF_MCUSEL_NetworkMCU << GPIO_PIN_CNF_MCUSEL_Pos;
    NRF_P0_S->PIN_CNF[30] = GPIO_PIN_CNF_MCUSEL_NetworkMCU << GPIO_PIN_CNF_MCUSEL_Pos;
    NRF_P0_S->PIN_CNF[31] = GPIO_PIN_CNF_MCUSEL_NetworkMCU << GPIO_PIN_CNF_MCUSEL_Pos;

    // Assign P1.02 to P1.05 to the network core (for debugging mac.c via logic analyzer)
    NRF_P1_S->PIN_CNF[2] = GPIO_PIN_CNF_MCUSEL_NetworkMCU << GPIO_PIN_CNF_MCUSEL_Pos;
    NRF_P1_S->PIN_CNF[3] = GPIO_PIN_CNF_MCUSEL_NetworkMCU << GPIO_PIN_CNF_MCUSEL_Pos;
    NRF_P1_S->PIN_CNF[4] = GPIO_PIN_CNF_MCUSEL_NetworkMCU << GPIO_PIN_CNF_MCUSEL_Pos;
    NRF_P1_S->PIN_CNF[5] = GPIO_PIN_CNF_MCUSEL_NetworkMCU << GPIO_PIN_CNF_MCUSEL_Pos;

    // Configure all GPIOs as non secure
    NRF_SPU_S->GPIOPORT[0].PERM = 0;
    NRF_SPU_S->GPIOPORT[1].PERM = 0;
}

static void _configure_ram_non_secure(uint8_t start_region, size_t length) {
    for (uint8_t region = start_region; region < start_region + length; region++) {
        NRF_SPU_S->RAMREGION[region].PERM = (SPU_RAMREGION_PERM_READ_Enable << SPU_RAMREGION_PERM_READ_Pos |
                                             SPU_RAMREGION_PERM_WRITE_Enable << SPU_RAMREGION_PERM_WRITE_Pos |
                                             SPU_RAMREGION_PERM_EXECUTE_Enable << SPU_RAMREGION_PERM_EXECUTE_Pos |
                                             SPU_RAMREGION_PERM_SECATTR_Non_Secure << SPU_RAMREGION_PERM_SECATTR_Pos);
    }
}

static void _init_ipc(void) {
    NRF_IPC_S->INTENSET                            = (1 << IPC_CHAN_RADIO_TO_UART);
    NRF_IPC_S->SEND_CNF[IPC_CHAN_UART_TO_RADIO]    = (1 << IPC_CHAN_UART_TO_RADIO);
    NRF_IPC_S->RECEIVE_CNF[IPC_CHAN_RADIO_TO_UART] = (1 << IPC_CHAN_RADIO_TO_UART);

    NVIC_EnableIRQ(IPC_IRQn);
    NVIC_ClearPendingIRQ(IPC_IRQn);
    NVIC_SetPriority(IPC_IRQn, IPC_IRQ_PRIORITY);
}

static void _release_network_core(void) {
    // Do nothing if network core is already started and ready
    if (!NRF_RESET_S->NETWORK.FORCEOFF && ipc_shared_data.net_ready) {
        return;
    } else if (!NRF_RESET_S->NETWORK.FORCEOFF) {
        ipc_shared_data.net_ready = false;
    }

    NRF_RESET_S->NETWORK.FORCEOFF = (RESET_NETWORK_FORCEOFF_FORCEOFF_Release << RESET_NETWORK_FORCEOFF_FORCEOFF_Pos);

    // add an extra delay to ensure the network core is released
    // NOTE: this is very hacky, but since this only happens once, we don't want to consume another timer
    for (uint32_t i = 0; i < 500000; i++) {
        __NOP();
    }

    while (!ipc_shared_data.net_ready) {}
}

// TX queue management functions
static bool _tx_queue_is_empty(void) {
    return _app_vars.tx_queue_count == 0;
}

static bool _tx_queue_is_full(void) {
    return _app_vars.tx_queue_count >= TX_QUEUE_SIZE;
}

static bool _tx_queue_enqueue(const uint8_t *data, size_t length) {
    if (_tx_queue_is_full() || length > sizeof(_app_vars.tx_queue[0].buffer)) {
        return false;  // Queue full or frame too large
    }

    memcpy(_app_vars.tx_queue[_app_vars.tx_queue_head].buffer, data, length);
    _app_vars.tx_queue[_app_vars.tx_queue_head].length = length;
    _app_vars.tx_queue_head                            = (_app_vars.tx_queue_head + 1) % TX_QUEUE_SIZE;
    _app_vars.tx_queue_count++;
    return true;
}

static bool _tx_queue_dequeue(uint8_t *data, size_t *length) {
    if (_tx_queue_is_empty()) {
        return false;
    }

    *length = _app_vars.tx_queue[_app_vars.tx_queue_tail].length;
    memcpy(data, _app_vars.tx_queue[_app_vars.tx_queue_tail].buffer, *length);
    _app_vars.tx_queue_tail = (_app_vars.tx_queue_tail + 1) % TX_QUEUE_SIZE;
    _app_vars.tx_queue_count--;
    return true;
}

static void _uart_callback(uint8_t *buffer, size_t length) {
    if (length == 0) {
        return;
    }

    memcpy(_app_vars.uart_buffer, buffer, length);
    _app_vars.uart_buffer_length   = length;
    _app_vars.uart_buffer_received = true;
}

int main(void) {
    printf("Hello Mari Gateway App Core (UART) %016llX\n", mr_device_id());

    _setup_debug_pins();

    mr_gpio_init(&pin_hdlc_error, MR_GPIO_OUT);
    mr_gpio_init(&pin_hdlc_ready_decode, MR_GPIO_OUT);
    mr_gpio_init(&pin_dbg_ipc, MR_GPIO_OUT);
    mr_gpio_init(&pin_dbg_timer, MR_GPIO_OUT);
    mr_gpio_init(&pin_dbg_uart, MR_GPIO_OUT);
    // mr_gpio_init(&pin_dbg_uart_write, MR_GPIO_OUT);
    mr_gpio_init(&pin_dbg_uart_new, MR_GPIO_OUT);

    // Enable HFCLK with external 32MHz oscillator
    mr_hfclk_init();

    _configure_ram_non_secure(2, 1);
    _init_ipc();
    mr_uart_init(MR_UART_INDEX, &_mr_uart_rx_pin, &_mr_uart_tx_pin, MR_UART_BAUDRATE, &_uart_callback);

    _release_network_core();
    // this is a bit hacky -- sometimes it does not work without this
    NRF_RESET_S->NETWORK.FORCEOFF = 0;

    while (1) {
        __WFE();

        if (_app_vars.uart_buffer_received) {
            _app_vars.uart_buffer_received = false;
            mr_gpio_set(&pin_dbg_uart_new);

            // use a loop to decode the whole buffer, testing the state machine at each byte
            for (size_t i = 0; i < _app_vars.uart_buffer_length; i++) {
                mr_hdlc_state_t hdlc_state = mr_hdlc_rx_byte(_app_vars.uart_buffer[i]);
                if (hdlc_state == MR_HDLC_STATE_READY) {
                    // decode the frame and send it to the radio
                    mr_gpio_set(&pin_hdlc_ready_decode);
                    // decode the frame
                    size_t msg_len                    = mr_hdlc_decode((uint8_t *)(void *)ipc_shared_data.uart_to_radio);
                    ipc_shared_data.uart_to_radio_len = msg_len;
                    if (msg_len) {
                        NRF_IPC_S->TASKS_SEND[IPC_CHAN_UART_TO_RADIO] = 1;
                    }
                    mr_gpio_clear(&pin_hdlc_ready_decode);
                    // we can break since we assume that the python code never sends two frames too fast in a row
                    break;
                } else if (hdlc_state == MR_HDLC_STATE_ERROR) {
                    mr_gpio_set(&pin_hdlc_error);
                    mr_gpio_clear(&pin_hdlc_error);
                    break;
                }
            }
            mr_gpio_clear(&pin_dbg_uart_new);
        }

        // Process queued TX frames when conditions are right
        if (!_tx_queue_is_empty() && !mr_uart_tx_busy(MR_UART_INDEX)) {
            uint8_t frame_data[256];
            size_t  frame_len;

            if (_tx_queue_dequeue(frame_data, &frame_len)) {
                _app_vars.tx_frame_len = mr_hdlc_encode(frame_data, frame_len, _app_vars.hdlc_encode_buffer);
                // mr_gpio_set(&pin_dbg_uart_write);
                mr_uart_write(MR_UART_INDEX, _app_vars.hdlc_encode_buffer, _app_vars.tx_frame_len);
                // mr_gpio_clear(&pin_dbg_uart_write);
            }
        }

        // Handle deferred TX when UART becomes available (keep for compatibility)
        if (_app_vars.tx_pending && !mr_uart_tx_busy(MR_UART_INDEX)) {
            _app_vars.tx_pending = false;
            // mr_gpio_set(&pin_dbg_uart_write);
            mr_uart_write(MR_UART_INDEX, _app_vars.hdlc_encode_buffer, _app_vars.tx_frame_len);
            // mr_gpio_clear(&pin_dbg_uart_write);
        }
    }
}

void IPC_IRQHandler(void) {
    mr_gpio_set(&pin_dbg_ipc);
    if (NRF_IPC_S->EVENTS_RECEIVE[IPC_CHAN_RADIO_TO_UART]) {
        NRF_IPC_S->EVENTS_RECEIVE[IPC_CHAN_RADIO_TO_UART] = 0;

        // Enqueue the frame instead of just setting a flag
        if (!_tx_queue_enqueue((const uint8_t *)ipc_shared_data.radio_to_uart, ipc_shared_data.radio_to_uart_len)) {
            // Queue full - could add error handling/statistics here
        }
    }
    mr_gpio_clear(&pin_dbg_ipc);
}
