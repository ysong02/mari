/**
 * @file
 * @ingroup bsp_uart
 *
 * @brief  nRF52833-specific definition of the "uart" bsp module.
 *
 * @author Alexandre Abadie <alexandre.abadie@inria.fr>
 *
 * @copyright Inria, 2022
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <nrf.h>
#include <nrf_peripherals.h>

#include "mr_gpio.h"
#include "uart.h"

//=========================== defines ==========================================

#if defined(NRF5340_XXAA) && defined(NRF_APPLICATION)
#define NRF_POWER      (NRF_POWER_S)
#define NRF_UART_TIMER (NRF_TIMER2_S)
#define TIMER_CC_NUM   TIMER2_CC_NUM
#define TIMER_IRQ      TIMER2_IRQn
#elif defined(NRF5340_XXAA) && defined(NRF_NETWORK)
#define NRF_POWER      (NRF_POWER_NS)
#define NRF_UART_TIMER (NRF_TIMER2_NS)
#define TIMER_CC_NUM   TIMER2_CC_NUM
#define TIMER_IRQ      TIMER2_IRQn
#else
#define NRF_UART_TIMER (NRF_TIMER4)
#define TIMER_CC_NUM   TIMER4_CC_NUM
#define TIMER_IRQ      TIMER4_IRQn
#endif

#define MR_UARTE_CHUNK_SIZE (64U)

typedef enum {
    UART_RX_STATE_IDLE = 1,
    UART_RX_STATE_RX_TRIGGER_BYTE,
    UART_RX_STATE_BACKOFF_TRIGGER_BYTE,
    UART_RX_STATE_RX_CHUNK,
} uart_rx_state_t;

typedef struct {
    NRF_UARTE_Type *p;
    IRQn_Type       irq;
} uart_conf_t;

typedef struct {
    uint8_t         rx_trigger_byte_ptr;    ///< pointer to the byte that triggers the RX state machine
    uint8_t         rx_trigger_byte_saved;  ///< saved value of the byte that triggered the RX state machine (because the ptr tends to get overwritten)
    uint8_t         rx_buffer[256];         ///< the buffer where received bytes on UART are stored
    uart_rx_cb_t    callback;               ///< pointer to the callback function
    uint8_t        *tx_buffer;              ///< current TX buffer
    size_t          tx_length;              ///< total bytes to transmit
    size_t          tx_pos;                 ///< current position in TX buffer
    bool            tx_busy;                ///< flag indicating TX is in progress
    uart_rx_state_t rx_state;               ///< current state of the RX state machine
} uart_vars_t;

//=========================== variables ========================================

static const uart_conf_t _devs[UARTE_COUNT] = {
#if defined(NRF5340_XXAA) && defined(NRF_APPLICATION)
    {
#if defined(NRF_TRUSTZONE_NONSECURE)
        .p = NRF_UARTE0_NS,
#else
        .p = NRF_UARTE0_S,
#endif
        .irq = SERIAL0_IRQn,
    },
    {
#if defined(NRF_TRUSTZONE_NONSECURE)
        .p = NRF_UARTE1_NS,
#else
        .p = NRF_UARTE1_S,
#endif
        .irq = SERIAL1_IRQn,
    },
    {
#if defined(NRF_TRUSTZONE_NONSECURE)
        .p = NRF_UARTE2_NS,
#else
        .p = NRF_UARTE2_S,
#endif
        .irq = SERIAL2_IRQn,
    },
    {
#if defined(NRF_TRUSTZONE_NONSECURE)
        .p = NRF_UARTE3_NS,
#else
        .p = NRF_UARTE3_S,
#endif
        .irq = SERIAL3_IRQn,
    },
#elif defined(NRF5340_XXAA) && defined(NRF_NETWORK)
    {
        .p   = NRF_UARTE0_NS,
        .irq = SERIAL0_IRQn,
    },
#else
    {
        .p   = NRF_UARTE0,
        .irq = UARTE0_UART0_IRQn,
    },
    {
        .p   = NRF_UARTE1,
        .irq = UARTE1_IRQn,
    },
#endif
};

static uart_vars_t _uart_vars[UARTE_COUNT] = { 0 };  ///< variable handling the UART context
static uart_t      _uart_global_index      = 0;      ///< needed for the timer interrupt handler

//=========================== prototypes =======================================

void mr_uart_start_rx(uart_t uart, uart_rx_state_t state);

//=========================== public ===========================================

void mr_uart_init(uart_t uart, const mr_gpio_t *rx_pin, const mr_gpio_t *tx_pin, uint32_t baudrate, uart_rx_cb_t callback) {
    _uart_global_index = uart;

#if defined(NRF5340_XXAA)
    if (baudrate > 460800) {
        // On nrf53 configure constant latency mode for better performances with high baudrates
        NRF_POWER->TASKS_CONSTLAT = 1;
    }
#endif

    // configure UART pins (RX as input, TX as output);
    mr_gpio_init(rx_pin, MR_GPIO_IN_PU);
    mr_gpio_init(tx_pin, MR_GPIO_OUT);

    // configure UART
    _devs[uart].p->CONFIG   = 0;
    _devs[uart].p->PSEL.RXD = (rx_pin->port << UARTE_PSEL_RXD_PORT_Pos) |
                              (rx_pin->pin << UARTE_PSEL_RXD_PIN_Pos) |
                              (UARTE_PSEL_RXD_CONNECT_Connected << UARTE_PSEL_RXD_CONNECT_Pos);
    _devs[uart].p->PSEL.TXD = (tx_pin->port << UARTE_PSEL_TXD_PORT_Pos) |
                              (tx_pin->pin << UARTE_PSEL_TXD_PIN_Pos) |
                              (UARTE_PSEL_TXD_CONNECT_Connected << UARTE_PSEL_TXD_CONNECT_Pos);
    _devs[uart].p->PSEL.RTS = 0xffffffff;  // pin disconnected
    _devs[uart].p->PSEL.CTS = 0xffffffff;  // pin disconnected

    // configure baudrate
    switch (baudrate) {
        case 1200:
            _devs[uart].p->BAUDRATE = (UARTE_BAUDRATE_BAUDRATE_Baud1200 << UARTE_BAUDRATE_BAUDRATE_Pos);
            break;
        case 9600:
            _devs[uart].p->BAUDRATE = (UARTE_BAUDRATE_BAUDRATE_Baud9600 << UARTE_BAUDRATE_BAUDRATE_Pos);
            break;
        case 14400:
            _devs[uart].p->BAUDRATE = (UARTE_BAUDRATE_BAUDRATE_Baud14400 << UARTE_BAUDRATE_BAUDRATE_Pos);
            break;
        case 19200:
            _devs[uart].p->BAUDRATE = (UARTE_BAUDRATE_BAUDRATE_Baud19200 << UARTE_BAUDRATE_BAUDRATE_Pos);
            break;
        case 28800:
            _devs[uart].p->BAUDRATE = (UARTE_BAUDRATE_BAUDRATE_Baud28800 << UARTE_BAUDRATE_BAUDRATE_Pos);
            break;
        case 31250:
            _devs[uart].p->BAUDRATE = (UARTE_BAUDRATE_BAUDRATE_Baud31250 << UARTE_BAUDRATE_BAUDRATE_Pos);
            break;
        case 38400:
            _devs[uart].p->BAUDRATE = (UARTE_BAUDRATE_BAUDRATE_Baud38400 << UARTE_BAUDRATE_BAUDRATE_Pos);
            break;
        case 56000:
            _devs[uart].p->BAUDRATE = (UARTE_BAUDRATE_BAUDRATE_Baud56000 << UARTE_BAUDRATE_BAUDRATE_Pos);
            break;
        case 57600:
            _devs[uart].p->BAUDRATE = (UARTE_BAUDRATE_BAUDRATE_Baud57600 << UARTE_BAUDRATE_BAUDRATE_Pos);
            break;
        case 76800:
            _devs[uart].p->BAUDRATE = (UARTE_BAUDRATE_BAUDRATE_Baud76800 << UARTE_BAUDRATE_BAUDRATE_Pos);
            break;
        case 115200:
            _devs[uart].p->BAUDRATE = (UARTE_BAUDRATE_BAUDRATE_Baud115200 << UARTE_BAUDRATE_BAUDRATE_Pos);
            break;
        case 230400:
            _devs[uart].p->BAUDRATE = (UARTE_BAUDRATE_BAUDRATE_Baud230400 << UARTE_BAUDRATE_BAUDRATE_Pos);
            break;
        case 250000:
            _devs[uart].p->BAUDRATE = (UARTE_BAUDRATE_BAUDRATE_Baud250000 << UARTE_BAUDRATE_BAUDRATE_Pos);
            break;
        case 460800:
            _devs[uart].p->BAUDRATE = (UARTE_BAUDRATE_BAUDRATE_Baud460800 << UARTE_BAUDRATE_BAUDRATE_Pos);
            break;
        case 921600:
            _devs[uart].p->BAUDRATE = (UARTE_BAUDRATE_BAUDRATE_Baud921600 << UARTE_BAUDRATE_BAUDRATE_Pos);
            break;
        case 1000000:
            _devs[uart].p->BAUDRATE = (UARTE_BAUDRATE_BAUDRATE_Baud1M << UARTE_BAUDRATE_BAUDRATE_Pos);
            break;
        default:
            // error, return without enabling UART
            return;
    }

    _devs[uart].p->ENABLE = (UARTE_ENABLE_ENABLE_Enabled << UARTE_ENABLE_ENABLE_Pos);

    if (callback) {
        // configure the UART for RX

        _uart_vars[uart].callback = callback;

        // setup the RX interrupt
        _devs[uart].p->INTENSET = (UARTE_INTENSET_ENDRX_Enabled << UARTE_INTENSET_ENDRX_Pos);

        // setup the RX state machine and start receiving
        mr_uart_start_rx(uart, UART_RX_STATE_RX_TRIGGER_BYTE);

        NVIC_EnableIRQ(_devs[uart].irq);
        NVIC_SetPriority(_devs[uart].irq, MR_UART_IRQ_PRIORITY);
        NVIC_ClearPendingIRQ(_devs[uart].irq);

        // configure the timer for RX
        NRF_UART_TIMER->TASKS_CLEAR = 1;
        NRF_UART_TIMER->PRESCALER   = 4;  // Run TIMER at 1MHz
        NRF_UART_TIMER->BITMODE     = (TIMER_BITMODE_BITMODE_32Bit << TIMER_BITMODE_BITMODE_Pos);
        NRF_UART_TIMER->INTENSET    = (1 << (TIMER_INTENSET_COMPARE0_Pos + TIMER_CC_NUM - 1));
        NVIC_SetPriority(TIMER_IRQ, 2);
        NVIC_EnableIRQ(TIMER_IRQ);
    }
}

void mr_uart_write(uart_t uart, uint8_t *buffer, size_t length) {
    // Don't start new TX if one is already in progress
    if (_uart_vars[uart].tx_busy) {
        return;
    }

    // Store TX state
    _uart_vars[uart].tx_buffer = buffer;
    _uart_vars[uart].tx_length = length;
    _uart_vars[uart].tx_pos    = 0;
    _uart_vars[uart].tx_busy   = true;

    // Enable TX interrupt
    _devs[uart].p->INTENSET |= (UARTE_INTENSET_ENDTX_Enabled << UARTE_INTENSET_ENDTX_Pos);

    // Start first chunk
    _devs[uart].p->EVENTS_ENDTX  = 0;
    _devs[uart].p->TXD.PTR       = (uint32_t)&buffer[0];
    size_t chunk_size            = (length > MR_UARTE_CHUNK_SIZE) ? MR_UARTE_CHUNK_SIZE : length;
    _devs[uart].p->TXD.MAXCNT    = chunk_size;
    _devs[uart].p->TASKS_STARTTX = 1;
}

bool mr_uart_tx_busy(uart_t uart) {
    return _uart_vars[uart].tx_busy;
}

void mr_uart_start_rx(uart_t uart, uart_rx_state_t state) {
    _uart_vars[uart].rx_state = state;
    if (state == UART_RX_STATE_RX_TRIGGER_BYTE) {
        _devs[uart].p->RXD.MAXCNT = 1;  // receive the trigger byte
        _devs[uart].p->RXD.PTR    = (uint32_t)&_uart_vars[uart].rx_trigger_byte_ptr;
    } else if (state == UART_RX_STATE_RX_CHUNK) {
        _devs[uart].p->RXD.MAXCNT = 63;  // receive the rest of the chunk
                                         // start receiving from the second byte to leave room for the trigger byte
        _devs[uart].p->RXD.PTR = (uint32_t)&_uart_vars[uart].rx_buffer[1];
    }
    _devs[uart].p->TASKS_STARTRX = 1;  // start receiving
}

//=========================== interrupts =======================================

#include "mr_gpio.h"
extern mr_gpio_t pin_dbg_uart, pin_dbg_timer;
static void      _uart_isr(uart_t uart) {

    // check if the interrupt was caused by a fully received package
    if (_devs[uart].p->EVENTS_ENDRX) {
        _devs[uart].p->EVENTS_ENDRX = 0;
        // make sure we actually received new data
        if (_devs[uart].p->RXD.AMOUNT != 0) {
            if (_uart_vars[uart].rx_state == UART_RX_STATE_RX_TRIGGER_BYTE && _devs[uart].p->RXD.AMOUNT == 1) {
                // save the trigger byte
                _uart_vars[uart].rx_trigger_byte_saved = _uart_vars[uart].rx_trigger_byte_ptr;
                // we received the trigger byte, can start receiving the chunk
                mr_uart_start_rx(uart, UART_RX_STATE_RX_CHUNK);
                // arm timer in case the chunk is not filled in time
                NRF_UART_TIMER->TASKS_CLEAR          = 1;
                NRF_UART_TIMER->CC[TIMER_CC_NUM - 1] = 2000;  // for 1000000 baudrate and chunk size 63
                // NRF_UART_TIMER->CC[TIMER_CC_NUM - 1] = 2000;  // for 460800 baudrate
                NRF_UART_TIMER->TASKS_START = 1;
            } else if (_uart_vars[uart].rx_state == UART_RX_STATE_RX_CHUNK) {
                // stop the timer
                NRF_UART_TIMER->TASKS_STOP = 1;

                // process the received buffer
                size_t rx_length              = _devs[uart].p->RXD.AMOUNT + 1;           // +1 for the trigger byte
                _uart_vars[uart].rx_buffer[0] = _uart_vars[uart].rx_trigger_byte_saved;  // put the trigger byte at the beginning of the buffer
                _uart_vars[uart].callback(_uart_vars[uart].rx_buffer, rx_length);

                // // all done, go back to receiving the trigger byte
                // mr_uart_start_rx(uart, UART_RX_STATE_RX_TRIGGER_BYTE);

                _uart_vars[uart].rx_state = UART_RX_STATE_BACKOFF_TRIGGER_BYTE;

                // arm timer to start receiving the trigger byte
                NRF_UART_TIMER->TASKS_CLEAR          = 1;
                NRF_UART_TIMER->CC[TIMER_CC_NUM - 1] = 300;  // us
                NRF_UART_TIMER->TASKS_START          = 1;
            } else {
                // something went wrong, go back to receiving the trigger byte
                mr_uart_start_rx(uart, UART_RX_STATE_RX_TRIGGER_BYTE);
            }
        } else {
            // nothing received, go back to receiving the trigger byte
            mr_uart_start_rx(uart, UART_RX_STATE_RX_TRIGGER_BYTE);
        }
    }

    // check if the interrupt was caused by TX completion
    if (_devs[uart].p->EVENTS_ENDTX) {
        _devs[uart].p->EVENTS_ENDTX = 0;

        // Update position
        _uart_vars[uart].tx_pos += MR_UARTE_CHUNK_SIZE;

        // Check if more chunks need to be sent
        if (_uart_vars[uart].tx_pos < _uart_vars[uart].tx_length) {
            // Send next chunk
            size_t remaining  = _uart_vars[uart].tx_length - _uart_vars[uart].tx_pos;
            size_t chunk_size = (remaining > MR_UARTE_CHUNK_SIZE) ? MR_UARTE_CHUNK_SIZE : remaining;

            _devs[uart].p->TXD.PTR       = (uint32_t)&_uart_vars[uart].tx_buffer[_uart_vars[uart].tx_pos];
            _devs[uart].p->TXD.MAXCNT    = chunk_size;
            _devs[uart].p->TASKS_STARTTX = 1;
        } else {
            // TX complete
            _uart_vars[uart].tx_busy = false;
            // Disable TX interrupt
            _devs[uart].p->INTENCLR = (UARTE_INTENCLR_ENDTX_Clear << UARTE_INTENCLR_ENDTX_Pos);
        }
    }
};

#if defined(NRF5340_XXAA)
void SERIAL0_IRQHandler(void) {
    _uart_isr(0);
}

#if defined(NRF5340_XXAA_APPLICATION)
void SERIAL1_IRQHandler(void) {
    _uart_isr(1);
}

void SERIAL2_IRQHandler(void) {
    _uart_isr(2);
}

void SERIAL3_IRQHandler(void) {
    _uart_isr(3);
}
#endif  // NRF5340_XXAA_APPLICATION

#else  // NRF5340_XXAA
void UARTE0_UART0_IRQHandler(void) {
    _uart_isr(0);
}

void UARTE1_IRQHandler(void) {
    _uart_isr(1);
}
#endif

#if defined(NRF5340_XXAA)
void TIMER2_IRQHandler(void) {
#else
void TIMER4_IRQHandler(void) {
#endif
    if (NRF_UART_TIMER->EVENTS_COMPARE[TIMER_CC_NUM - 1]) {
        NRF_UART_TIMER->EVENTS_COMPARE[TIMER_CC_NUM - 1] = 0;
        NRF_UART_TIMER->TASKS_STOP                       = 1;

        if (_uart_vars[_uart_global_index].rx_state == UART_RX_STATE_RX_CHUNK) {
            // tell the uart to stop receiving -> this will cause an ENDRX interrupt
            _devs[_uart_global_index].p->TASKS_STOPRX = 1;
        } else if (_uart_vars[_uart_global_index].rx_state == UART_RX_STATE_BACKOFF_TRIGGER_BYTE) {
            // tell the uart to start receiving the trigger byte
            mr_uart_start_rx(_uart_global_index, UART_RX_STATE_RX_TRIGGER_BYTE);
        }
    }
}
