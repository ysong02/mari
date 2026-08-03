#ifndef __MR_RADIO_H
#define __MR_RADIO_H

/**
 * @defgroup    bsp_radio   Radio support
 * @ingroup     bsp
 * @brief       Control the radio peripheral
 *
 * This radio driver supports BLE 1Mbit, 2Mbit, Long Range 125Kbit, Long Range 500Kbit
 * and IEEE 802.15.4 250Kbit
 *
 * @{
 * @file
 * @author Said Alvarado-Marin <said-alexander.alvarado-marin@inria.fr>
 * @author Alexandre Abadie <alexandre.abadie@inria.fr>
 * @author Diego Badillo-San-Juan <diego.badillo-san-juan@inria.fr>
 *
 * @copyright Inria, 2022-2024
 * @}
 */

#include <stdint.h>
#include <stdbool.h>
#include <nrf.h>

//=========================== defines ==========================================

#ifndef DEFAULT_NETWORK_ADDRESS
#define DEFAULT_NETWORK_ADDRESS 0x12345678UL  ///< Default network address
#endif

#define MR_BLE_PAYLOAD_MAX_LENGTH        UINT8_MAX
#define MR_IEEE802154_PAYLOAD_MAX_LENGTH (125UL)  ///< Total usable payload for IEEE 802.15.4 is 125 octets (PSDU) when CRC is activated

/// Modes supported by the radio
typedef enum {
    MR_RADIO_BLE_1MBit,
    MR_RADIO_BLE_2MBit,
    MR_RADIO_BLE_LR125Kbit,
    MR_RADIO_BLE_LR500Kbit,
    MR_RADIO_IEEE802154_250Kbit
} mr_radio_mode_t;

typedef void (*mr_radio_cb_t)(uint8_t *packet, uint8_t length);  ///< get the received packet
typedef void (*radio_ts_packet_t)(uint32_t ts);                  ///< capture timestamp for start/end of packet

//=========================== public ===========================================

/**
 * @brief Initializes the RADIO peripheral
 *
 * After this function you must explicitly set the frequency of the radio
 * with the mr_radio_set_frequency function.
 *
 * @param[in] rx_cb pointer to a function that will be called each time a packet is received.
 * @param[in] mode     Mode used by the radio BLE (1MBit, 2MBit, LR125KBit, LR500Kbit) or IEEE 802.15.4 (250Kbit)
 *
 */
void mr_radio_init(radio_ts_packet_t start_pac_cb, radio_ts_packet_t end_pac_cb, mr_radio_mode_t mode);

/**
 * @brief Set the tx-rx frequency of the radio, by the following formula
 *
 * Radio frequency 2400 + freq (MHz) [0, 100]
 *
 * @param[in] freq Frequency of the radio [0, 100]
 */
void mr_radio_set_frequency(uint8_t freq);

/**
 * @brief Set the physical channel used of the radio
 *
 * BLE channels [0-39] (37-39 are advertising); IEEE 802.15.4 channels [11-26] (2405-2480 MHz).
 *
 * @param[in] channel   Channel used by the radio
 */
void mr_radio_set_channel(uint8_t channel);

/**
 * @brief Set the network address used to send/receive radio packets
 *
 * @param[in] addr Network address
 */
void mr_radio_set_network_address(uint32_t addr);

/**
 * @brief Sends a single packet through the Radio
 *
 * NOTE: call mr_radio_init/mr_radio_set_frequency first, and mr_radio_disable first if currently receiving.
 *
 * @param[in] packet pointer to the array of data to send over the radio (max size = 32)
 * @param[in] length Number of bytes to send (max size = 32)
 *
 */
void mr_radio_tx(const uint8_t *packet, uint8_t length);

/**
 * @brief Starts Receiving packets through the Radio
 *
 * NOTE: call mr_radio_init/mr_radio_set_frequency first.
 *
 */
void mr_radio_rx(void);

/**
 * @brief Reads the RSSI of a received packet
 *
 * Should be called after a packet is received, e.g. in the radio callback
 */
int8_t mr_radio_rssi(void);

/**
 * @brief Disables the radio, no packet can be received and energy consumption is minimal
 */
void mr_radio_disable(void);

bool mr_radio_pending_rx_read(void);
void mr_radio_get_rx_packet(uint8_t *packet, uint8_t *length);

void mr_radio_tx_prepare(const uint8_t *tx_buffer, uint8_t length);
void mr_radio_tx_dispatch(void);

/// Number of RX completions that failed the CRC check. Safe to call from the main loop.
uint32_t mr_radio_get_crc_error_count(void);

#endif  // __MR_RADIO_H
