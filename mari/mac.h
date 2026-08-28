#ifndef __MAC_H
#define __MAC_H

/**
 * @defgroup    net_mac      MAC-low radio driver
 * @ingroup     drv
 * @brief       MAC Driver for Mari
 *
 * @{
 * @file
 * @author Geovane Fedrecheski <geovane.fedrecheski@inria.fr>
 * @copyright Inria, 2024-now
 * @}
 */

#include <stdint.h>
#include <nrf.h>

#include "models.h"

//=========================== defines ==========================================

#define MARI_TIMER_DEV                2  ///< HF timer device used for the TSCH scheduler
#define MARI_TIMER_INTER_SLOT_CHANNEL 0  ///< Channel for ticking the whole slot
#define MARI_TIMER_CHANNEL_1          1  ///< Channel for ticking intra-slot sections
#define MARI_TIMER_CHANNEL_2          2  ///< Channel for ticking intra-slot sections
#define MARI_TIMER_CHANNEL_3          3  ///< Channel for ticking the desynchronization window

// Bytes per millisecond in BLE 2M mode
#define MARI_BLE_PAYLOAD_MAX_LENGTH UINT8_MAX
#define BLE_2M                      (1000 * 1000 * 2)     // 2 Mbps
#define BLE_2M_B_MS                 (BLE_2M / 8 / 1000)   // 250 bytes/ms
#define BLE_2M_US_PER_BYTE          (1000 / BLE_2M_B_MS)  // 4 us

// Intra-slot durations, with TOA definitions assuming BLE 2M mode.
#define MARI_TS_TX_OFFSET            (400)                                               // time for radio setup before TX
#define MARI_RX_GUARD_TIME           (140)                                               // time range relative to MARI_TS_TX_OFFSET for the receiver to start RXing
#define MARI_END_GUARD_TIME          (MARI_RX_GUARD_TIME + 100)                          // Added 40 us based on measurements witn nRF52 and nRF53
#define MARI_PACKET_TOA              (BLE_2M_US_PER_BYTE * MARI_BLE_PAYLOAD_MAX_LENGTH)  // Time on air for the maximum payload.
#define MARI_PACKET_TOA_WITH_PADDING (MARI_PACKET_TOA + 120)                             // Padding from experiments, incl. ~28us until the ADDRESS event fires

// Duration of some packets
#define MARI_BEACON_TOA              (BLE_2M_US_PER_BYTE * sizeof(mr_beacon_packet_header_t))  // Time on air for the beacon packet
#define MARI_BEACON_TOA_WITH_PADDING (MARI_BEACON_TOA + 60)                                    // Add padding based on experiments.

#define MARI_WHOLE_SLOT_DURATION (MARI_TS_TX_OFFSET + MARI_PACKET_TOA_WITH_PADDING + MARI_END_GUARD_TIME)  // Complete slot duration

#define MARI_MAX_TIME_NO_RX_DESYNC (MARI_WHOLE_SLOT_DURATION * MARI_SCAN_MAX_SLOTS)  // us, arbitrary value for now

// default scan duration in us
#define MARI_SCAN_MAX_SLOTS    (MARI_N_CELLS_MAX)                                // how many slots to scan for. should probably be the size of the largest schedule
#define MARI_SCAN_MAX_DURATION (MARI_SCAN_MAX_SLOTS * MARI_WHOLE_SLOT_DURATION)  // how many slots to scan for. should probably be the size of the largest schedule

#define MARI_BG_SCAN_DURATION (MARI_WHOLE_SLOT_DURATION - (MARI_END_GUARD_TIME * 2))

// Must exceed mari_edge's connect-reply round trip (MQTT hop to the verifier).
#define MARI_MAX_SLOTFRAMES_NO_RX_LEAVE (50)

/* Duration of intra-slot sections */
typedef struct {
    // transmitter
    uint32_t tx_offset;  ///< Offset for the transmitter to start transmitting.
    uint32_t tx_max;     ///< Maximum time the transmitter can be active.

    // receiver
    uint32_t rx_guard;   ///< Time range relative to tx_offset for the receiver to start RXing.
    uint32_t rx_offset;  ///< Offset for the receiver to start receiving.
    uint32_t rx_max;     ///< Maximum time the receiver can be active.

    // common
    uint32_t end_guard;   ///< Time after the slot for the radio to fully turn off; must be at least rx_guard.
    uint32_t whole_slot;  ///< Total duration of the slot
} mr_slot_durations_t;

//=========================== variables ========================================

extern mr_slot_durations_t slot_durations;

//=========================== prototypes ==========================================

void     mr_mac_init(mr_event_cb_t event_callback);
uint64_t mr_mac_get_synced_ts(void);
uint64_t mr_mac_get_synced_gateway(void);
uint16_t mr_mac_get_synced_network_id(void);
uint64_t mr_mac_get_asn(void);
uint32_t mr_mac_get_tiner_value(void);
bool     mr_mac_node_is_synced(void);

#endif  // __MAC_H
