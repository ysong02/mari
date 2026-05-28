#ifndef __MODELS_H
#define __MODELS_H

/**
 * @defgroup    models      common models
 * @ingroup     mari
 * @brief       Common models used in the mari protocol
 *
 * @{
 * @file
 * @author Geovane Fedrecheski <geovane.fedrecheski@inria.fr>
 * @copyright Inria, 2024-now
 * @}
 */

#include <stdint.h>
#include <stdlib.h>
#include <nrf.h>
#include <stdbool.h>

#include "bloom.h"

//=========================== defines =========================================

#define MARI_N_BLE_REGULAR_CHANNELS     37
#define MARI_N_BLE_ADVERTISING_CHANNELS 3

// #ifndef MARI_FIXED_CHANNEL
#define MARI_FIXED_CHANNEL      0   // to hardcode the channel, use a valid value other than 0
#define MARI_FIXED_SCAN_CHANNEL 37  // to hardcode the channel, use a valid value other than 0
// #endif

#define MARI_N_CELLS_MAX 149

#define MARI_ENABLE_BACKGROUND_SCAN 1

#define MARI_PACKET_MAX_SIZE 255

#define MARI_STATS_SCHED_USAGE_SIZE 4  // supports schedules with up to 256 cells

#define MARI_EDHOC_PAYLOAD_TAG 0xED
#define MARI_EDHOC_MAX_MSG_LEN 150

//=========================== types ============================================

// -------- types sent over the air --------

typedef enum {
    MARI_PACKET_BEACON        = 1,
    MARI_PACKET_JOIN_REQUEST  = 2,
    MARI_PACKET_JOIN_RESPONSE = 4,
    MARI_PACKET_KEEPALIVE     = 8,
    MARI_PACKET_DATA          = 16,
} mr_packet_type_t;

typedef struct __attribute__((packed)) {
    int8_t rssi;
} mr_packet_statistics_t;

// general packet header
typedef struct __attribute__((packed)) {
    uint8_t                version;
    mr_packet_type_t       type;
    uint16_t               network_id;
    uint64_t               dst;
    uint64_t               src;
    mr_packet_statistics_t stats;
} mr_packet_header_t;

// beacon packet
typedef struct __attribute__((packed)) {
    uint8_t          version;
    mr_packet_type_t type;
    uint16_t         network_id;
    uint64_t         asn;
    uint64_t         src;
    uint8_t          remaining_capacity;
    uint8_t          active_schedule_id;
    uint8_t          bloom_filter[MARI_BLOOM_M_BYTES];
} mr_beacon_packet_header_t;

// -------- types used internally --------

typedef enum {
    MARI_GATEWAY = 'G',
    MARI_NODE    = 'D',
} mr_node_type_t;

typedef enum {
    MARI_NEW_PACKET = 1,
    MARI_CONNECTED,
    MARI_DISCONNECTED,
    MARI_NODE_JOINED,
    MARI_NODE_LEFT,
    MARI_KEEPALIVE,
    MARI_ERROR,
    MARI_ATTESTATION,
    MARI_EDHOC_MSG1,  ///< Node received EDHOC msg1 in beacon
    MARI_EDHOC_MSG2,  ///< Gateway received EDHOC msg2 in join request
    MARI_EDHOC_MSG3,  ///< Node received EDHOC msg3 in join response
} mr_event_t;

typedef enum {
    MARI_NONE              = 0,
    MARI_HANDOVER          = 1,
    MARI_OUT_OF_SYNC       = 2,
    MARI_PEER_LOST         = 3,  // deprecated
    MARI_GATEWAY_FULL      = 4,
    MARI_PEER_LOST_TIMEOUT = 5,
    MARI_PEER_LOST_BLOOM   = 6,
    MARI_HANDOVER_FAILED   = 7,
    // add attestation
    MARI_ATTESTATION_FAILED = 8,
} mr_event_tag_t;

typedef struct {
    uint8_t             len;
    mr_packet_header_t *header;
    uint8_t            *payload;
    uint8_t             payload_len;
} mari_packet_t;

typedef struct {
    union {
        mari_packet_t new_packet;
        struct {
            uint64_t node_id;
        } node_info;
        struct {
            uint64_t gateway_id;
        } gateway_info;
        struct {
            uint64_t node_id;
            uint8_t  data[MARI_EDHOC_MAX_MSG_LEN];
            uint8_t  len;
        } edhoc;
    } data;
    mr_event_tag_t tag;
} mr_event_data_t;

typedef enum {
    MARI_RADIO_ACTION_SLEEP = 'S',
    MARI_RADIO_ACTION_RX    = 'R',
    MARI_RADIO_ACTION_TX    = 'T',
} mr_radio_action_t;

typedef enum {
    SLOT_TYPE_BEACON        = 'B',
    SLOT_TYPE_SHARED_UPLINK = 'S',
    SLOT_TYPE_DOWNLINK      = 'D',
    SLOT_TYPE_UPLINK        = 'U',
} slot_type_t;

typedef struct {
    mr_radio_action_t radio_action;
    uint8_t           channel;
    slot_type_t       type;
} mr_slot_info_t;

typedef struct {
    slot_type_t type;
    uint8_t     channel_offset;
    uint64_t    assigned_node_id;
    uint64_t    last_received_asn;  ///< ASN marking the last time the node was heard from
    uint64_t    bloom_h1;           ///< H1 hash of the node ID, used to compute the bloom filter
    uint64_t    bloom_h2;           ///< H2 hash of the node ID, used to compute the bloom filter
    // for attestation
    bool     is_attesting;
    uint64_t attest_asn_dl;
} cell_t;

typedef struct {
    uint8_t id;                       // unique identifier for the schedule
    uint8_t max_nodes;                // maximum number of nodes that can be scheduled, equivalent to the number of uplink slot_durations
    uint8_t backoff_n_min;            // minimum exponent for the backoff algorithm
    uint8_t backoff_n_max;            // maximum exponent for the backoff algorithm
    size_t  n_cells;                  // number of cells in this schedule
    cell_t  cells[MARI_N_CELLS_MAX];  // cells in this schedule. NOTE(FIXME?): the first 3 cells must be beacons
} schedule_t;

typedef struct {
    uint8_t  channel;
    int8_t   rssi;
    uint32_t start_ts;
    uint32_t end_ts;
    uint64_t asn;
    bool     to_me;
    uint8_t  packet[MARI_PACKET_MAX_SIZE];
    uint8_t  packet_len;
} mr_received_packet_t;

// -------- types used for UART --------

typedef enum {
    MARI_EDGE_NODE_JOINED  = 1,
    MARI_EDGE_NODE_LEFT    = 2,
    MARI_EDGE_DATA         = 3,
    MARI_EDGE_KEEPALIVE    = 4,
    MARI_EDGE_GATEWAY_INFO = 5,
    MARI_EDGE_EDHOC        = 6,
} mr_gateway_edge_type_t;

typedef enum {
    MARI_EDHOC_SUBTYPE_MSG1 = 1,
    MARI_EDHOC_SUBTYPE_MSG2 = 2,
    MARI_EDHOC_SUBTYPE_MSG3 = 3,
    MARI_EDHOC_SUBTYPE_MSG4 = 4,
} mr_edhoc_subtype_t;

// uart packet for gateway info
typedef struct __attribute__((packed)) {
    uint64_t device_id;
    uint16_t net_id;
    uint16_t schedule_id;
    uint64_t sched_usage[MARI_STATS_SCHED_USAGE_SIZE];
    uint64_t asn;
    uint32_t timer;
} mr_uart_packet_gateway_info_t;

// -------- types used for metrics collection --------

typedef enum {
    MARI_PAYLOAD_TYPE_METRICS_PROBE = 0x9C,
} mr_metrics_payload_type_t;

typedef struct __attribute__((packed)) {
    mr_metrics_payload_type_t type;  ///< Payload type (1 byte)

    uint64_t cloud_tx_ts_us;        ///< Cloud transmit timestamp in microseconds (8 bytes)
    uint64_t cloud_rx_ts_us;        ///< Cloud receive timestamp in microseconds (8 bytes)
    uint32_t cloud_tx_count;        ///< Cloud transmit counter (4 bytes)
    uint32_t cloud_rx_count;        ///< Cloud receive counter (4 bytes)
    uint64_t edge_tx_ts_us;         ///< Edge transmit timestamp in microseconds (8 bytes)
    uint64_t edge_rx_ts_us;         ///< Edge receive timestamp in microseconds (8 bytes)
    uint32_t edge_tx_count;         ///< Edge transmit counter (4 bytes)
    uint32_t edge_rx_count;         ///< Edge receive counter (4 bytes)
    uint32_t gw_tx_count;           ///< Gateway transmit counter (4 bytes)
    uint32_t gw_rx_count;           ///< Gateway receive counter (4 bytes)
    uint64_t gw_rx_asn;             ///< Gateway receive ASN (8 bytes)
    uint64_t gw_tx_enqueued_asn;    ///< Gateway TX enqueued ASN (8 bytes)
    uint64_t gw_tx_dequeued_asn;    ///< Gateway TX dequeued ASN (8 bytes)
    uint32_t node_rx_count;         ///< Node receive counter (4 bytes)
    uint32_t node_tx_count;         ///< Node transmit counter (4 bytes)
    uint64_t node_rx_asn;           ///< Node receive ASN (8 bytes)
    uint64_t node_tx_enqueued_asn;  ///< Node TX enqueued ASN (8 bytes)
    uint64_t node_tx_dequeued_asn;  ///< Node TX dequeued ASN (8 bytes)
    int8_t   rssi_at_node;          ///< RSSI at node in dBm (1 byte, signed)
    int8_t   rssi_at_gw;            ///< RSSI at gateway in dBm (1 byte, signed)
} mr_metrics_payload_t;

//=========================== callbacks =======================================

typedef void (*mr_event_cb_t)(mr_event_t event, mr_event_data_t event_data);

#endif  // __MODELS_H
