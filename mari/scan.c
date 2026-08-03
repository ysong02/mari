/**
 * @file
 * @ingroup     mari
 *
 * @brief       Scan list management
 *
 * @author Geovane Fedrecheski <geovane.fedrecheski@inria.fr>
 *
 * @copyright Inria, 2024
 */

#include <nrf.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "scan.h"

//=========================== variables =======================================

typedef struct {
    mr_gateway_scan_t scans[MARI_MAX_SCAN_LIST_SIZE];
} scan_vars_t;

scan_vars_t scan_vars = { 0 };

//=========================== prototypes ======================================

void              _save_rssi(size_t idx, mr_beacon_packet_header_t beacon, int8_t rssi, uint8_t channel, uint32_t ts_scan, uint64_t asn_scan);
uint32_t          _get_ts_latest(mr_gateway_scan_t scan);
mr_channel_info_t _get_channel_info_latest(mr_gateway_scan_t scan);
bool              _scan_is_too_old(mr_gateway_scan_t scan, uint32_t ts_scan);

//=========================== public ===========================================

// Update this gateway's rssi if already scanned; else take an empty spot, or overwrite the oldest reading.
void mr_scan_add(mr_beacon_packet_header_t beacon, int8_t rssi, uint8_t channel, uint32_t ts_scan, uint64_t asn_scan) {
    uint64_t gateway_id        = beacon.src;
    bool     found             = false;
    int16_t  empty_spot_idx    = -1;
    uint32_t ts_oldest_all     = ts_scan;
    uint32_t ts_oldest_all_idx = 0;
    for (size_t i = 0; i < MARI_MAX_SCAN_LIST_SIZE; i++) {
        // if found this gateway_id, update its respective rssi entry and mark as found.
        if (scan_vars.scans[i].gateway_id == gateway_id) {
            _save_rssi(i, beacon, rssi, channel, ts_scan, asn_scan);
            found = true;
            continue;
        }

        // try and save the first empty spot we see
        // if gateway_id == 0, there is an empty spot here, save the index (will only do this once)
        if (scan_vars.scans[i].gateway_id == 0 && empty_spot_idx < 0) {
            empty_spot_idx = i;
        }

        uint32_t ts_cmp = _get_ts_latest(scan_vars.scans[i]);
        if (scan_vars.scans[i].gateway_id != 0 && ts_cmp < ts_oldest_all) {
            ts_oldest_all     = ts_cmp;
            ts_oldest_all_idx = i;
        }
    }
    if (found) {
        // if found a matching gateway_id, nothing else to do
        return;
    } else {
        // if not, find an optimal spot for saving this new rssi reading
        //   either save it onto an empty spot, or override the oldest one
        if (empty_spot_idx >= 0) {  // there is an empty spot
            scan_vars.scans[empty_spot_idx].gateway_id = gateway_id;
            _save_rssi(empty_spot_idx, beacon, rssi, channel, ts_scan, asn_scan);
        } else {
            // no match and no empty slot: overwrite the oldest reading
            memset(&scan_vars.scans[ts_oldest_all_idx], 0, sizeof(mr_gateway_scan_t));
            scan_vars.scans[ts_oldest_all_idx].gateway_id = gateway_id;
            _save_rssi(ts_oldest_all_idx, beacon, rssi, channel, ts_scan, asn_scan);
        }
    }
}

// Return the gateway with the highest average rssi (full-capacity gateways are never added to the scan list).
bool mr_scan_select(mr_channel_info_t *best_channel_info, uint32_t ts_scan_started, uint32_t ts_scan_ended) {
    int8_t best_gateway_idx = -1;
    // make sure best_channel_info is zeroed out
    memset(best_channel_info, 0, sizeof(mr_channel_info_t));
    int8_t best_gateway_rssi = INT8_MIN;
    for (size_t i = 0; i < MARI_MAX_SCAN_LIST_SIZE; i++) {
        if (scan_vars.scans[i].gateway_id == 0) {
            continue;
        }
        // compute average rssi, only including the rssi readings that are not too old
        int8_t avg_rssi = 0;
        int8_t n_rssi   = 0;
        for (size_t j = 0; j < MARI_N_BLE_ADVERTISING_CHANNELS; j++) {
            if (scan_vars.scans[i].channel_info[j].timestamp == 0) {  // no scan info reading here
                continue;
            }
            // check twice for old scans: scans from before this scan started, and scans older than the mari configuration
            if (scan_vars.scans[i].channel_info[j].timestamp < ts_scan_started) {  // scan info is too old
                continue;
            }
            if (ts_scan_ended - scan_vars.scans[i].channel_info[j].timestamp > MARI_SCAN_OLD_US) {  // scan info is is too old
                continue;
            }
            avg_rssi += scan_vars.scans[i].channel_info[j].rssi;
            n_rssi++;
        }
        if (n_rssi == 0) {
            continue;
        }
        avg_rssi /= n_rssi;
        if (avg_rssi > best_gateway_rssi) {
            best_gateway_rssi = avg_rssi;
            best_gateway_idx  = i;
        }
    }
    if (best_gateway_idx < 0) {
        return false;
    }
    *best_channel_info = _get_channel_info_latest(scan_vars.scans[best_gateway_idx]);
    // TODO: should probably report the average rssi: best_channel_info->rssi = best_gateway_rssi;
    return true;
}

//=========================== private ==========================================

inline void _save_rssi(size_t idx, mr_beacon_packet_header_t beacon, int8_t rssi, uint8_t channel, uint32_t ts_scan, uint64_t asn_scan) {
    size_t channel_idx = channel % MARI_N_BLE_REGULAR_CHANNELS;
    // copy beacon without bloom filter to reduce memory consumption during scan
    mr_beacon_scan_header_t scan_beacon = {
        .version            = beacon.version,
        .type               = beacon.type,
        .network_id         = beacon.network_id,
        .asn                = beacon.asn,
        .src                = beacon.src,
        .remaining_capacity = beacon.remaining_capacity,
        .active_schedule_id = beacon.active_schedule_id
    };

    scan_vars.scans[idx].channel_info[channel_idx].rssi         = rssi;
    scan_vars.scans[idx].channel_info[channel_idx].timestamp    = ts_scan;
    scan_vars.scans[idx].channel_info[channel_idx].captured_asn = asn_scan;
    scan_vars.scans[idx].channel_info[channel_idx].beacon       = scan_beacon;
}

inline bool _scan_is_too_old(mr_gateway_scan_t scan, uint32_t ts_scan) {
    uint32_t ts_latest = _get_ts_latest(scan);
    return (ts_scan - ts_latest) > MARI_SCAN_OLD_US;
}

inline uint32_t _get_ts_latest(mr_gateway_scan_t scan) {
    mr_channel_info_t latest = _get_channel_info_latest(scan);
    return latest.timestamp;
}

// get the latest channel_info for a given scan (could be any of them, but the latest will have minimum drift)
inline mr_channel_info_t _get_channel_info_latest(mr_gateway_scan_t scan) {
    uint32_t latest_idx = 0;
    for (size_t i = 0; i < MARI_N_BLE_ADVERTISING_CHANNELS; i++) {
        if (scan.channel_info[i].timestamp > scan.channel_info[latest_idx].timestamp) {
            latest_idx = i;
        }
    }
    return scan.channel_info[latest_idx];
}
