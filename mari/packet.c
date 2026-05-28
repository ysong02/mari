/**
 * @brief       Build a mari packets
 *
 * @author Geovane Fedrecheski <geovane.fedrecheski@inria.fr>
 *
 * @copyright Inria, 2024
 */
#include <stdint.h>
#include <string.h>

#include "mr_device.h"
#include "scheduler.h"
#include "association.h"
#include "packet.h"
#include "mac.h"
#include "mari.h"

//=========================== prototypes =======================================

static size_t _set_header(uint8_t *buffer, uint64_t dst, mr_packet_type_t packet_type);

//=========================== public ===========================================

size_t mr_build_packet_data(uint8_t *buffer, uint64_t dst, uint8_t *data, size_t data_len) {
    size_t header_len = _set_header(buffer, dst, MARI_PACKET_DATA);
    memcpy(buffer + header_len, data, data_len);
    return header_len + data_len;
}

size_t mr_build_packet_keepalive(uint8_t *buffer, uint64_t dst) {
    return _set_header(buffer, dst, MARI_PACKET_KEEPALIVE);
}

size_t mr_build_packet_join_request(uint8_t *buffer, uint64_t dst) {
    return _set_header(buffer, dst, MARI_PACKET_JOIN_REQUEST);
}

size_t mr_build_packet_join_response(uint8_t *buffer, uint64_t dst) {
    return _set_header(buffer, dst, MARI_PACKET_JOIN_RESPONSE);
}

size_t mr_build_packet_beacon(uint8_t *buffer, uint16_t net_id, uint64_t asn, uint8_t remaining_capacity, uint8_t active_schedule_id) {
    mr_beacon_packet_header_t beacon = {
        .version            = MARI_PROTOCOL_VERSION,
        .type               = MARI_PACKET_BEACON,
        .network_id         = net_id,
        .asn                = asn,
        .src                = mr_device_id(),
        .remaining_capacity = remaining_capacity,
        .active_schedule_id = active_schedule_id,
    };
    // add bloom filter
    mr_bloom_gateway_copy(beacon.bloom_filter);
    memcpy(buffer, &beacon, sizeof(mr_beacon_packet_header_t));
    return sizeof(mr_beacon_packet_header_t);
}

size_t mr_build_uart_packet_gateway_info(uint8_t *buffer) {
    mr_uart_packet_gateway_info_t gateway_info = {
        .device_id   = mr_device_id(),
        .net_id      = mr_assoc_get_network_id(),
        .schedule_id = mr_scheduler_get_active_schedule_id(),
        .asn         = mr_mac_get_asn(),
    };
    memcpy(gateway_info.sched_usage, mr_scheduler_get_schedule_usage(), sizeof(uint64_t) * MARI_STATS_SCHED_USAGE_SIZE);
    memcpy(buffer, &gateway_info, sizeof(mr_uart_packet_gateway_info_t));
    return sizeof(mr_uart_packet_gateway_info_t);
}


//=========================== private ==========================================

static size_t _set_header(uint8_t *buffer, uint64_t dst, mr_packet_type_t packet_type) {
    uint64_t src = mr_device_id();

    mr_packet_header_t header = {
        .version    = MARI_PROTOCOL_VERSION,
        .type       = packet_type,
        .network_id = mr_assoc_get_network_id(),
        .dst        = dst,
        .src        = src,
    };
    memcpy(buffer, &header, sizeof(mr_packet_header_t));
    return sizeof(mr_packet_header_t);
}
