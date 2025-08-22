/**
 * @file
 * @ingroup     mari
 *
 * @brief       Implementation of the mari protocol
 *
 * @author Geovane Fedrecheski <geovane.fedrecheski@inria.fr>
 *
 * @copyright Inria, 2025
 */

#include <nrf.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "mr_device.h"
#include "mr_rng.h"
#include "mr_timer_hf.h"
#include "models.h"
#include "packet.h"
#include "mac.h"
#include "scheduler.h"
#include "association.h"
#include "queue.h"
#include "bloom.h"
#include "mari.h"

#include "attestation.h"

//=========================== defines ==========================================

typedef struct {
    mr_node_type_t node_type;
    mr_event_cb_t  app_event_callback;
} mari_vars_t;

//=========================== variables ========================================

static mari_vars_t _mari_vars = { 0 };

//=========================== prototypes =======================================

static void event_callback(mr_event_t event, mr_event_data_t event_data);
static void mr_mari_force_gateway_startup_random_delay(void);

//=========================== public ===========================================
// in this library, user-facing functions begin with mari_*, while internal functions begin with mr_*

// -------- common --------

void mari_init(mr_node_type_t node_type, uint16_t net_id, schedule_t *app_schedule, mr_event_cb_t app_event_callback) {
    _mari_vars.node_type          = node_type;
    _mari_vars.app_event_callback = app_event_callback;

    // initialize drivers
    mr_timer_hf_init(MARI_TIMER_DEV);
    mr_rng_init();

    // initialize stateful mari modules
    mr_assoc_init(net_id, event_callback);
    mr_scheduler_init(app_schedule);
    if (node_type == MARI_GATEWAY) {
        mr_bloom_gateway_init();
    }

    if (node_type == MARI_GATEWAY) {
        mr_mari_force_gateway_startup_random_delay();
    }

    // kick off the MAC state machine
    mr_mac_init(event_callback);
}

void mari_tx(uint8_t *packet, uint8_t length) {
    mr_queue_add(packet, length);
}

mr_node_type_t mari_get_node_type(void) {
    return _mari_vars.node_type;
}

void mari_set_node_type(mr_node_type_t node_type) {
    _mari_vars.node_type = node_type;
}

// -------- gateway ----------

size_t mari_gateway_get_nodes(uint64_t *nodes) {
    return mr_scheduler_gateway_get_nodes(nodes);
}

size_t mari_gateway_count_nodes(void) {
    return mr_scheduler_gateway_get_nodes_count();
}

// -------- node ----------

void mari_node_tx_payload(uint8_t *payload, uint8_t payload_len) {
    uint8_t packet[MARI_PACKET_MAX_SIZE] = { 0 };
    uint8_t len                          = mr_build_packet_data(packet, mari_node_gateway_id(), payload, payload_len);
    mr_queue_add(packet, len);
}

bool mari_node_is_connected(void) {
    return mr_assoc_is_joined();
}

uint64_t mari_node_gateway_id(void) {
    return mr_mac_get_synced_gateway();
}

//=========================== iternal api =====================================

void mr_mari_force_gateway_startup_random_delay(void) {
    // in the gateway, defer the start of the MAC for a random time (between 0 and slotframe duration)
    // this is to avoid gateway-to-gateway mutual cancellation, in case all gateways start at the same time
    uint8_t rng_value;
    mr_rng_read_u8(&rng_value);
    // restrict random value to slotframe slot count
    uint8_t  random_slot_count = rng_value % mr_scheduler_get_active_schedule_slot_count();
    uint32_t delay_us          = random_slot_count * MARI_WHOLE_SLOT_DURATION;
    mr_timer_hf_delay_us(MARI_TIMER_DEV, delay_us);
}

bool mr_handle_packet(uint8_t *packet, uint8_t length) {
    mr_packet_header_t *header = (mr_packet_header_t *)packet;

    bool wrong_destination = header->dst != mr_device_id() && header->dst != MARI_BROADCAST_ADDRESS;
    bool not_a_beacon      = header->type != MARI_PACKET_BEACON;
    if (wrong_destination && not_a_beacon) {
        return false;
    }

    if (mari_get_node_type() == MARI_GATEWAY) {
        if (header->network_id != mr_assoc_get_network_id()) {
            // ignore packets from other networks
            return false;
        }

        bool from_joined_node = mr_assoc_gateway_node_is_joined(header->src);

        switch (header->type) {
            case MARI_PACKET_JOIN_REQUEST:
            {
                // try to assign a cell to the node
                // the asn-based keep-alive is also initialized
                // the hashes h1 and h2 are also set
                // NOTE: we accept re-joins because of possible collisions on the join response (downlink)
                int16_t cell_id = mr_scheduler_gateway_assign_next_available_uplink_cell(header->src, mr_mac_get_asn());
                if (cell_id >= 0) {
                    // at the packet level, max_nodes is limited to 256 (using uint8_t cell_id)
                    mr_queue_set_join_response(header->src, (uint8_t)cell_id, flag_attest);
                    // set the dirty flag that will trigger the event loop to compute the bloom filter
                    mr_bloom_gateway_set_dirty();
                    _mari_vars.app_event_callback(MARI_NODE_JOINED, (mr_event_data_t){ .data.node_info.node_id = header->src });
                } else {
                    _mari_vars.app_event_callback(MARI_ERROR, (mr_event_data_t){ .tag = MARI_GATEWAY_FULL });
                }
                break;
            }
            case MARI_PACKET_DATA:
            {
                if (!from_joined_node) {
                    // ignore packets from nodes that are not joined
                    return false;
                }
                // send the packet to the application
                mr_event_data_t event_data = {
                    .data.new_packet = {
                        .len         = length,
                        .header      = header,
                        .payload     = packet + sizeof(mr_packet_header_t),
                        .payload_len = length - sizeof(mr_packet_header_t) }
                };
                _mari_vars.app_event_callback(MARI_NEW_PACKET, event_data);
                mr_assoc_gateway_keep_node_alive(header->src, mr_mac_get_asn());  // keep track of when the last packet was received
                break;
            }
            case MARI_PACKET_KEEPALIVE:
            {
                if (!from_joined_node) {
                    // ignore packets from nodes that are not joined
                    return false;
                }
                mr_assoc_gateway_keep_node_alive(header->src, mr_mac_get_asn());  // keep track of when the last packet was received
                mr_event_data_t event_data = {
                    .data.node_info = { .node_id = header->src }
                };
                _mari_vars.app_event_callback(MARI_KEEPALIVE, event_data);
                break;
            }
            default:
                break;
        }

    } else if (mari_get_node_type() == MARI_NODE) {
        if (!mr_assoc_node_matches_network_id(header->network_id)) {
            // ignore packet with non-matching network id
            return false;
        }

        bool from_my_joined_gateway = header->src == mr_mac_get_synced_gateway() && mr_assoc_get_state() == JOIN_STATE_JOINED;

        switch (header->type) {
            case MARI_PACKET_BEACON:
                mr_assoc_handle_beacon(packet, length, MARI_FIXED_SCAN_CHANNEL, mr_mac_get_asn());
                break;
            case MARI_PACKET_JOIN_RESPONSE:
            {
                if (mr_assoc_get_state() != JOIN_STATE_JOINING) {
                    // ignore if not in the JOINING state
                    return false;
                }
                if (header->dst != mr_device_id()) {
                    // ignore if not for me
                    return false;
                }
                // the first byte after the header contains the cell_id
                uint8_t cell_id = packet[sizeof(mr_packet_header_t)];
                // the second byte after the header contains the flag_attest
                uint8_t flag_attest = packet[sizeof(mr_packet_header_t) + 1];
                if (mr_scheduler_node_assign_myself_to_cell(cell_id)) {
                    mr_assoc_node_handle_joined(header->src);
                    if (flag_attest) {
                        // TODO: add an attestation event 
                    }
                } else {
                    _mari_vars.app_event_callback(MARI_ERROR, (mr_event_data_t){ 0 });
                }
                break;
            }
            case MARI_PACKET_DATA:
            {
                if (!from_my_joined_gateway) {
                    // ignore data packets from other gateways
                    return false;
                }
                // send the packet to the application
                mr_event_data_t event_data = {
                    .data.new_packet = {
                        .len         = length,
                        .header      = header,
                        .payload     = packet + sizeof(mr_packet_header_t),
                        .payload_len = length - sizeof(mr_packet_header_t) }
                };
                _mari_vars.app_event_callback(MARI_NEW_PACKET, event_data);
                mr_assoc_node_keep_gateway_alive(mr_mac_get_asn());
                break;
            }
            case MARI_PACKET_KEEPALIVE:
                if (!from_my_joined_gateway) {
                    // ignore keep-alives from other gateways
                    return false;
                }
                mr_assoc_node_keep_gateway_alive(mr_mac_get_asn());
                break;
            default:
                break;
        }
    }

    return true;
}

void mari_event_loop(void) {
    // process the event loop
    switch (mari_get_node_type()) {
        case MARI_GATEWAY:
            mr_bloom_gateway_event_loop();
            break;
        case MARI_NODE:
            break;
    }
}

//=========================== callbacks ===========================================

static void event_callback(mr_event_t event, mr_event_data_t event_data) {
    // handle some events internally
    switch (event) {
        case MARI_NODE_LEFT:
            mr_bloom_gateway_set_dirty();
            break;
        default:
            break;
    }

    // forward the event to the application callback
    if (_mari_vars.app_event_callback) {
        _mari_vars.app_event_callback(event, event_data);
    }
}
