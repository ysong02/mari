/**
 * @file
 * @ingroup     queue
 *
 * @brief       Packet queue management
 *
 * @author Geovane Fedrecheski <geovane.fedrecheski@inria.fr>
 *
 * @copyright Inria, 2024
 */

#include <nrf.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "packet.h"
#include "mac.h"
#include "scheduler.h"
#include "association.h"
#include "bloom.h"
#include "mari.h"
#include "queue.h"

// for attestation
#include "attestation.h"
#include <stdio.h>

//=========================== defines ==========================================

typedef struct {
    uint8_t length;
    uint8_t buffer[MARI_PACKET_MAX_SIZE];
} mr_packet_t;

typedef struct {
    uint8_t     current;  ///< Current position in the queue
    uint8_t     last;     ///< Position of the last item added in the queue
    mr_packet_t packets[MARI_PACKET_QUEUE_SIZE];
} mari_packet_queue_t;

typedef struct {
    uint8_t     current;
    uint8_t     last;
    mr_packet_t packets[MARI_JOIN_RESPONSE_QUEUE_SIZE];
} mari_joinresp_queue_t;

typedef struct {
    mari_packet_queue_t packet_queue;
    bool                queue_locked;  ///< Simple lock to prevent concurrent access
    mr_packet_t         join_packet;
    mari_joinresp_queue_t joinresp_queue;  // gateway JOIN_RESPONSE FIFO
} queue_vars_t;

//=========================== variables ========================================

static queue_vars_t queue_vars = { 0 };

//=========================== prototypes =======================================

//=========================== public ===========================================

uint8_t mr_queue_next_packet(slot_type_t slot_type, uint8_t *packet) {
    uint8_t len = 0;

    if (mari_get_node_type() == MARI_GATEWAY) {
        if (slot_type == SLOT_TYPE_BEACON) {
            // prepare a beacon packet with current asn, remaining capacity and active schedule id
            len = mr_build_packet_beacon(
                packet,
                mr_assoc_get_network_id(),
                mr_mac_get_asn(),
                mr_scheduler_gateway_remaining_capacity(),
                mr_scheduler_get_active_schedule_id());
        } else if (slot_type == SLOT_TYPE_DOWNLINK) {
            // if (mr_queue_has_join_packet()) {
            //     len = mr_queue_get_join_packet(packet);
            // Priority 1: JOIN_RESPONSE FIFO
            if (queue_vars.joinresp_queue.current != queue_vars.joinresp_queue.last) {
                mr_packet_t *jp = &queue_vars.joinresp_queue.packets[queue_vars.joinresp_queue.current];
                memcpy(packet, jp->buffer, jp->length);
                len = jp->length;
                queue_vars.joinresp_queue.current =
                    (queue_vars.joinresp_queue.current + 1) % MARI_JOIN_RESPONSE_QUEUE_SIZE;

                // for attestation, get asn_dl for gateway
                mr_packet_header_t *h  = (mr_packet_header_t *)packet;
                uint8_t            *pl = packet + sizeof(mr_packet_header_t);
                if (len >= sizeof(mr_packet_header_t) + 2) {
                    uint8_t flag_attest = pl[1];
                    if (flag_attest) {
                        uint64_t asn_dl = mr_mac_get_asn() - 1;
                        mr_assoc_gateway_set_attesting(h->dst, true);
                        mr_assoc_gateway_set_attest_dl_asn(h->dst, asn_dl);
                    }
                }
            } else {
                // load a packet from the queue, if any is available
                len = mr_queue_peek(packet);
                if (len) {
                    // actually pop the packet from the queue
                    mr_queue_pop();
                }
            }
        }
    } else if (mari_get_node_type() == MARI_NODE) {
        if (slot_type == SLOT_TYPE_SHARED_UPLINK) {
            if (mr_assoc_node_ready_to_join()) {
                mr_assoc_node_start_joining();
                len = mr_queue_get_join_packet(packet);
            }
        } else if (slot_type == SLOT_TYPE_UPLINK) {
            // TODO: add a filter for attestation packet when the state == is_attesting
            // load a packet from the queue, if any is available
            len = mr_queue_peek(packet);
            if (len) {
                // actually pop the packet from the queue
                mr_queue_pop();
            } else if (MARI_AUTO_UPLINK_KEEPALIVE) {
                // send a keepalive packet
                len = mr_build_packet_keepalive(packet, mr_mac_get_synced_gateway());
            }
        }
    }

    return len;
}

void mr_queue_add(uint8_t *packet, uint8_t length) {
    // // lock is asymetrical: add (called from application) can wait in busy loop
    while (queue_vars.queue_locked) {
        // wait for the queue to be unlocked
    }
    queue_vars.queue_locked = true;

    // // enqueue for transmission
    // memcpy(queue_vars.packet_queue.packets[queue_vars.packet_queue.last].buffer, packet, length);
    // queue_vars.packet_queue.packets[queue_vars.packet_queue.last].length = length;
    // // increment the `last` index
    // queue_vars.packet_queue.last = (queue_vars.packet_queue.last + 1) % MARI_PACKET_QUEUE_SIZE;

    // queue_vars.queue_locked = false;

    // check if queue is full (next position would collide with current)
    uint8_t next_last = (queue_vars.packet_queue.last + 1) % MARI_PACKET_QUEUE_SIZE;
    if (next_last == queue_vars.packet_queue.current) {
        // Queue full: drop this packet (do NOT overwrite unsent packets)
        queue_vars.queue_locked = false;
        return;
    }

    // enqueue for transmission
    memcpy(queue_vars.packet_queue.packets[queue_vars.packet_queue.last].buffer, packet, length);
    queue_vars.packet_queue.packets[queue_vars.packet_queue.last].length = length;
    // increment the `last` index
    queue_vars.packet_queue.last = next_last;

    queue_vars.queue_locked = false;
}

uint8_t mr_queue_peek(uint8_t *packet) {
    // lock is asymetrical: peek (called from MAC) can simply give up if the queue is locked
    if (queue_vars.queue_locked) {
        // simply give up if the queue is locked (will try again next slot)
        return 0;
    }

    if (queue_vars.packet_queue.current == queue_vars.packet_queue.last) {
        return 0;
    }

    memcpy(packet, queue_vars.packet_queue.packets[queue_vars.packet_queue.current].buffer, queue_vars.packet_queue.packets[queue_vars.packet_queue.current].length);
    // do not increment the `current` index here, as this is just a peek
    return queue_vars.packet_queue.packets[queue_vars.packet_queue.current].length;
}

bool mr_queue_pop(void) {
    // lock is asymetrical: just as with peek
    if (queue_vars.queue_locked) {
        // simply give up if the queue is locked (will try again next slot)
        return false;
    }

    if (queue_vars.packet_queue.current == queue_vars.packet_queue.last) {
        return false;
    } else {
        // increment the `current` index
        queue_vars.packet_queue.current = (queue_vars.packet_queue.current + 1) % MARI_PACKET_QUEUE_SIZE;
        return true;
    }
}

void mr_queue_reset(void) {
    queue_vars.packet_queue.current = 0;
    queue_vars.packet_queue.last    = 0;
    queue_vars.join_packet.length   = 0;
    queue_vars.queue_locked         = false;
    memset(queue_vars.join_packet.buffer, 0, sizeof(queue_vars.join_packet.buffer));

    queue_vars.joinresp_queue.current = 0;
    queue_vars.joinresp_queue.last    = 0;
    for (size_t i = 0; i < MARI_JOIN_RESPONSE_QUEUE_SIZE; i++) {
        queue_vars.joinresp_queue.packets[i].length = 0;
        memset(queue_vars.joinresp_queue.packets[i].buffer, 0, sizeof(queue_vars.joinresp_queue.packets[i].buffer));
    }
}

void mr_queue_set_join_request(uint64_t node_id) {
    queue_vars.join_packet.length = mr_build_packet_join_request(queue_vars.join_packet.buffer, node_id);
}

void mr_queue_set_join_response(uint64_t node_id, uint8_t assigned_cell_id, uint8_t flag_attest) {
    // uint8_t len                          = mr_build_packet_join_response(queue_vars.join_packet.buffer, node_id);
    // queue_vars.join_packet.buffer[len++] = assigned_cell_id;
    // queue_vars.join_packet.buffer[len++] = flag_attest;
    // queue_vars.join_packet.length        = len;
    // Gateway-only: enqueue JOIN_RESPONSE into FIFO (do not overwrite others)
    uint8_t next_last = (queue_vars.joinresp_queue.last + 1) % MARI_JOIN_RESPONSE_QUEUE_SIZE;
    if (next_last == queue_vars.joinresp_queue.current) {
        // FIFO full -> drop this join response (node will retry)
        return;
    }

    mr_packet_t *jp = &queue_vars.joinresp_queue.packets[queue_vars.joinresp_queue.last];
    uint8_t len     = mr_build_packet_join_response(jp->buffer, node_id);
    jp->buffer[len++] = assigned_cell_id;
    jp->buffer[len++] = flag_attest;
    jp->length        = len;

    queue_vars.joinresp_queue.last = next_last;
}

bool mr_queue_has_join_packet(void) {
    return queue_vars.join_packet.length > 0;
}

// if used by the node, gets it a join request packet
// if used by the gateway, gets it a join response packet
uint8_t mr_queue_get_join_packet(uint8_t *packet) {
    memcpy(packet, queue_vars.join_packet.buffer, queue_vars.join_packet.length);
    uint8_t len = queue_vars.join_packet.length;

    // clear the join request
    queue_vars.join_packet.length = 0;

    return len;
}
