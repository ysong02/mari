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

// Independent of MARI_JOIN_RESPONSE_QUEUE_SIZE so both can be tuned separately.
#define EDHOC_MSG3_ENTRIES       32
#define PENDING_JOINRESP_SIZE    32

// How many slots to wait for msg3 before sending join response without it (fallback).
// The UART roundtrip (edge processes msg2, returns msg3) is ~10-30 ms; 30 slots ~300 ms is ample.
#define JOINRESP_WAIT_TIMEOUT_SLOTS 30

typedef struct {
    uint64_t node_id;
    uint8_t  data[MARI_EDHOC_MAX_MSG_LEN];
    uint8_t  len;
} edhoc_msg3_entry_t;

typedef struct {
    bool     valid;
    uint64_t node_id;
    uint8_t  cell_id;
    uint64_t created_asn;
} pending_joinresp_t;

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
    mari_packet_queue_t   packet_queue;
    bool                  queue_locked;  ///< Simple lock to prevent concurrent access
    mr_packet_t           join_packet;
    mari_joinresp_queue_t joinresp_queue;  // gateway JOIN_RESPONSE FIFO
} queue_vars_t;

//=========================== variables ========================================

static queue_vars_t queue_vars = { 0 };

// EDHOC storage (gateway side)
static uint8_t edhoc_msg1_data[MARI_EDHOC_MAX_MSG_LEN] = { 0 };
static uint8_t edhoc_msg1_len                          = 0;
static edhoc_msg3_entry_t edhoc_msg3_entries[EDHOC_MSG3_ENTRIES] = { 0 };

// EDHOC msg2 pending buffer (node side): saved when msg2 arrives before join packet is prepared
static uint8_t pending_msg2_data[MARI_EDHOC_MAX_MSG_LEN] = { 0 };
static uint8_t pending_msg2_len                          = 0;

// Gateway side: join responses held until msg3 arrives from the edge (one slot per node)
static pending_joinresp_t pending_joinresp_pool[PENDING_JOINRESP_SIZE] = { 0 };

//=========================== prototypes =======================================

static void _finalize_join_response(uint64_t node_id, uint8_t cell_id);

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
            // append EDHOC msg1 if available
            if (edhoc_msg1_len > 0 && (len + 2 + edhoc_msg1_len) <= MARI_PACKET_MAX_SIZE) {
                packet[len++] = MARI_EDHOC_PAYLOAD_TAG;
                packet[len++] = edhoc_msg1_len;
                memcpy(packet + len, edhoc_msg1_data, edhoc_msg1_len);
                len += edhoc_msg1_len;
            }
        } else if (slot_type == SLOT_TYPE_DOWNLINK) {
            // Finalize any pending join responses once msg3 has arrived (or timeout elapsed)
            for (uint8_t pi = 0; pi < PENDING_JOINRESP_SIZE; pi++) {
                if (!pending_joinresp_pool[pi].valid) { continue; }
                bool msg3_ready = false;
                for (uint8_t i = 0; i < EDHOC_MSG3_ENTRIES; i++) {
                    if (edhoc_msg3_entries[i].node_id == pending_joinresp_pool[pi].node_id &&
                        edhoc_msg3_entries[i].len > 0) {
                        msg3_ready = true;
                        break;
                    }
                }
                bool timed_out = (mr_mac_get_asn() - pending_joinresp_pool[pi].created_asn) >= JOINRESP_WAIT_TIMEOUT_SLOTS;
                if (msg3_ready || timed_out) {
                    _finalize_join_response(pending_joinresp_pool[pi].node_id, pending_joinresp_pool[pi].cell_id);
                    pending_joinresp_pool[pi].valid = false;
                }
            }
            // Priority 1: JOIN_RESPONSE FIFO
            if (queue_vars.joinresp_queue.current != queue_vars.joinresp_queue.last) {
                mr_packet_t *jp = &queue_vars.joinresp_queue.packets[queue_vars.joinresp_queue.current];
                memcpy(packet, jp->buffer, jp->length);
                len = jp->length;
                queue_vars.joinresp_queue.current =
                    (queue_vars.joinresp_queue.current + 1) % MARI_JOIN_RESPONSE_QUEUE_SIZE;

                // record asn_dl for attestation freshness: the downlink ASN when join response was sent
                mr_packet_header_t *h = (mr_packet_header_t *)packet;
                mr_assoc_gateway_set_attest_dl_asn(h->dst, mr_mac_get_asn());
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
    pending_msg2_len = 0;
    for (uint8_t i = 0; i < PENDING_JOINRESP_SIZE; i++) {
        pending_joinresp_pool[i].valid = false;
    }

    queue_vars.joinresp_queue.current = 0;
    queue_vars.joinresp_queue.last    = 0;
    for (size_t i = 0; i < MARI_JOIN_RESPONSE_QUEUE_SIZE; i++) {
        queue_vars.joinresp_queue.packets[i].length = 0;
        memset(queue_vars.joinresp_queue.packets[i].buffer, 0, sizeof(queue_vars.joinresp_queue.packets[i].buffer));
    }
}

void mr_queue_set_join_request(uint64_t node_id) {
    queue_vars.join_packet.length = mr_build_packet_join_request(queue_vars.join_packet.buffer, node_id);
    // auto-append msg2 if it was already generated before this call
    if (pending_msg2_len > 0) {
        uint8_t cur_len = queue_vars.join_packet.length;
        if ((cur_len + 2 + pending_msg2_len) <= MARI_PACKET_MAX_SIZE) {
            queue_vars.join_packet.buffer[cur_len++] = MARI_EDHOC_PAYLOAD_TAG;
            queue_vars.join_packet.buffer[cur_len++] = pending_msg2_len;
            memcpy(queue_vars.join_packet.buffer + cur_len, pending_msg2_data, pending_msg2_len);
            queue_vars.join_packet.length = cur_len + pending_msg2_len;
        }
    }
}

// Build the join response packet (with msg3 if available) and add it to the FIFO.
static void _finalize_join_response(uint64_t node_id, uint8_t cell_id) {
    uint8_t next_last = (queue_vars.joinresp_queue.last + 1) % MARI_JOIN_RESPONSE_QUEUE_SIZE;
    if (next_last == queue_vars.joinresp_queue.current) {
        return;  // FIFO full, drop (node will retry)
    }

    mr_packet_t *jp   = &queue_vars.joinresp_queue.packets[queue_vars.joinresp_queue.last];
    uint8_t      len  = mr_build_packet_join_response(jp->buffer, node_id);
    jp->buffer[len++] = cell_id;
    for (uint8_t i = 0; i < EDHOC_MSG3_ENTRIES; i++) {
        if (edhoc_msg3_entries[i].node_id == node_id && edhoc_msg3_entries[i].len > 0) {
            if ((len + 2 + edhoc_msg3_entries[i].len) <= MARI_PACKET_MAX_SIZE) {
                jp->buffer[len++] = MARI_EDHOC_PAYLOAD_TAG;
                jp->buffer[len++] = edhoc_msg3_entries[i].len;
                memcpy(jp->buffer + len, edhoc_msg3_entries[i].data, edhoc_msg3_entries[i].len);
                len += edhoc_msg3_entries[i].len;
            }
            edhoc_msg3_entries[i].node_id = 0;
            edhoc_msg3_entries[i].len     = 0;
            break;
        }
    }
    jp->length                     = len;
    queue_vars.joinresp_queue.last = next_last;
}

void mr_queue_set_join_response(uint64_t node_id, uint8_t assigned_cell_id) {
    // Hold the join response until msg3 arrives from the edge.
    // Search for an existing slot for this node (re-join) or a free slot.
    for (uint8_t i = 0; i < PENDING_JOINRESP_SIZE; i++) {
        if (!pending_joinresp_pool[i].valid || pending_joinresp_pool[i].node_id == node_id) {
            pending_joinresp_pool[i].valid       = true;
            pending_joinresp_pool[i].node_id     = node_id;
            pending_joinresp_pool[i].cell_id     = assigned_cell_id;
            pending_joinresp_pool[i].created_asn = mr_mac_get_asn();
            return;
        }
    }
    // Pool full: overwrite slot 0 so the current node is not silently dropped.
    pending_joinresp_pool[0].valid       = true;
    pending_joinresp_pool[0].node_id     = node_id;
    pending_joinresp_pool[0].cell_id     = assigned_cell_id;
    pending_joinresp_pool[0].created_asn = mr_mac_get_asn();
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

void mr_queue_set_edhoc_msg1(uint8_t *data, uint8_t len) {
    if (len > MARI_EDHOC_MAX_MSG_LEN) {
        len = MARI_EDHOC_MAX_MSG_LEN;
    }
    memcpy(edhoc_msg1_data, data, len);
    edhoc_msg1_len = len;
}

void mr_queue_set_edhoc_msg3(uint64_t node_id, uint8_t *data, uint8_t len) {
    if (len > MARI_EDHOC_MAX_MSG_LEN) {
        len = MARI_EDHOC_MAX_MSG_LEN;
    }
    // find existing entry or free slot
    for (uint8_t i = 0; i < EDHOC_MSG3_ENTRIES; i++) {
        if (edhoc_msg3_entries[i].node_id == node_id || edhoc_msg3_entries[i].node_id == 0) {
            edhoc_msg3_entries[i].node_id = node_id;
            edhoc_msg3_entries[i].len     = len;
            memcpy(edhoc_msg3_entries[i].data, data, len);
            // Finalize the pending join response immediately so it is queued in the FIFO
            // before the next downlink slot fires.
            for (uint8_t pi = 0; pi < PENDING_JOINRESP_SIZE; pi++) {
                if (pending_joinresp_pool[pi].valid && pending_joinresp_pool[pi].node_id == node_id) {
                    _finalize_join_response(pending_joinresp_pool[pi].node_id, pending_joinresp_pool[pi].cell_id);
                    pending_joinresp_pool[pi].valid = false;
                    break;
                }
            }
            return;
        }
    }
    // no space: overwrite slot 0
    edhoc_msg3_entries[0].node_id = node_id;
    edhoc_msg3_entries[0].len     = len;
    memcpy(edhoc_msg3_entries[0].data, data, len);
    for (uint8_t pi = 0; pi < PENDING_JOINRESP_SIZE; pi++) {
        if (pending_joinresp_pool[pi].valid && pending_joinresp_pool[pi].node_id == node_id) {
            _finalize_join_response(pending_joinresp_pool[pi].node_id, pending_joinresp_pool[pi].cell_id);
            pending_joinresp_pool[pi].valid = false;
            break;
        }
    }
}

void mr_queue_append_edhoc_to_join_request(uint8_t *data, uint8_t len) {
    if (len > MARI_EDHOC_MAX_MSG_LEN) {
        len = MARI_EDHOC_MAX_MSG_LEN;
    }
    // always save msg2 so mr_queue_set_join_request can append it even if called later
    memcpy(pending_msg2_data, data, len);
    pending_msg2_len = len;

    if (queue_vars.join_packet.length < sizeof(mr_packet_header_t)) {
        // join packet not prepared yet; mr_queue_set_join_request will append msg2 when called
        return;
    }
    // join packet already exists: reset to base and append msg2 now
    uint8_t cur_len = sizeof(mr_packet_header_t);
    if ((cur_len + 2 + len) > MARI_PACKET_MAX_SIZE) {
        return;
    }
    queue_vars.join_packet.buffer[cur_len++] = MARI_EDHOC_PAYLOAD_TAG;
    queue_vars.join_packet.buffer[cur_len++] = len;
    memcpy(queue_vars.join_packet.buffer + cur_len, data, len);
    queue_vars.join_packet.length = cur_len + len;
}
