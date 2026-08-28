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

#include "attestation.h"
#include <stdio.h>

//=========================== defines ==========================================

#define EDHOC_MSG3_ENTRIES       32
#define PENDING_JOINRESP_SIZE    32

// How long the gateway waits for mari_edge's connect reply before falling back to a bare join response.
#define JOINRESP_WAIT_TIMEOUT_SLOTS 3000

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
    uint8_t buffer[MARI_PACKET_MAX_SIZE];
    uint8_t length;
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

// Round-robin state between the two gateway downlink sources (see mr_queue_next_packet).
static bool _downlink_prefer_general = false;

//=========================== prototypes =======================================

static void    _finalize_join_response(uint64_t node_id, uint8_t cell_id);
static int16_t _gateway_find_uplink_cell_id(uint64_t node_id);
static uint8_t _pop_join_response(uint8_t *packet);

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
            // Alternate FIFO/general queue -- strict FIFO priority used to starve the general queue (attest ack, reboot) whenever retries kept producing join responses.
            bool joinresp_ready = queue_vars.joinresp_queue.current != queue_vars.joinresp_queue.last;

            if (joinresp_ready && !_downlink_prefer_general) {
                len                      = _pop_join_response(packet);
                _downlink_prefer_general = true;
            } else {
                len = mr_queue_peek(packet);
                if (len) {
                    mr_queue_pop();
                    _downlink_prefer_general = false;
                } else if (joinresp_ready) {
                    len                      = _pop_join_response(packet);
                    _downlink_prefer_general = true;
                }
            }
        }
    } else if (mari_get_node_type() == MARI_NODE) {
        if (slot_type == SLOT_TYPE_SHARED_UPLINK) {
            if (mr_assoc_node_ready_to_join() && pending_msg2_len > 0) {
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

// Pop the next join response off the FIFO into `packet`, assuming the caller already checked it's non-empty; only ever called from the downlink slot.
static uint8_t _pop_join_response(uint8_t *packet) {
    mr_packet_t *jp = &queue_vars.joinresp_queue.packets[queue_vars.joinresp_queue.current];
    memcpy(packet, jp->buffer, jp->length);
    uint8_t len = jp->length;
    queue_vars.joinresp_queue.current =
        (queue_vars.joinresp_queue.current + 1) % MARI_JOIN_RESPONSE_QUEUE_SIZE;

    // record asn_dl for attestation freshness: the downlink ASN when join response was sent
    mr_packet_header_t *h = (mr_packet_header_t *)packet;
    mr_assoc_gateway_set_attest_dl_asn(h->dst, mr_mac_get_asn());
    return len;
}

// Build the join response (with msg3 if available) and push it to the FIFO.
// Called from both the MAC ISR and the main loop, so the `last` read-modify-write
// is guarded with a PRIMASK save/restore (nests safely inside the ISR).
static void _finalize_join_response(uint64_t node_id, uint8_t cell_id) {
    uint32_t primask = __get_PRIMASK();
    __disable_irq();

    uint8_t next_last = (queue_vars.joinresp_queue.last + 1) % MARI_JOIN_RESPONSE_QUEUE_SIZE;
    if (next_last == queue_vars.joinresp_queue.current) {
        __set_PRIMASK(primask);
        CRAFT_DIAG_PRINTF("[DIAG-GW] DROP join response for 0x%08X%08X: FIFO full\n",
                          CRAFT_DIAG_ID_HI(node_id), CRAFT_DIAG_ID_LO(node_id));
        return;  // FIFO full, drop (node will retry)
    }

    mr_packet_t *jp       = &queue_vars.joinresp_queue.packets[queue_vars.joinresp_queue.last];
    uint8_t      len      = mr_build_packet_join_response(jp->buffer, node_id);
    bool         attached = false;
    jp->buffer[len++] = cell_id;
    for (uint8_t i = 0; i < EDHOC_MSG3_ENTRIES; i++) {
        if (edhoc_msg3_entries[i].node_id == node_id && edhoc_msg3_entries[i].len > 0) {
            if ((len + 2 + edhoc_msg3_entries[i].len) <= MARI_PACKET_MAX_SIZE) {
                jp->buffer[len++] = MARI_EDHOC_PAYLOAD_TAG;
                jp->buffer[len++] = edhoc_msg3_entries[i].len;
                memcpy(jp->buffer + len, edhoc_msg3_entries[i].data, edhoc_msg3_entries[i].len);
                len += edhoc_msg3_entries[i].len;
                attached = true;
            }
            edhoc_msg3_entries[i].node_id = 0;
            edhoc_msg3_entries[i].len     = 0;
            break;
        }
    }
    jp->length = len;
    __DMB();  // buffer contents must be visible before `last` publishes them
    queue_vars.joinresp_queue.last = next_last;

    __set_PRIMASK(primask);

    // Printed outside the critical section -- CRAFT_DIAG_PRINTF can block on
    // the RTT buffer, and this function nests inside the MAC ISR.
    CRAFT_DIAG_PRINTF("[DIAG-GW] TX join response queued for 0x%08X%08X cell=%u connect_reply=%s\n",
                      CRAFT_DIAG_ID_HI(node_id), CRAFT_DIAG_ID_LO(node_id), (unsigned)cell_id,
                      attached ? "yes" : "no");
    (void)attached;
}

// Look up the uplink cell already assigned to a joined node (gateway side).
static int16_t _gateway_find_uplink_cell_id(uint64_t node_id) {
    schedule_t *schedule = mr_scheduler_get_active_schedule_ptr();
    for (size_t i = 0; i < schedule->n_cells; i++) {
        if (schedule->cells[i].type == SLOT_TYPE_UPLINK && schedule->cells[i].assigned_node_id == node_id) {
            return (int16_t)i;
        }
    }
    return -1;
}

void mr_queue_set_join_response(uint64_t node_id, uint8_t assigned_cell_id) {
    // Hold the join response until msg3 arrives; reuse this node's slot if it's a re-join, else take a free one.
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

// Re-queues a connect-reply retry after the original pending-response record was already consumed.
static void _requeue_connect_reply_retry(uint64_t node_id) {
    int16_t cell_id = _gateway_find_uplink_cell_id(node_id);
    if (cell_id >= 0) {
        _finalize_join_response(node_id, (uint8_t)cell_id);
    }
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
            bool found_pending = false;
            for (uint8_t pi = 0; pi < PENDING_JOINRESP_SIZE; pi++) {
                if (pending_joinresp_pool[pi].valid && pending_joinresp_pool[pi].node_id == node_id) {
                    _finalize_join_response(pending_joinresp_pool[pi].node_id, pending_joinresp_pool[pi].cell_id);
                    pending_joinresp_pool[pi].valid = false;
                    found_pending               = true;
                    break;
                }
            }
            if (!found_pending) {
                _requeue_connect_reply_retry(node_id);
            }
            return;
        }
    }
    // no space: overwrite slot 0
    edhoc_msg3_entries[0].node_id = node_id;
    edhoc_msg3_entries[0].len     = len;
    memcpy(edhoc_msg3_entries[0].data, data, len);
    bool found_pending = false;
    for (uint8_t pi = 0; pi < PENDING_JOINRESP_SIZE; pi++) {
        if (pending_joinresp_pool[pi].valid && pending_joinresp_pool[pi].node_id == node_id) {
            _finalize_join_response(pending_joinresp_pool[pi].node_id, pending_joinresp_pool[pi].cell_id);
            pending_joinresp_pool[pi].valid = false;
            found_pending               = true;
            break;
        }
    }
    if (!found_pending) {
        _requeue_connect_reply_retry(node_id);
    }
}

void mr_queue_gateway_reset_edhoc_state(void) {
    for (uint8_t i = 0; i < EDHOC_MSG3_ENTRIES; i++) {
        edhoc_msg3_entries[i].node_id = 0;
        edhoc_msg3_entries[i].len     = 0;
    }
    for (uint8_t i = 0; i < PENDING_JOINRESP_SIZE; i++) {
        pending_joinresp_pool[i].valid = false;
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
