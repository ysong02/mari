#ifndef __ASSOCIATION_H
#define __ASSOCIATION_H

/**
 * @file
 * @ingroup     mari_assoc
 *
 * @brief       Association procedure for the mari protocol
 *
 * @author Geovane Fedrecheski <geovane.fedrecheski@inria.fr>
 *
 * @copyright Inria, 2024-now
 */

#include <stdint.h>
#include <stdbool.h>

#include "models.h"

//=========================== defines ==========================================

typedef enum {
    JOIN_STATE_IDLE     = 1,
    JOIN_STATE_SCANNING = 2,
    JOIN_STATE_SYNCED   = 4,
    JOIN_STATE_JOINING  = 8,
    JOIN_STATE_JOINED   = 16,
} mr_assoc_state_t;

//=========================== variables ========================================

//=========================== prototypes =======================================

void             mr_assoc_init(uint16_t net_id, mr_event_cb_t event_callback);
void             mr_assoc_set_state(mr_assoc_state_t join_state);
mr_assoc_state_t mr_assoc_get_state(void);
bool             mr_assoc_is_joined(void);
void             mr_assoc_handle_beacon(uint8_t *packet, uint8_t length, uint8_t channel, uint32_t ts);
void             mr_assoc_handle_packet(uint8_t *packet, uint8_t length);
uint16_t         mr_assoc_get_network_id(void);

void mr_assoc_node_handle_synced(void);
bool mr_assoc_node_ready_to_join(void);
void mr_assoc_node_start_joining(void);
void mr_assoc_node_handle_joined(uint64_t gateway_id);
bool mr_assoc_node_handle_failed_join(void);
bool mr_assoc_node_too_long_waiting_for_join_response(void);
bool mr_assoc_node_too_long_synced_without_joining(void);
void mr_assoc_node_handle_give_up_joining(void);
void mr_assoc_node_handle_pending_disconnect(void);
void mr_assoc_node_handle_immediate_disconnect(mr_event_tag_t tag);
bool mr_assoc_node_matches_network_id(uint16_t network_id);

void mr_assoc_node_register_collision_backoff(void);
void mr_assoc_node_reset_backoff(void);

bool mr_assoc_node_should_leave(uint32_t asn);
void mr_assoc_node_keep_gateway_alive(uint64_t asn);

bool mr_assoc_gateway_node_is_joined(uint64_t node_id);

bool mr_assoc_gateway_keep_node_alive(uint64_t node_id, uint64_t asn);
void mr_assoc_gateway_clear_old_nodes(uint64_t asn);

// attestation: asn_dl per node (downlink ASN when join response was sent)
void mr_assoc_gateway_set_attest_dl_asn(uint64_t node_id, uint64_t asn_dl);
bool mr_assoc_gateway_get_attest_dl_asn(uint64_t node_id, uint64_t *asn_dl_out);

// remove a node from the schedule (e.g., on attestation failure)
void mr_assoc_gateway_remove_node(uint64_t node_id);

// remove all nodes from the schedule and clear the bloom filter (used for coordinated reboot)
void mr_assoc_gateway_remove_all_nodes(void);

#endif  // __ASSOCIATION_H
