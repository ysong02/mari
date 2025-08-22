#ifndef __QUEUE_H
#define __QUEUE_H

/**
 * @ingroup     mari
 * @brief       Queue management
 *
 * @{
 * @file
 * @author Geovane Fedrecheski <geovane.fedrecheski@inria.fr>
 * @copyright Inria, 2024-now
 * @}
 */

#include <stdint.h>
#include <stdbool.h>

#include "models.h"

//=========================== defines =========================================

#define MARI_PACKET_QUEUE_SIZE (32)  // must be a power of 2

#define MARI_AUTO_UPLINK_KEEPALIVE 1  // whether to send a keepalive packet when there is nothing to send

//=========================== prototypes ======================================

void    mr_queue_add(uint8_t *packet, uint8_t length);
uint8_t mr_queue_next_packet(slot_type_t slot_type, uint8_t *packet);
uint8_t mr_queue_peek(uint8_t *packet);
bool    mr_queue_pop(void);
void    mr_queue_reset(void);

// void mr_queue_set_join_packet(uint64_t node_id, mr_packet_type_t packet_type);
void mr_queue_set_join_request(uint64_t node_id);
void mr_queue_set_join_response(uint64_t node_id, uint8_t assigned_cell_id, uint8_t flag_attest);

bool    mr_queue_has_join_packet(void);
uint8_t mr_queue_get_join_packet(uint8_t *packet);

#endif  // __QUEUE_H
