#ifndef __MARI_H
#define __MARI_H

/**
 * @defgroup    mari      Mari
 * @brief       Implementation of the mari protocol
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

//=========================== defines ==========================================

#define MARI_MAX_NODES         101  // FIXME: find a way to sync with the pre-stored schedules
#define MARI_BROADCAST_ADDRESS 0xFFFFFFFFFFFFFFFF

//=========================== prototypes ==========================================

void           mari_init(mr_node_type_t node_type, uint16_t net_id, schedule_t *app_schedule, mr_event_cb_t app_event_callback);
void           mari_event_loop(void);
void           mari_tx(uint8_t *packet, uint8_t length);
mr_node_type_t mari_get_node_type(void);
void           mari_set_node_type(mr_node_type_t node_type);

size_t mari_gateway_get_nodes(uint64_t *nodes);
size_t mari_gateway_count_nodes(void);

void     mari_node_tx_payload(uint8_t *payload, uint8_t payload_len);
bool     mari_node_is_connected(void);
uint64_t mari_node_gateway_id(void);
// for attestation asn collection
uint64_t mari_node_get_last_asn_dl(void);

// -------- internal api --------
bool mr_handle_packet(uint8_t *packet, uint8_t length);

#endif  // __MARI_H
