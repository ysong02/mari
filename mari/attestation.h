#ifndef __ATTESTATION_H
#define __ATTESTATION_H

/**
 * @ingroup     mari
 * @brief       attestation header file
 *
 * @{
 * @file
 * @author Yuxuan Song <yuxuan.song@inria.fr>
 * @copyright Inria, 2025
 * @}
 */

#include <nrf.h>
#include <stdint.h>
#include <stdbool.h>

//=========================== defines =========================================
#define MAX_SIG_STRUCTURE   255
#define MAM_EVIDENCE        128

//=========================== variables =======================================
// temporary
extern uint8_t flag_attest;

//=========================== prototypes ======================================

uint8_t mr_attestation_evidence_generation (uint64_t asn_dl, uint8_t *buffer, uint8_t *buffer_size);
bool mr_attestation_check_version (uint8_t *buffer, uint32_t expected_version);

#endif  // __ATTESTATION_H