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
#define MAX_SIG_STRUCTURE 255
#define MAX_EVIDENCE      128

//=========================== prototypes ======================================

void mr_attestation_evidence_generation(uint64_t asn_dl, const uint8_t prk_exporter[32], uint8_t *buffer, uint8_t *buffer_size);

#endif  // __ATTESTATION_H
