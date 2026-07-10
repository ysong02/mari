#ifndef __MAURA_ATTESTATION_H
#define __MAURA_ATTESTATION_H

/**
 * @file
 * @ingroup     app
 *
 * @author Yuxuan Song <yuxuan.song@inria.fr>
 * @copyright Inria, 2025
 */

#include <nrf.h>
#include <stdint.h>
#include <stdbool.h>
#include "C:/Users/yusong/Downloads/lakers/target/include/lakers.h"

//=========================== defines =========================================

#define MAURA_NONCE_SIZE          (8u)
#define MAURA_HASH_LEN            (32u)
#define MAURA_PROVIDED_EVIDENCE_TYPE (258u)
#define MAURA_MAX_TOKEN           (500u)

typedef enum {
    MAURA_ATTEST_SUCCESS         = 0,
    MAURA_ATTEST_ERROR_SIGNATURE = -9,
} maura_attestation_status_t;

//=========================== public functions =================================

/**
 * @brief Decode EAD_2 value: CBOR [evidence_type_uint, nonce_bstr].
 */
uint8_t maura_decode_ead_2(const uint8_t *buffer, uint32_t *evidence_type, uint8_t *nonce, uint8_t *nonce_len);

/**
 * @brief Prepare EAD_1 value: CBOR [258] — evidence type list.
 */
void maura_prepare_ead_1(EADItemC *ead, uint8_t label, bool is_critical);

/**
 * @brief Prepare EAD_3 value: COSE_Sign1 attestation token with attestation_binder
 *        in the external_aad of the Sig_Structure.
 *
 * @param ead_3        Output EAD item (populated by this function).
 * @param label        EAD label (use 1).
 * @param is_critical  EAD critical flag.
 * @param nonce        8-byte nonce from EAD_2 (from verifier via edge).
 * @param nonce_len    Length of nonce.
 * @param msg1         Raw EDHOC message_1 bytes (for H_12 computation).
 * @param msg1_len     Length of msg1.
 * @param msg2         Raw EDHOC message_2 bytes (for H_12 computation).
 * @param msg2_len     Length of msg2.
 */
void maura_prepare_ead_3(EADItemC *ead_3, uint8_t label, bool is_critical,
                          const uint8_t *nonce, uint8_t nonce_len,
                          const uint8_t *msg1, uint8_t msg1_len,
                          const uint8_t *msg2, uint8_t msg2_len);

#endif  // __MAURA_ATTESTATION_H
