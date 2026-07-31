#ifndef __CRAFT_ATTESTATION_H
#define __CRAFT_ATTESTATION_H

/**
 * @file
 * @ingroup     app
 * @brief       CRAFT connect (join) + SEDA attest, node side.
 *
 * @author Yuxuan Song <yuxuan.song@inria.fr>
 * @copyright Inria, 2026
 */

#include <stdint.h>
#include <stdbool.h>

//=========================== defines =========================================

// connect wire layout: h_i(1) | Ta_i(4) | Tb_i(4) | PK_i(32) | SigExp(4) | sigma(64)
#define CRAFT_H_SIZE          (1u)
#define CRAFT_TA_SIZE         (4u)
#define CRAFT_TB_SIZE         (4u)
#define CRAFT_PK_SIZE         (32u)
#define CRAFT_SIGEXP_SIZE     (4u)
#define CRAFT_SIGMA_SIZE      (64u)
#define CRAFT_SIGNED_SIZE     (CRAFT_H_SIZE + CRAFT_TA_SIZE + CRAFT_TB_SIZE + CRAFT_PK_SIZE)  // 41, what sigma covers
#define CRAFT_CONNECT_SIZE    (CRAFT_SIGNED_SIZE + CRAFT_SIGEXP_SIZE + CRAFT_SIGMA_SIZE)       // 109

#define CRAFT_CHALLENGE_SIZE       (8u)
#define CRAFT_CONNECT_REPLY_SIZE   (CRAFT_CONNECT_SIZE + CRAFT_CHALLENGE_SIZE)  // 117: connect reply + piggybacked challenge

#define CRAFT_HASH_LEN        (32u)
#define CRAFT_ATTEST_TAG_SIZE (32u)  // bare HMAC-SHA256 tag, nothing else
#define CRAFT_X25519_KEY_SIZE (32u)

typedef enum {
    CRAFT_OK               = 0,
    CRAFT_ERROR_SIGNATURE  = -1,  ///< sigma_edge failed to verify against PK_O
    CRAFT_ERROR_BAD_LENGTH = -2,
} craft_status_t;

//=========================== public functions =================================

/// Builds h_i|Ta_i|Tb_i|PK_i|SigExp|sigma_i. Returns CRAFT_CONNECT_SIZE.
uint8_t craft_build_connect_request(uint8_t *buffer);

/// Verifies sigma_edge against PK_O and extracts pk_edge/challenge. Also
/// derives k_ij (kept for protocol fidelity though unused downstream).
craft_status_t craft_process_connect_reply(const uint8_t *buffer, uint8_t buffer_len,
                                            uint8_t pk_edge_out[CRAFT_X25519_KEY_SIZE],
                                            uint8_t challenge_out[CRAFT_CHALLENGE_SIZE],
                                            uint8_t k_ij_out[CRAFT_X25519_KEY_SIZE]);

/// tag = HMAC-SHA256(K, challenge || hash || node_id).
void craft_compute_attest_tag(const uint8_t challenge[CRAFT_CHALLENGE_SIZE], uint8_t tag_out[CRAFT_ATTEST_TAG_SIZE]);

#endif  // __CRAFT_ATTESTATION_H
