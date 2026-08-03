#ifndef __X25519_H
#define __X25519_H

/**
 * @defgroup    crypto_x25519  X25519 (Curve25519) Diffie-Hellman
 * @ingroup     crypto
 * @brief       X25519 key agreement (RFC 7748), pure software
 *
 * Montgomery-ladder scalar multiplication ported from Daniel Beer's
 * c25519 (<dlbeer@gmail.com>, public domain), reusing the f25519 field
 * arithmetic already present in this codebase (soft_f25519.c/h) -- same
 * library family soft_ed25519.c/soft_edsign.c already come from.
 *
 * @{
 * @file
 * @}
 */

#include <stdint.h>

#define X25519_KEY_SIZE 32

/**
 * @brief   Compute an X25519 shared secret: crypto_x25519(out, my_sk, their_pk).
 *
 * @param[out]  shared_secret   Resulting 32-byte shared secret (raw X-coordinate,
 *                               not yet hashed -- caller runs it through a KDF).
 * @param[in]   private_key     Our own 32-byte raw (unclamped) X25519 private key.
 * @param[in]   peer_public_key Peer's 32-byte X25519 public key.
 */
void crypto_x25519(uint8_t shared_secret[X25519_KEY_SIZE], const uint8_t private_key[X25519_KEY_SIZE], const uint8_t peer_public_key[X25519_KEY_SIZE]);

#endif  // __X25519_H
