/**
 * @file
 * @ingroup crypto
 *
 * @brief  X25519 (RFC 7748) Diffie-Hellman via Montgomery-ladder scalar
 *         multiplication on Curve25519.
 *
 * Ported from Daniel Beer's c25519 <dlbeer@gmail.com> (18 Apr 2014), released
 * into the public domain (https://www.dlbeer.co.nz/oss/c25519.html) -- only
 * the X-coordinate-only scalar multiply (c25519_smult) is needed here, not
 * the full (x,y) recovery / Edwards-Montgomery conversion machinery, since
 * CRAFT uses separate Ed25519 signing keys and X25519 DH keys (no need to
 * convert between the two). Reuses the f25519 field-arithmetic primitives
 * already present in this codebase (soft_f25519.c/h -- same library family
 * soft_ed25519.c/soft_edsign.c already come from).
 *
 * @author Yuxuan Song <yuxuan.song@inria.fr>
 * @copyright Inria, 2026
 */

#include <string.h>

#include "soft_f25519.h"
#include "x25519.h"

//=========================== private ==========================================

/* Double an X-coordinate (explicit formulas database: dbl-1987-m). */
static void _xc_double(uint8_t *x3, uint8_t *z3, const uint8_t *x1, const uint8_t *z1) {
    uint8_t x1sq[F25519_SIZE];
    uint8_t z1sq[F25519_SIZE];
    uint8_t x1z1[F25519_SIZE];
    uint8_t a[F25519_SIZE];

    f25519_mul__distinct(x1sq, x1, x1);
    f25519_mul__distinct(z1sq, z1, z1);
    f25519_mul__distinct(x1z1, x1, z1);

    f25519_sub(a, x1sq, z1sq);
    f25519_mul__distinct(x3, a, a);

    f25519_mul_c(a, x1z1, 486662);
    f25519_add(a, x1sq, a);
    f25519_add(a, z1sq, a);
    f25519_mul__distinct(x1sq, x1z1, a);
    f25519_mul_c(z3, x1sq, 4);
}

/* Differential addition (explicit formulas database: dbl-1987-m3). */
static void _xc_diffadd(uint8_t *x5, uint8_t *z5,
    const uint8_t *x1, const uint8_t *z1,
    const uint8_t *x2, const uint8_t *z2,
    const uint8_t *x3, const uint8_t *z3) {
    uint8_t da[F25519_SIZE];
    uint8_t cb[F25519_SIZE];
    uint8_t a[F25519_SIZE];
    uint8_t b[F25519_SIZE];

    f25519_add(a, x2, z2);
    f25519_sub(b, x3, z3);
    f25519_mul__distinct(da, a, b);

    f25519_sub(b, x2, z2);
    f25519_add(a, x3, z3);
    f25519_mul__distinct(cb, a, b);

    f25519_add(a, da, cb);
    f25519_mul__distinct(b, a, a);
    f25519_mul__distinct(x5, z1, b);

    f25519_sub(a, da, cb);
    f25519_mul__distinct(b, a, a);
    f25519_mul__distinct(z5, x1, b);
}

static void _projective_ladder(uint8_t *xm, uint8_t *zm, uint8_t *xm1, uint8_t *zm1, const uint8_t *q, const uint8_t *e) {
    /* Note: bit 254 is assumed to be 1 (guaranteed by clamping in crypto_x25519). */
    f25519_copy(xm, q);

    for (int i = 253; i >= 0; i--) {
        const int bit = (e[i >> 3] >> (i & 7)) & 1;
        uint8_t   xms[F25519_SIZE];
        uint8_t   zms[F25519_SIZE];

        /* From P_m and P_(m-1), compute P_(2m) and P_(2m-1) */
        _xc_diffadd(xm1, zm1, q, f25519_one, xm, zm, xm1, zm1);
        _xc_double(xm, zm, xm, zm);

        /* Compute P_(2m+1) */
        _xc_diffadd(xms, zms, xm1, zm1, xm, zm, q, f25519_one);

        /* Select: bit=1 --> (P_(2m+1), P_(2m)); bit=0 --> (P_(2m), P_(2m-1)) */
        f25519_select(xm1, xm1, xm, bit);
        f25519_select(zm1, zm1, zm, bit);
        f25519_select(xm, xm, xms, bit);
        f25519_select(zm, zm, zms, bit);
    }
}

/* X-coordinate-only scalar multiply: given the X-coordinate of q, return the
 * X-coordinate of e*q. e must already be clamped (see crypto_x25519). */
static void _c25519_smult(uint8_t *result, const uint8_t *q, const uint8_t *e) {
    uint8_t xm[F25519_SIZE];
    uint8_t zm[F25519_SIZE]  = { 1 };
    uint8_t xm1[F25519_SIZE] = { 1 };
    uint8_t zm1[F25519_SIZE] = { 0 };

    _projective_ladder(xm, zm, xm1, zm1, q, e);

    /* Freeze out of projective coordinates */
    f25519_inv__distinct(zm1, zm);
    f25519_mul__distinct(result, zm1, xm);
    f25519_normalize(result);
}

//=========================== public ============================================

void crypto_x25519(uint8_t shared_secret[X25519_KEY_SIZE], const uint8_t private_key[X25519_KEY_SIZE], const uint8_t peer_public_key[X25519_KEY_SIZE]) {
    // RFC 7748 clamping, applied to a local scratch copy -- the stored private
    // key stays the raw/unclamped form (same convention as the reference
    // cryptography library used by generate_craft_keys.py, which clamps
    // internally at exchange() time rather than storing a pre-clamped key).
    // Clamping is idempotent, so this is bit-for-bit interoperable either way.
    uint8_t clamped[X25519_KEY_SIZE];
    memcpy(clamped, private_key, X25519_KEY_SIZE);
    clamped[0]  &= 0xf8;
    clamped[31] &= 0x7f;
    clamped[31] |= 0x40;

    _c25519_smult(shared_secret, peer_public_key, clamped);
}
