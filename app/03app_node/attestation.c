/**
 * @file
 * @ingroup     app
 * @brief       Related-work node attestation: COSE_Sign1 token generation with
 *              attestation_binder in external_aad of the Sig_Structure.
 *
 *
 * @author Yuxuan Song <yuxuan.song@inria.fr>
 * @copyright Inria, 2026
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "attestation.h"
#include "sha256.h"
#include "ed25519.h"
#include "C:/Users/yusong/Downloads/lakers/target/include/lakers.h"

//=========================== defines =========================================

#define ED25519_SIGNATURE_LEN   (64U)
#define SHA256_BLOCK_LEN        (64U)

#define IANA_CBOR_COSWID_FILE_HASH_IMAGE_KEY  7
#define IANA_CBOR_COSWID_FILE_KEY             17
#define IANA_CBOR_COSWID_TAG_VERSION_KEY      12
#define IANA_CBOR_COSWID_EVIDENCE_KEY         3
#define IANA_CBOR_EAT_UEID_KEY                256
#define IANA_CBOR_EAT_NONCE_KEY               10
#define IANA_CBOR_EAT_MEASUREMENTS_KEY        273
#define IANA_COAP_CONTENT_FORMATS_SWID        258
#define IANA_COSE_HEADER_PARAMETERS_ALG       1

// Same test Ed25519 key pair as mari/mari/attestation.c (verifier must use matching public key)
static const uint8_t _public_key[32] = {
    0xb2, 0x4f, 0x6d, 0x4e, 0x5f, 0x81, 0x47, 0xaf, 0x1d, 0x1c, 0xd8, 0xc2, 0x6e, 0x1a, 0x51, 0x0b,
    0x7a, 0x0f, 0x7f, 0x0a, 0x7b, 0xcc, 0x60, 0x68, 0x89, 0x55, 0xd3, 0x27, 0xb9, 0x9c, 0x64, 0x75
};

static const uint8_t _private_key[32] = {
    0xf3, 0x8f, 0x0d, 0xd6, 0x13, 0x62, 0x06, 0x3c, 0xd7, 0xa1, 0xdf, 0x84, 0x6b, 0x8a, 0x56, 0x2e,
    0x9c, 0x60, 0x55, 0x80, 0xe9, 0x95, 0xed, 0xe9, 0x5f, 0x64, 0x47, 0xc5, 0x04, 0x44, 0x96, 0x87
};

// Fixed test firmware hash (same as mari/mari/attestation.c for verifier compatibility)
static const uint8_t _test_hash[MAURA_HASH_LEN] = {
    0xDE, 0x6C, 0xD0, 0x5D, 0x50, 0x77, 0x86, 0x48,
    0xBD, 0xB0, 0x7B, 0x4D, 0x1C, 0x6D, 0xB8, 0x1E,
    0x0C, 0x2D, 0xF4, 0x53, 0x3A, 0x32, 0xE5, 0x15,
    0xE5, 0x33, 0xA2, 0x6E, 0x21, 0x72, 0x87, 0x3B
};

// ID_CRED_I = {4: h'\x01'} pre-encoded as CBOR map
static const uint8_t _id_cred_i_cbor[4] = {0xa1, 0x04, 0x41, 0x01};

//=========================== CBOR helpers ====================================

static uint8_t _cbor_put_array(uint8_t *buf, uint8_t n) {
    buf[0] = (uint8_t)(0x80u | n);
    return 1;
}

static uint8_t _cbor_put_unsigned(uint8_t *buf, unsigned long v) {
    if (v <= 0x17u) {
        buf[0] = (uint8_t)v;
        return 1;
    } else if (v <= 0xffu) {
        buf[0] = 0x18; buf[1] = (uint8_t)v;
        return 2;
    } else if (v <= 0xffffu) {
        buf[0] = 0x19; buf[1] = (uint8_t)(v >> 8); buf[2] = (uint8_t)v;
        return 3;
    } else {
        buf[0] = 0x1a;
        buf[1] = (uint8_t)(v >> 24); buf[2] = (uint8_t)(v >> 16);
        buf[3] = (uint8_t)(v >> 8);  buf[4] = (uint8_t)v;
        return 5;
    }
}

static uint8_t _cbor_put_negative(uint8_t *buf, int8_t v) {
    // only -1..-15 (v < 0)
    buf[0] = (uint8_t)(0x20u | (uint8_t)(-1 - v));
    return 1;
}

static uint8_t _cbor_put_bytes(uint8_t *buf, const uint8_t *data, uint8_t len) {
    uint8_t n = 0;
    if (len > 23) { buf[n++] = 0x58; buf[n++] = len; }
    else          { buf[n++] = (uint8_t)(0x40u | len); }
    if (len && data) { memcpy(&buf[n], data, len); n += len; }
    return n;
}

static uint8_t _cbor_put_text(uint8_t *buf, const char *s, uint8_t len) {
    uint8_t n = 0;
    if (len > 23) { buf[n++] = 0x78; buf[n++] = len; }
    else          { buf[n++] = (uint8_t)(0x60u | len); }
    if (len && s) { memcpy(&buf[n], s, len); n += len; }
    return n;
}

static uint8_t _cbor_put_map(uint8_t *buf, uint8_t n_elems) {
    buf[0] = (uint8_t)(0xa0u | n_elems);
    return 1;
}

//=========================== CBOR decoding helpers ===========================

static uint8_t _cbor_decode_uint(const uint8_t *buf, uint32_t *out) {
    uint8_t b = buf[0];
    if (b <= 0x17u)  { *out = b;                                                    return 1; }
    if (b == 0x18u)  { *out = buf[1];                                               return 2; }
    if (b == 0x19u)  { *out = ((uint32_t)buf[1] << 8) | buf[2];                    return 3; }
    if (b == 0x1au)  { *out = ((uint32_t)buf[1] << 24) | ((uint32_t)buf[2] << 16)
                              | ((uint32_t)buf[3] << 8)  | buf[4];                  return 5; }
    *out = 0; return 0;
}

static uint8_t _cbor_decode_bytes(const uint8_t *buf, uint8_t *out, uint8_t *len) {
    uint8_t b = buf[0];
    if (b >= 0x40u && b <= 0x57u) { *len = b - 0x40u; memcpy(out, &buf[1], *len); return 1 + *len; }
    if (b == 0x58u)                { *len = buf[1];    memcpy(out, &buf[2], *len); return 2 + *len; }
    *len = 0; return 0;
}

//=========================== HMAC-SHA256 / HKDF-Expand =======================

static void _hmac_sha256(const uint8_t *key, uint8_t klen, const uint8_t *data, uint16_t dlen, uint8_t out[MAURA_HASH_LEN]) {
    uint8_t k[SHA256_BLOCK_LEN];
    uint8_t ipad[SHA256_BLOCK_LEN];
    uint8_t opad[SHA256_BLOCK_LEN];
    memset(k, 0, SHA256_BLOCK_LEN);
    if (klen > SHA256_BLOCK_LEN) {
        crypto_sha256_init();
        crypto_sha256_update(key, klen);
        crypto_sha256(k);
    } else {
        memcpy(k, key, klen);
    }
    for (uint8_t i = 0; i < SHA256_BLOCK_LEN; i++) { ipad[i] = k[i] ^ 0x36u; opad[i] = k[i] ^ 0x5cu; }
    uint8_t inner[MAURA_HASH_LEN];
    crypto_sha256_init();
    crypto_sha256_update(ipad, SHA256_BLOCK_LEN);
    crypto_sha256_update(data, dlen);
    crypto_sha256(inner);
    crypto_sha256_init();
    crypto_sha256_update(opad, SHA256_BLOCK_LEN);
    crypto_sha256_update(inner, MAURA_HASH_LEN);
    crypto_sha256(out);
}

static void _hkdf_expand(const uint8_t prk[MAURA_HASH_LEN], const uint8_t *info, uint8_t info_len, uint8_t out[MAURA_HASH_LEN]) {
    uint8_t okm_input[128];
    memcpy(okm_input, info, info_len);
    okm_input[info_len] = 0x01u;
    _hmac_sha256(prk, MAURA_HASH_LEN, okm_input, (uint16_t)(info_len + 1), out);
}

//=========================== Attestation binder ==============================

/**
 * @brief Compute attestation_binder = HKDF-Expand(zero_32, CBOR[H_12, "attestation", ID_CRED_I], 32)
 *        where H_12 = SHA256(SHA256(msg1) || msg2).
 */
static void _compute_attestation_binder(uint8_t binder[MAURA_HASH_LEN],
                                         const uint8_t *msg1, uint8_t msg1_len,
                                         const uint8_t *msg2, uint8_t msg2_len) {
    // Step 1: H(msg1)
    uint8_t h_msg1[MAURA_HASH_LEN];
    crypto_sha256_init();
    crypto_sha256_update(msg1, msg1_len);
    crypto_sha256(h_msg1);

    // Step 2: H_12 = H(H(msg1) || msg2)
    uint8_t h12[MAURA_HASH_LEN];
    crypto_sha256_init();
    crypto_sha256_update(h_msg1, MAURA_HASH_LEN);
    crypto_sha256_update(msg2, msg2_len);
    crypto_sha256(h12);

    // Step 3: attest_info = CBOR [H_12, "attestation", ID_CRED_I_map]
    uint8_t attest_info[64];
    uint8_t ai = 0;
    ai += _cbor_put_array(&attest_info[ai], 3);
    ai += _cbor_put_bytes(&attest_info[ai], h12, MAURA_HASH_LEN);
    ai += _cbor_put_text(&attest_info[ai], "attestation", 11);
    memcpy(&attest_info[ai], _id_cred_i_cbor, sizeof(_id_cred_i_cbor));
    ai += sizeof(_id_cred_i_cbor);

    // Step 4: binder = HKDF-Expand(zero_32, attest_info, 32)
    uint8_t zero_key[MAURA_HASH_LEN] = {0};
    _hkdf_expand(zero_key, attest_info, ai, binder);
}

//=========================== COSE_Sign1 token generation =====================

static maura_attestation_status_t _encode_cose_headers(uint8_t *buf, uint8_t *sz,
                                                         uint8_t *ph_start, uint8_t *ph_end) {
    buf[0] = 0xd2; buf[1] = 0x84; buf[2] = 0x43;  // COSE_Sign1 tag, 4-elem array, 3-byte bstr
    *sz = 3;
    *ph_start = *sz;
    *sz += _cbor_put_map(&buf[*sz], 1);
    *sz += _cbor_put_unsigned(&buf[*sz], IANA_COSE_HEADER_PARAMETERS_ALG);
    *sz += _cbor_put_negative(&buf[*sz], -8);  // EdDSA
    *ph_end = *sz;
    *sz += _cbor_put_map(&buf[*sz], 0);  // empty unprotected header
    return MAURA_ATTEST_SUCCESS;
}

static maura_attestation_status_t _encode_token_payload(const uint8_t *nonce, uint8_t nonce_len,
                                                          uint8_t *pre_buf, uint8_t *pre_sz) {
    // {10: h'nonce', 256: "momo", 273: [[258, coswid]]}
    *pre_sz += _cbor_put_map(&pre_buf[*pre_sz], 3);
    *pre_sz += _cbor_put_unsigned(&pre_buf[*pre_sz], IANA_CBOR_EAT_NONCE_KEY);
    *pre_sz += _cbor_put_bytes(&pre_buf[*pre_sz], nonce, nonce_len);
    *pre_sz += _cbor_put_unsigned(&pre_buf[*pre_sz], IANA_CBOR_EAT_UEID_KEY);
    *pre_sz += _cbor_put_text(&pre_buf[*pre_sz], "momo", 4);
    *pre_sz += _cbor_put_unsigned(&pre_buf[*pre_sz], IANA_CBOR_EAT_MEASUREMENTS_KEY);
    *pre_sz += _cbor_put_array(&pre_buf[*pre_sz], 1);
    *pre_sz += _cbor_put_array(&pre_buf[*pre_sz], 2);
    *pre_sz += _cbor_put_unsigned(&pre_buf[*pre_sz], IANA_COAP_CONTENT_FORMATS_SWID);
    return MAURA_ATTEST_SUCCESS;
}

static maura_attestation_status_t _encode_measurements(uint8_t *pre_buf, uint8_t *pre_sz) {
    // coswid: {12: 0, 3: evidence}
    *pre_sz += _cbor_put_map(&pre_buf[*pre_sz], 2);
    *pre_sz += _cbor_put_unsigned(&pre_buf[*pre_sz], IANA_CBOR_COSWID_TAG_VERSION_KEY);
    *pre_sz += _cbor_put_unsigned(&pre_buf[*pre_sz], 0);
    *pre_sz += _cbor_put_unsigned(&pre_buf[*pre_sz], IANA_CBOR_COSWID_EVIDENCE_KEY);
    return MAURA_ATTEST_SUCCESS;
}

static maura_attestation_status_t _encode_evidence(const uint8_t *hash, uint8_t *pre_buf, uint8_t *pre_sz) {
    // evidence: {17: [{7: [1, h'hash']}]}
    *pre_sz += _cbor_put_map(&pre_buf[*pre_sz], 1);
    *pre_sz += _cbor_put_unsigned(&pre_buf[*pre_sz], IANA_CBOR_COSWID_FILE_KEY);
    *pre_sz += _cbor_put_array(&pre_buf[*pre_sz], 1);
    *pre_sz += _cbor_put_map(&pre_buf[*pre_sz], 1);
    *pre_sz += _cbor_put_unsigned(&pre_buf[*pre_sz], IANA_CBOR_COSWID_FILE_HASH_IMAGE_KEY);
    *pre_sz += _cbor_put_array(&pre_buf[*pre_sz], 2);
    *pre_sz += _cbor_put_unsigned(&pre_buf[*pre_sz], 1);  // sha-256
    *pre_sz += _cbor_put_bytes(&pre_buf[*pre_sz], hash, MAURA_HASH_LEN);
    return MAURA_ATTEST_SUCCESS;
}

static maura_attestation_status_t _sign(uint8_t *token_buf, uint8_t *token_sz,
                                         uint8_t ph_start, uint8_t ph_end,
                                         uint8_t payload_start,
                                         const uint8_t *binder) {
    // Sig_Structure = ["Signature1", h'protected', h'binder', h'payload']
    uint8_t ss[MAURA_MAX_TOKEN];
    uint8_t ss_len = 0;
    ss_len += _cbor_put_array(&ss[ss_len], 4);
    ss_len += _cbor_put_text(&ss[ss_len], "Signature1", 10);

    uint8_t ph_len = ph_end - ph_start;
    ss_len += _cbor_put_bytes(&ss[ss_len], &token_buf[ph_start], ph_len);

    // external_aad = attestation binder (32 bytes as bstr)
    ss_len += _cbor_put_bytes(&ss[ss_len], binder, MAURA_HASH_LEN);

    // payload (everything from payload_start to current token_sz)
    uint8_t payload_len = *token_sz - payload_start;
    memcpy(&ss[ss_len], &token_buf[payload_start], payload_len);
    ss_len += payload_len;

    uint8_t sig[ED25519_SIGNATURE_LEN];
    size_t  sig_len = crypto_ed25519_sign(sig, ss, ss_len, _private_key, _public_key);
    if (sig_len != ED25519_SIGNATURE_LEN) { return MAURA_ATTEST_ERROR_SIGNATURE; }

    *token_sz += _cbor_put_bytes(&token_buf[*token_sz], sig, ED25519_SIGNATURE_LEN);
    return MAURA_ATTEST_SUCCESS;
}

/**
 * @brief Generate a COSE_Sign1 token with attestation_binder in external_aad.
 *
 * @param nonce      8-byte nonce from verifier.
 * @param binder     32-byte attestation_binder.
 * @param token_buf  Output buffer (must be >= MAURA_MAX_TOKEN bytes).
 * @param token_sz   Output token length.
 */
static maura_attestation_status_t _generate_token(const uint8_t *nonce, uint8_t nonce_len,
                                                    const uint8_t *binder,
                                                    uint8_t *token_buf, uint8_t *token_sz) {
    *token_sz = 0;
    uint8_t ph_start = 0, ph_end = 0;
    _encode_cose_headers(token_buf, token_sz, &ph_start, &ph_end);

    uint8_t payload_start = *token_sz;
    uint8_t pre_buf[MAURA_MAX_TOKEN];
    uint8_t pre_sz = 0;
    _encode_token_payload(nonce, nonce_len, pre_buf, &pre_sz);
    _encode_measurements(pre_buf, &pre_sz);
    _encode_evidence(_test_hash, pre_buf, &pre_sz);

    *token_sz += _cbor_put_bytes(&token_buf[*token_sz], pre_buf, pre_sz);

    return _sign(token_buf, token_sz, ph_start, ph_end, payload_start, binder);
}

//=========================== public ==========================================

uint8_t maura_decode_ead_2(const uint8_t *buf, uint32_t *ev_type, uint8_t *nonce, uint8_t *nonce_len) {
    uint8_t idx = 0;
    if (buf[idx++] != 0x82) { return (uint8_t)-1; }  // expect array(2)
    idx += _cbor_decode_uint(&buf[idx], ev_type);
    idx += _cbor_decode_bytes(&buf[idx], nonce, nonce_len);
    return 0;
}

void maura_prepare_ead_1(EADItemC *ead, uint8_t label, bool is_critical) {
    ead->label       = label;
    ead->is_critical = is_critical;
    uint8_t n = 0;
    n += _cbor_put_array(&ead->value.content[n], 1);
    n += _cbor_put_unsigned(&ead->value.content[n], MAURA_PROVIDED_EVIDENCE_TYPE);
    ead->value.len = n;
}

void maura_prepare_ead_3(EADItemC *ead_3, uint8_t label, bool is_critical,
                           const uint8_t *nonce, uint8_t nonce_len,
                           const uint8_t *msg1, uint8_t msg1_len,
                           const uint8_t *msg2, uint8_t msg2_len) {
    ead_3->label       = label;
    ead_3->is_critical = is_critical;

    uint8_t binder[MAURA_HASH_LEN];
    _compute_attestation_binder(binder, msg1, msg1_len, msg2, msg2_len);

    uint8_t token_sz = 0;
    maura_attestation_status_t st =
        _generate_token(nonce, nonce_len, binder, ead_3->value.content, &token_sz);
    ead_3->value.len = token_sz;
    if (st != MAURA_ATTEST_SUCCESS) {
        printf("[MAURA] Token generation failed: %d\n", (int)st);
    }
}
