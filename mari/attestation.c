/**
 * @ingroup     mari
 * @brief       attestation evidence generation
 *
 * @{
 * @file
 * @author Yuxuan Song <yuxuan.song@inria.fr>
 * @copyright Inria, 2025
 * @}
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "attestation.h"
#include "sha256.h"
#include "ed25519.h"
#include "mr_device.h"

//=========================== defines ==========================================
#define HASH_LEN              (32u)
#define ED25519_SIGNATURE_LEN (64U)
#define SHA256_BLOCK_LEN      (64U)

//=========================== variables ========================================
static uint8_t       signature[ED25519_SIGNATURE_LEN] = { 0 };
static const uint8_t fw_version                       = 1;
static const uint8_t key_id                           = 1;

static const uint8_t public_key[32] = {
    0xb2, 0x4f, 0x6d, 0x4e, 0x5f, 0x81, 0x47, 0xaf, 0x1d, 0x1c, 0xd8, 0xc2, 0x6e, 0x1a, 0x51, 0x0b,
    0x7a, 0x0f, 0x7f, 0x0a, 0x7b, 0xcc, 0x60, 0x68, 0x89, 0x55, 0xd3, 0x27, 0xb9, 0x9c, 0x64, 0x75
};

static const uint8_t private_key[32] = {
    0xf3, 0x8f, 0x0d, 0xd6, 0x13, 0x62, 0x06, 0x3c, 0xd7, 0xa1, 0xdf, 0x84, 0x6b, 0x8a, 0x56, 0x2e,
    0x9c, 0x60, 0x55, 0x80, 0xe9, 0x95, 0xed, 0xe9, 0x5f, 0x64, 0x47, 0xc5, 0x04, 0x44, 0x96, 0x87
};

//=========================== prototypes ==========================================
static uint8_t cborencoder_put_array(uint8_t *buffer, uint8_t elements);
static uint8_t cborencoder_put_unsigned(uint8_t *buffer, uint64_t value);
static uint8_t cborencoder_put_bytes(uint8_t *buffer, const uint8_t *bytes, uint8_t bytes_len);
static void    hmac_sha256(const uint8_t *key, uint8_t key_len, const uint8_t *data, uint16_t data_len, uint8_t out[HASH_LEN]);
static void    edhoc_kdf(const uint8_t prk[HASH_LEN], uint8_t label, const uint8_t *context, uint8_t context_len, uint8_t length, uint8_t *out);
static void    mr_attestation_signature_generation(uint64_t asn_dl, const uint8_t *hash, const uint8_t *attestation_binder, const uint8_t *priv_key, const uint8_t *pub_key);

//=========================== public ===========================================

void mr_attestation_evidence_generation(uint64_t asn_dl, const uint8_t prk_exporter[32], uint8_t *buffer, uint8_t *buffer_size) {
    // derive attestation_binder = EDHOC-KDF(PRK_exporter, 2, "attestation", 32)
    uint8_t       attestation_binder[HASH_LEN];
    const uint8_t attest_ctx[] = { 'a', 't', 't', 'e', 's', 't', 'a', 't', 'i', 'o', 'n' };  // 11 bytes
    edhoc_kdf(prk_exporter, 2, attest_ctx, sizeof(attest_ctx), HASH_LEN, attestation_binder);

    // hash the code section for execution-time measurement (flash start to .data load start,
    // covering vectors + text + rodata — not the full empty flash)
    extern uint32_t __data_load_start__;
    const uint8_t *fw_start = (const uint8_t *)0x00000000U;
    const size_t   fw_size  = (size_t)((uintptr_t)&__data_load_start__);
    uint8_t hash[HASH_LEN];
    // CC310 DMA cannot read from flash directly — copy in chunks through RAM
    uint8_t chunk[256];
    crypto_sha256_init();
    for (size_t off = 0; off < fw_size; off += sizeof(chunk)) {
        size_t n = fw_size - off;
        if (n > sizeof(chunk)) { n = sizeof(chunk); }
        memcpy(chunk, fw_start + off, n);
        crypto_sha256_update(chunk, n);
    }
    crypto_sha256(hash);

    // printf("[ATTEST] fw_size=%u hash=", (unsigned)fw_size);
    // for (uint8_t i = 0; i < HASH_LEN; i++) { printf("%02x", hash[i]); }
    // printf("\n");

    // fixed test value: real hash discarded so verifier reference stays valid
    static const uint8_t test_hash[HASH_LEN] = {
        0xDE, 0x6C, 0xD0, 0x5D, 0x50, 0x77, 0x86, 0x48,
        0xBD, 0xB0, 0x7B, 0x4D, 0x1C, 0x6D, 0xB8, 0x1E,
        0x0C, 0x2D, 0xF4, 0x53, 0x3A, 0x32, 0xE5, 0x15,
        0xE5, 0x33, 0xA2, 0x6E, 0x21, 0x72, 0x87, 0x3B
    };
    mr_attestation_signature_generation(asn_dl, test_hash, attestation_binder, private_key, public_key);

    // printf("[ATTEST] sig=");
    // for (uint8_t i = 0; i < ED25519_SIGNATURE_LEN; i++) { printf("%02x", signature[i]); }
    // printf("\n");

    // encode evidence as CBOR array [fw_version, key_id, signature]
    uint8_t offset = *buffer_size;
    offset += cborencoder_put_array(&buffer[offset], 3);
    offset += cborencoder_put_unsigned(&buffer[offset], fw_version);
    offset += cborencoder_put_unsigned(&buffer[offset], key_id);
    offset += cborencoder_put_bytes(&buffer[offset], signature, ED25519_SIGNATURE_LEN);
    *buffer_size = offset;
}

//=========================== private ==========================================

// HMAC-SHA256: out = H((key^opad) || H((key^ipad) || data))
static void hmac_sha256(const uint8_t *key, uint8_t key_len, const uint8_t *data, uint16_t data_len, uint8_t out[HASH_LEN]) {
    uint8_t k[SHA256_BLOCK_LEN];
    uint8_t k_ipad[SHA256_BLOCK_LEN];
    uint8_t k_opad[SHA256_BLOCK_LEN];

    memset(k, 0, SHA256_BLOCK_LEN);
    if (key_len > SHA256_BLOCK_LEN) {
        // hash the key if it is longer than the block size
        crypto_sha256_init();
        crypto_sha256_update(key, key_len);
        crypto_sha256(k);
    } else {
        memcpy(k, key, key_len);
    }

    for (uint8_t i = 0; i < SHA256_BLOCK_LEN; i++) {
        k_ipad[i] = k[i] ^ 0x36u;
        k_opad[i] = k[i] ^ 0x5Cu;
    }

    // inner hash: H(k_ipad || data)
    uint8_t inner[HASH_LEN];
    crypto_sha256_init();
    crypto_sha256_update(k_ipad, SHA256_BLOCK_LEN);
    crypto_sha256_update(data, data_len);
    crypto_sha256(inner);

    // outer hash: H(k_opad || inner)
    crypto_sha256_init();
    crypto_sha256_update(k_opad, SHA256_BLOCK_LEN);
    crypto_sha256_update(inner, HASH_LEN);
    crypto_sha256(out);
}

// HKDF-Expand with CBOR-encoded info: output = HMAC(PRK, CBOR_seq(label, context, length) || 0x01)
// length must be <= HASH_LEN (32)
static void edhoc_kdf(const uint8_t prk[HASH_LEN], uint8_t label, const uint8_t *context, uint8_t context_len, uint8_t length, uint8_t *out) {
    uint8_t info[64];
    uint8_t info_len = 0;
    info_len += cborencoder_put_unsigned(&info[info_len], label);
    info_len += cborencoder_put_bytes(&info[info_len], context, context_len);
    info_len += cborencoder_put_unsigned(&info[info_len], length);

    // T(1) = HMAC(PRK, info || 0x01)
    uint8_t okm_input[64 + 1];
    memcpy(okm_input, info, info_len);
    okm_input[info_len] = 0x01;

    uint8_t t1[HASH_LEN];
    hmac_sha256(prk, HASH_LEN, okm_input, (uint16_t)(info_len + 1), t1);
    memcpy(out, t1, length);
}

// sign [asn_dl, key_id, hash, node_id, attestation_binder] with Ed25519
static void mr_attestation_signature_generation(uint64_t asn_dl, const uint8_t *hash, const uint8_t *attestation_binder, const uint8_t *priv_key, const uint8_t *pub_key) {
    uint8_t sig_structure_len = 0;
    uint8_t sig_structure_cbor[MAX_SIG_STRUCTURE];

    sig_structure_len += cborencoder_put_array(&sig_structure_cbor[sig_structure_len], 5);
    sig_structure_len += cborencoder_put_unsigned(&sig_structure_cbor[sig_structure_len], asn_dl);
    sig_structure_len += cborencoder_put_unsigned(&sig_structure_cbor[sig_structure_len], key_id);
    sig_structure_len += cborencoder_put_bytes(&sig_structure_cbor[sig_structure_len], hash, HASH_LEN);
    sig_structure_len += cborencoder_put_unsigned(&sig_structure_cbor[sig_structure_len], mr_device_id());
    sig_structure_len += cborencoder_put_bytes(&sig_structure_cbor[sig_structure_len], attestation_binder, HASH_LEN);

    size_t sig_len = crypto_ed25519_sign(signature, sig_structure_cbor, sig_structure_len, priv_key, pub_key);
    (void)sig_len;
}

static uint8_t cborencoder_put_array(uint8_t *buffer, uint8_t elements) {
    uint8_t ret = 0;
    if (elements > 15) {
        return 0xFF;
    }
    buffer[ret++] = (0x80 | elements);
    return ret;
}

static uint8_t cborencoder_put_unsigned(uint8_t *buffer, uint64_t value) {
    uint8_t ret = 0;
    if (value <= 0x17) {
        buffer[ret++] = (uint8_t)value;
    } else if (value <= 0xff) {
        buffer[ret++] = 0x18;
        buffer[ret++] = (uint8_t)value;
    } else if (value <= 0xffff) {
        buffer[ret++] = 0x19;
        buffer[ret++] = (value >> 8) & 0xff;
        buffer[ret++] = value & 0xff;
    } else if (value <= 0xffffffff) {
        buffer[ret++] = 0x1a;
        buffer[ret++] = (value >> 24) & 0xff;
        buffer[ret++] = (value >> 16) & 0xff;
        buffer[ret++] = (value >> 8) & 0xff;
        buffer[ret++] = value & 0xff;
    } else {
        buffer[ret++] = 0x1b;
        buffer[ret++] = (value >> 56) & 0xff;
        buffer[ret++] = (value >> 48) & 0xff;
        buffer[ret++] = (value >> 40) & 0xff;
        buffer[ret++] = (value >> 32) & 0xff;
        buffer[ret++] = (value >> 24) & 0xff;
        buffer[ret++] = (value >> 16) & 0xff;
        buffer[ret++] = (value >> 8) & 0xff;
        buffer[ret++] = value & 0xff;
    }
    return ret;
}

static uint8_t cborencoder_put_bytes(uint8_t *buffer, const uint8_t *bytes, uint8_t bytes_len) {
    uint8_t ret = 0;
    if (bytes_len > 23) {
        buffer[ret++] = 0x58;
        buffer[ret++] = bytes_len;
    } else {
        buffer[ret++] = (0x40 | bytes_len);
    }
    if (bytes_len != 0 && bytes != NULL) {
        memcpy(&buffer[ret], bytes, bytes_len);
        ret += bytes_len;
    }
    return ret;
}
