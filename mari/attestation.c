/**
 * @ingroup     mari
 * @brief       attestation, only perform when the option 'attestation' is set
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

// #include "partition.h"
#include "attestation.h"
#include "mr_sha256.h"
#include "mr_ed25519.h"
#include "association.h"
#include "mac.h"
#include "mr_device.h"
//=========================== defines ==========================================
#define HASH_LEN                (32u)
#define ED25519_SIGNATURE_LEN   (64U)
#define ED25519_PRIVATE_KEY_LEN (32U)
#define ED25519_PUBLIC_KEY_LEN  (32U)

// evidence type, send from node
typedef struct {
    uint32_t fw_version;
    uint8_t  signature[ED25519_SIGNATURE_LEN];
} __attribute__((packed)) evidence_t;

// verification request type, send by gateway
typedef struct {
    uint8_t *evidence;
    uint8_t  evidence_len;
    uint64_t asn_ul;
    uint64_t asn_offset;
    uint64_t node_id;
} verification_request_t;

//=========================== variables ========================================
// temporary values
uint8_t  flag_attest         = 1;
uint32_t expected_fw_version = 1;

uint8_t hash[HASH_LEN] = { 0 };
// db_partitions_table_t _table = {0};
static uint8_t signature[ED25519_SIGNATURE_LEN] = { 0 };
uint8_t        fw_version                       = 1;
uint8_t        key_id                           = 1;
const uint8_t  public_key[32]                   = {
    0xb2, 0x4f, 0x6d, 0x4e, 0x5f, 0x81, 0x47, 0xaf, 0x1d, 0x1c, 0xd8, 0xc2, 0x6e, 0x1a, 0x51, 0x0b, 0x7a, 0x0f, 0x7f, 0x0a, 0x7b, 0xcc, 0x60, 0x68, 0x89, 0x55, 0xd3, 0x27, 0xb9, 0x9c, 0x64, 0x75
};

const uint8_t private_key[32] = {
    0xf3, 0x8f, 0x0d, 0xd6, 0x13, 0x62, 0x06, 0x3c, 0xd7, 0xa1, 0xdf, 0x84, 0x6b, 0x8a, 0x56, 0x2e, 0x9c, 0x60, 0x55, 0x80, 0xe9, 0x95, 0xed, 0xe9, 0x5f, 0x64, 0x47, 0xc5, 0x04, 0x44, 0x96, 0x87
};

//=========================== prototypes ==========================================
static uint8_t cborencoder_put_array(uint8_t *buffer, uint8_t elements);
static uint8_t cborencoder_put_unsigned(uint8_t *buffer, uint64_t value);
static uint8_t cborencoder_put_bytes(uint8_t *buffer, const uint8_t *bytes, uint8_t bytes_len);
static uint8_t cbor_decode_unsigned(uint8_t *buffer, uint32_t *value);
// static void mr_attestation_get_hashed_image (db_partitions_table_t* partition_table, uint8_t hash[HASH_LEN], uint32_t *image_size);
static void mr_attestation_get_hashed_image(uint8_t hash[HASH_LEN]);
static void mr_attestation_signature_generation(uint64_t asn_dl, uint8_t *hash, const uint8_t *private_key, const uint8_t *public_key);
static bool mr_attestation_check_fw_version(uint8_t *buffer, uint32_t expected_fw_version);
static void mr_attestation_verification_request(uint8_t *evidence, uint8_t evidence_len, uint64_t asn_dl, uint64_t asn_ul, uint64_t node_id, uint8_t *buffer, uint8_t *buffer_size);
//=========================== public ===========================================
void mr_attestation_evidence_generation(uint64_t asn_dl, uint8_t *buffer, uint8_t *buffer_size) {
    // uint32_t image_size;
    uint8_t offset = *buffer_size;
    mr_attestation_get_hashed_image(hash);
    // temporary: set a hash value for test
    uint8_t hash[HASH_LEN] = {
        0xDE, 0x6C, 0xD0, 0x5D, 0x50, 0x77, 0x86, 0x48,
        0xBD, 0xB0, 0x7B, 0x4D, 0x1C, 0x6D, 0xB8, 0x1E,
        0x0C, 0x2D, 0xF4, 0x53, 0x3A, 0x32, 0xE5, 0x15,
        0xE5, 0x33, 0xA2, 0x6E, 0x21, 0x72, 0x87,
        0x3B
        // 0x33
    };
    mr_attestation_signature_generation(asn_dl, hash, private_key, public_key);

    evidence_t evidence = {
        .fw_version = fw_version
    };
    memcpy(evidence.signature, signature, ED25519_SIGNATURE_LEN);

    // encode the evidence to cbor, order: firmware version, signature
    offset += cborencoder_put_array(&buffer[offset], 2);
    offset += cborencoder_put_unsigned(&buffer[offset], evidence.fw_version);
    offset += cborencoder_put_bytes(&buffer[offset], evidence.signature, ED25519_SIGNATURE_LEN);
    *buffer_size = offset;
}

bool mr_attestation_send_verif_req(uint8_t *packet, uint8_t *length) {
    mr_packet_header_t *header = (mr_packet_header_t *)packet;
    uint8_t            *ptr    = packet + sizeof(mr_packet_header_t);
    uint8_t             plen   = *length - sizeof(mr_packet_header_t);

    // check if it is attesting state
    if (mr_assoc_gateway_is_attesting(header->src)) {
        if (plen == 0 || ptr[0] != MARI_ATTEST_EVIDENCE_PAYLOAD_TAG) {
            return false;
        }
        uint8_t *evi     = ptr + 1;
        uint8_t  evi_len = plen - 1;

        if (!mr_attestation_check_fw_version(evi, expected_fw_version)) {
            return false;
        }

        uint64_t asn_ul = mr_mac_get_asn() - 1;
        uint64_t asn_dl = 0;
        mr_assoc_gateway_get_attest_dl_asn(header->src, &asn_dl);

        uint8_t vr_buf[MAX_VERIFICATION_REQUEST];
        uint8_t vr_len = 0;
        mr_attestation_verification_request(evi, evi_len, asn_dl, asn_ul, header->src, vr_buf, &vr_len);

        uint8_t *payload_ptr = packet + sizeof(mr_packet_header_t);
        memcpy(payload_ptr, vr_buf, vr_len);

        *length = vr_len + sizeof(mr_packet_header_t);
        return true;
    } else {
        // only not sending packet returns false, so here it is still true
        return true;
    }
}

//=========================== private ==========================================
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
        buffer[ret++] = value;
    } else if (value <= 0xff) {
        buffer[ret++] = 0x18;
        buffer[ret++] = value;
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

static uint8_t cbor_decode_unsigned(uint8_t *buffer, uint32_t *value) {
    uint8_t ret       = 0;
    uint8_t lead_byte = buffer[0];

    if (lead_byte <= 0x17) {
        *value = lead_byte;
        ret    = 1;
    } else if (lead_byte == 0x18) {
        *value = buffer[1];
        ret    = 2;
    } else if (lead_byte == 0x19) {
        *value = (buffer[1] << 8) | buffer[2];
        ret    = 3;
    } else if (lead_byte == 0x1a) {
        *value = (buffer[1] << 24) | (buffer[2] << 16) | (buffer[3] << 8) | buffer[4];
        ret    = 5;
    } else {
        ret = 0;
    }

    return ret;
}

/**
 * @brief get the hashed image value on active partition
 */
static void mr_attestation_get_hashed_image(uint8_t hash[HASH_LEN]) {

    // db_read_partitions_table(partition_table);

    // find the start of image, the size of the image
    // uint32_t image_address = partition_table->partitions[partition_table->active_image].address;
    // *image_size = partition_table->partitions[partition_table->active_image].size;
    uint32_t image_address = 0x00000000;
    uint32_t image_size    = 0x00100000;

    // initialize crypto
    crypto_sha256_init();
    crypto_sha256_update((uint8_t *)image_address, image_size);

    // finalize sha256
    crypto_sha256(hash);
}

/**
 * @brief generate the signature
 */
static void mr_attestation_signature_generation(uint64_t asn_dl, uint8_t *hash, const uint8_t *private_key, const uint8_t *public_key) {
    // construct sig_structure
    uint8_t sig_structure_len = 0;
    uint8_t sig_structure_cbor[MAX_SIG_STRUCTURE];
    // four elements for signature generation, order: asn_dl, key_id, hash, node_id
    sig_structure_len += cborencoder_put_array(&sig_structure_cbor[sig_structure_len], 4);
    sig_structure_len += cborencoder_put_unsigned(&sig_structure_cbor[sig_structure_len], asn_dl);
    sig_structure_len += cborencoder_put_unsigned(&sig_structure_cbor[sig_structure_len], key_id);
    sig_structure_len += cborencoder_put_bytes(&sig_structure_cbor[sig_structure_len], hash, HASH_LEN);
    sig_structure_len += cborencoder_put_unsigned(&sig_structure_cbor[sig_structure_len], mr_device_id());

    // sign the sig_structure
    size_t signature_len = crypto_ed25519_sign(signature, sig_structure_cbor, sig_structure_len, private_key, public_key);
    if (signature_len != ED25519_SIGNATURE_LEN) {
        printf("ERROR: signature_len");
    }
}

// gateway checks if the evidence firmware version is the expected one
static bool mr_attestation_check_fw_version(uint8_t *buffer, uint32_t expected_fw_version) {
    uint32_t decoded_fw_version;
    // jump to version value position
    uint8_t offset = 1;
    offset += cbor_decode_unsigned(buffer + offset, &decoded_fw_version);
    return (decoded_fw_version == expected_fw_version);
}

static void mr_attestation_verification_request(uint8_t *evidence, uint8_t evidence_len, uint64_t asn_dl, uint64_t asn_ul, uint64_t node_id, uint8_t *buffer, uint8_t *buffer_size) {
    // prepare the material to send to Verifier, order: asn_u, asn_offset, evidence, node_id
    *buffer_size += cborencoder_put_array(&buffer[*buffer_size], 4);
    *buffer_size += cborencoder_put_unsigned(&buffer[*buffer_size], asn_ul);
    *buffer_size += cborencoder_put_unsigned(&buffer[*buffer_size], asn_ul - asn_dl);
    *buffer_size += cborencoder_put_bytes(&buffer[*buffer_size], evidence, evidence_len);
    *buffer_size += cborencoder_put_unsigned(&buffer[*buffer_size], node_id);
}
