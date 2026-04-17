/**
 * @file
 * @ingroup     app
 *
 * @brief       Mari Gateway application example
 *
 * @author Geovane Fedrecheski <geovane.fedrecheski@inria.fr>
 *
 * @copyright Inria, 2025
 */
#include <nrf.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>

#include "mr_gpio.h"
#include "mr_timer_hf.h"

//=========================== defines ==========================================

#define BLOOM_M_BITS   1024
#define BLOOM_M_BYTES  (BLOOM_M_BITS / 8)
#define BLOOM_K_HASHES 3

#define MARI_APP_TIMER_DEV 1
#define NODES_MAX          101
#define NODES_LEN          101  // number of nodes to actually test the filter against

//=========================== variables ==========================================

// clang-format off
uint64_t nodes[NODES_MAX] = {
    0x66b6ce28d5f79f9d, 0x7e3e2fa977053dbd, 0xa9464aa41e476850, 0xc3392ba31b942960,
    0xf6366a989412c4a2, 0xe15eb948f01628f5, 0x8134acdc4d850865, 0x50fe0f61b2c89138,
    0x33b01f0eb8f32556, 0xfd6f4778fa206d98, 0xcc5e612c52f7a464, 0x83977e67a587f525,
    0x723d07546f2958e5, 0x9445a073bca2da7d, 0xdc6ed7ef37fb3919, 0xdf02d664d07cf519,
    0x68e477dccc3d598f, 0x340fbf0827a073b4, 0x1d3966c4bee827b8, 0xa5ebeaba8978173e,
    0x12845f13999b4b85, 0x0327b36641ebf756, 0xb9a00738924c70b3, 0x3dce552ee2504b16,
    0xf8c7c934b13fa530, 0x39efb532d39883e0, 0xb702949822d9b122, 0x0f10066835ce9dd8,
    0x520ab73a6bf4c1c7, 0xc494a23523080645, 0xb39087f19cb0926c, 0x40fe9899738c20bb,
    0x4b9a55ca0d9002a3, 0xafe0f00d6dd55d7b, 0x87a06e457686c10c, 0x20e2179128c51f01,
    0x32a08b32cd16dd64, 0xcfc22a4a4eb5f318, 0xbcdfaa95f3e15324, 0x41d999ea99b32281,
    0xeb7db59d687fc4f8, 0x480d6c3ebdeee35e, 0x3cb796e45459792c, 0xd05db3a40dc4fd47,
    0x7d58e94532d5b89e, 0x287f0ed0ad6af8de, 0x18fde1f5f33213c2, 0x4f4cc2b496d348b6,
    0x1e236afcc5684b49, 0x1353391ad81c35c0, 0xac8844364fe8337d, 0x1ef8a50729cf761f,
    0x285537522fac8e99, 0x266be8c4ce14f0e9, 0xa701426686015699, 0x89679e13043e3305,
    0x125628733feb3291, 0x552e4e334efb52a0, 0x5688a6082ece2721, 0xb04dd44504411224,
    0x21e3e255b5cb6731, 0x348e71248c561e15, 0x3a50c2f35430ee1f, 0x24abc63f5adb63f9,
    0x0ae0a47f2d32376d, 0x578bc360c815d794, 0xaac18029c8ce1231, 0x9ce2fdf3e68b1fb3,
    0x4d856a4a7cddb340, 0x3899d3a86d9b5342, 0x6f64c6ede8bf8e1b, 0xf9975e1856d85129,
    0xaa4bef1c10c4590c, 0xf9d42633fee25e08, 0xefe6bc3eb44e8857, 0xc675461cb075bc95,
    0xae25616b3ffdb037, 0x2afd50fcd9595f05, 0xfdc6ef8167c205b7, 0xc10b4dfb5c670d33,
    0x6c54fca4239f37cd, 0x16e24e32ae5a6b99, 0xe4526146e0c52cad, 0x0dd1bfcebc5ec5d5,
    0x38709bb504b2dd48, 0x3f872cb2184b2a8c, 0x9074ae9afbb350d4, 0x4d555173ada88582,
    0x9976197f8dc99000, 0x4d10504373a198e5, 0xa3b52cd833d3169c, 0x99d9c043335a2e78,
    0x16163f11d4d0a8ab, 0xed7842f285d0018f, 0x667b6848fe3c0b82, 0x73507722ba719faf,
    0x53f1770e59755fc6, 0xb36a6a60fd5dd751, 0xcf88c87179119062, 0x41140562c6dddcc9,
};
// clang-format on

mr_gpio_t pin2 = { .port = 1, .pin = 4 };
mr_gpio_t pin3 = { .port = 1, .pin = 5 };

//=========================== functions ==========================================

// FNV-1a 64-bit hash
static __attribute__((unused)) uint64_t fnv1a64(uint64_t input) {
    uint64_t hash = 0xcbf29ce484222325ULL;
    for (int b = 0; b < 8; b++) {
        uint8_t byte = (input >> (56 - b * 8)) & 0xFF;
        hash ^= byte;
        hash *= 0x100000001b3ULL;
    }
    return hash;
}

// Thomas Wang’s 64-bit mix hash
static inline __attribute__((unused)) uint64_t mix64(uint64_t x) {
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ULL;
    x ^= x >> 33;
    return x;
}

void mr_scheduler_gateway_gen_bloom_from_list(uint64_t *nodes, size_t count, uint8_t *bloom_output) {
    (void)bloom_output;
    // mr_gpio_set(&pin2);
    memset(bloom_output, 0, BLOOM_M_BYTES);
    // mr_gpio_clear(&pin2);  // 16.7 us in DEBUG

    // f*ck off warnings!
    uint64_t idx = 0;
    (void)idx;
    uint64_t id, h1, h2;
    (void)id;
    (void)h1;
    (void)h2;

    // benchmark the differnt steps, separately
    id = nodes[0];
    mr_gpio_set(&pin3);
    h1 = fnv1a64(id);
    h2 = fnv1a64(id ^ 0x5bd1e995);
    (void)h1;
    (void)h2;
    mr_gpio_clear(&pin3);  // 15.9 us in DEBUG

    mr_gpio_set(&pin3);
    for (int k = 0; k < BLOOM_K_HASHES; k++) {
        // uint64_t idx = (h1 + k * h2) % BLOOM_M_BITS;
        idx = (h1 + k * h2) & (BLOOM_M_BITS - 1);  // Fast bitmask instead of division
        bloom_output[idx / 8] |= (1 << (idx % 8));
    }
    mr_gpio_clear(&pin3);  // 2.65 us in DEBUG

    // benchmark the whole loop
    mr_gpio_set(&pin2);
    for (size_t i = 0; i < count; i++) {
        id = nodes[i];
        (void)id;

        h1 = fnv1a64(id);
        h2 = fnv1a64(id ^ 0x5bd1e995);
        (void)h1;
        (void)h2;

        for (int k = 0; k < BLOOM_K_HASHES; k++) {
            // uint64_t idx = (h1 + k * h2) % BLOOM_M_BITS;
            idx = (h1 + k * h2) & (BLOOM_M_BITS - 1);  // Fast bitmask instead of division
            bloom_output[idx / 8] |= (1 << (idx % 8));
        }
    }
    mr_gpio_clear(&pin2);  // 1749 us in DEBUG
}

bool mr_scheduler_node_bloom_contains(uint64_t node_id, const uint8_t *bloom) {
    uint64_t h1 = fnv1a64(node_id);
    uint64_t h2 = fnv1a64(node_id ^ 0x5bd1e995);

    for (int k = 0; k < BLOOM_K_HASHES; k++) {
        uint64_t idx = (h1 + k * h2) % BLOOM_M_BITS;
        if ((bloom[idx / 8] & (1 << (idx % 8))) == 0) {
            return false;
        }
    }
    return true;
}

//============================ main ============================================

int main(void) {
    printf("Test Mari Bloom\n");
    mr_timer_hf_init(MARI_APP_TIMER_DEV);
    mr_gpio_init(&pin2, MR_GPIO_OUT);
    mr_gpio_init(&pin3, MR_GPIO_OUT);

    uint8_t  bloom[BLOOM_M_BYTES];
    uint32_t now_ts, elapsed_ts;

    now_ts = mr_timer_hf_now(MARI_APP_TIMER_DEV);
    mr_scheduler_gateway_gen_bloom_from_list(nodes, NODES_LEN, bloom);
    elapsed_ts = mr_timer_hf_now(MARI_APP_TIMER_DEV) - now_ts;
    printf("Bloom of %d bytes generated in %d us\n", BLOOM_M_BYTES, elapsed_ts);

    size_t len_test = 10;  // NODES_LEN
    for (size_t i = 0; i < len_test; i++) {
        now_ts     = mr_timer_hf_now(MARI_APP_TIMER_DEV);
        bool found = mr_scheduler_node_bloom_contains(nodes[i], bloom);
        elapsed_ts = mr_timer_hf_now(MARI_APP_TIMER_DEV) - now_ts;
        // printf("Bloom tested in %d us\n", elapsed_ts);
        printf("Node %d = 0x%llX is %s in bloom  |  %d us\n", i, nodes[i], found ? "likely" : "NOT", elapsed_ts);
    }

    // Try a fake node
    uint64_t fake_node = 0xAAAAAAAAAAAAAAAA;
    now_ts             = mr_timer_hf_now(MARI_APP_TIMER_DEV);
    bool found         = mr_scheduler_node_bloom_contains(fake_node, bloom);
    elapsed_ts         = mr_timer_hf_now(MARI_APP_TIMER_DEV) - now_ts;
    // printf("Bloom tested in %d us\n", elapsed_ts);
    printf("Fake node 0x%llX is %s in bloom  |  %d us\n", fake_node, found ? "likely" : "NOT", elapsed_ts);

    // main loop
    while (1) {
        __SEV();
        __WFE();
        __WFE();
    }
}
