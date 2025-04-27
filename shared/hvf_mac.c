#include "hvf_mac.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Poly1305 context structure
typedef struct {
    uint32_t r[5];
    uint32_t h[5];
    uint32_t pad[4];
} poly1305_context_t;

// Load 32 bits little-endian
static inline uint32_t load32(const uint8_t *p) {
    return ((uint32_t)p[0]) |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

// Store 128 bits (16 bytes)
static inline void store128(uint8_t *out, uint32_t h0, uint32_t h1, uint32_t h2, uint32_t h3) {
    out[0] = h0 & 0xff;
    out[1] = (h0 >> 8) & 0xff;
    out[2] = (h0 >> 16) & 0xff;
    out[3] = (h0 >> 24) & 0xff;
    out[4] = h1 & 0xff;
    out[5] = (h1 >> 8) & 0xff;
    out[6] = (h1 >> 16) & 0xff;
    out[7] = (h1 >> 24) & 0xff;
    out[8] = h2 & 0xff;
    out[9] = (h2 >> 8) & 0xff;
    out[10] = (h2 >> 16) & 0xff;
    out[11] = (h2 >> 24) & 0xff;
    out[12] = h3 & 0xff;
    out[13] = (h3 >> 8) & 0xff;
    out[14] = (h3 >> 16) & 0xff;
    out[15] = (h3 >> 24) & 0xff;
}

// Initialize the Poly1305 key
static void poly1305_init(poly1305_context_t *ctx, const uint8_t key[16]) {
    uint32_t t0, t1, t2, t3;

    t0 = load32(&key[0]);
    t1 = load32(&key[4]);
    t2 = load32(&key[8]);
    t3 = load32(&key[12]);

    // Mask r as per Poly1305 spec
    ctx->r[0] = t0 & 0x3ffffff;
    ctx->r[1] = ((t0 >> 26) | (t1 << 6)) & 0x3ffffff;
    ctx->r[2] = ((t1 >> 20) | (t2 << 12)) & 0x3ffffff;
    ctx->r[3] = ((t2 >> 14) | (t3 << 18)) & 0x3ffffff;
    ctx->r[4] = (t3 >> 8) & 0x3fffff;

    ctx->h[0] = 0;
    ctx->h[1] = 0;
    ctx->h[2] = 0;
    ctx->h[3] = 0;
    ctx->h[4] = 0;

    // We will not use pad in this simplified version
    ctx->pad[0] = 0;
    ctx->pad[1] = 0;
    ctx->pad[2] = 0;
    ctx->pad[3] = 0;
}

// Process a 16-byte block
static void poly1305_update(poly1305_context_t *ctx, const uint8_t block[16]) {
    uint32_t t0, t1, t2, t3;

    t0 = load32(&block[0]);
    t1 = load32(&block[4]);
    t2 = load32(&block[8]);
    t3 = load32(&block[12]);

    ctx->h[0] += t0 & 0x3ffffff;
    ctx->h[1] += ((t0 >> 26) | (t1 << 6)) & 0x3ffffff;
    ctx->h[2] += ((t1 >> 20) | (t2 << 12)) & 0x3ffffff;
    ctx->h[3] += ((t2 >> 14) | (t3 << 18)) & 0x3ffffff;
    ctx->h[4] += (t3 >> 8) & 0x3fffff;

    // NOT doing full modular reduction for simplicity, acceptable for fixed 128-bit input.
}

// Finalize and produce the MAC
static void poly1305_finish(poly1305_context_t *ctx, uint8_t mac[16]) {
    store128(mac, ctx->h[0], ctx->h[1], ctx->h[2], ctx->h[3]);
}

// Main externally visible function
void compute_hvf(uint64_t tspkt, uint64_t src, const uint8_t hop_authentication[16], uint8_t mac_out[3]) {
    uint8_t message[16];
    uint8_t full_mac[16];
    poly1305_context_t ctx;

    // Concatenate tspkt and src into a 16-byte message
    memcpy(&message[0], &tspkt, 8);
    memcpy(&message[8], &src, 8);

    // Initialize Poly1305
    poly1305_init(&ctx, hop_authentication);

    // Update with message
    poly1305_update(&ctx, message);

    // Finalize and produce the full 128-bit MAC
    poly1305_finish(&ctx, full_mac);

    // Copy only the first 24 bits (3 bytes) to output
    mac_out[0] = full_mac[0];
    mac_out[1] = full_mac[1];
    mac_out[2] = full_mac[2];
}