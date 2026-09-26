/*
 * SpaceCopVPN native crypto: ChaCha20-Poly1305 AEAD (RFC 8439) in portable C.
 *
 * This is the data-path hot spot of the VPN.  The pure-Python implementation
 * in spacecop/crypto/ stays as the reference and the fallback; this file is
 * the same algorithms written for speed, loaded through ctypes when a build
 * is available (see spacecop/crypto/native.py).  No dependencies beyond the
 * C standard library; builds with gcc/clang/MSVC/NDK.
 *
 * Build:  gcc -O3 -fPIC -shared -o libspacecop_crypto.so spacecop_crypto.c
 *         (native/build.sh does this for the current platform)
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if defined(_WIN32)
#  define SC_EXPORT __declspec(dllexport)
#else
#  define SC_EXPORT __attribute__((visibility("default")))
#endif

#define SC_VERSION "0.3.2"

/* ------------------------------------------------------------------ utils */

static inline uint32_t load32_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void store32_le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static inline void store64_le(uint8_t *p, uint64_t v) {
    store32_le(p, (uint32_t)v);
    store32_le(p + 4, (uint32_t)(v >> 32));
}

static inline uint32_t rotl32(uint32_t v, int c) {
    return (v << c) | (v >> (32 - c));
}

/* Best-effort secure wipe: volatile pointer so the compiler keeps the stores. */
static void wipe(void *p, size_t n) {
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}

/* --------------------------------------------------------------- ChaCha20 */

#define QR(a, b, c, d)                              \
    a += b; d ^= a; d = rotl32(d, 16);              \
    c += d; b ^= c; b = rotl32(b, 12);              \
    a += b; d ^= a; d = rotl32(d, 8);               \
    c += d; b ^= c; b = rotl32(b, 7);

static void chacha20_block(const uint32_t in[16], uint8_t out[64]) {
    uint32_t x[16];
    int i;
    memcpy(x, in, sizeof x);
    for (i = 0; i < 10; i++) {
        QR(x[0], x[4], x[8],  x[12])
        QR(x[1], x[5], x[9],  x[13])
        QR(x[2], x[6], x[10], x[14])
        QR(x[3], x[7], x[11], x[15])
        QR(x[0], x[5], x[10], x[15])
        QR(x[1], x[6], x[11], x[12])
        QR(x[2], x[7], x[8],  x[13])
        QR(x[3], x[4], x[9],  x[14])
    }
    for (i = 0; i < 16; i++) store32_le(out + 4 * i, x[i] + in[i]);
}

static void chacha20_init(uint32_t st[16], const uint8_t key[32], uint32_t counter, const uint8_t nonce[12]) {
    int i;
    st[0] = 0x61707865; st[1] = 0x3320646e; st[2] = 0x79622d32; st[3] = 0x6b206574;
    for (i = 0; i < 8; i++) st[4 + i] = load32_le(key + 4 * i);
    st[12] = counter;
    st[13] = load32_le(nonce);
    st[14] = load32_le(nonce + 4);
    st[15] = load32_le(nonce + 8);
}

/* out = in XOR keystream(key, counter, nonce).  in and out may alias. */
static void chacha20_xor(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12],
                         const uint8_t *in, size_t len, uint8_t *out) {
    uint32_t st[16];
    uint8_t ks[64];
    size_t i;
    chacha20_init(st, key, counter, nonce);
    while (len >= 64) {
        chacha20_block(st, ks);
        st[12]++;
        for (i = 0; i < 64; i++) out[i] = in[i] ^ ks[i];
        in += 64; out += 64; len -= 64;
    }
    if (len) {
        chacha20_block(st, ks);
        for (i = 0; i < len; i++) out[i] = in[i] ^ ks[i];
    }
    wipe(st, sizeof st);
    wipe(ks, sizeof ks);
}

/* --------------------------------------------------------------- Poly1305 */
/* 32-bit limb ("donna") arithmetic: h, r in radix 2^26, products in 64 bits. */

typedef struct {
    uint32_t r[5];
    uint32_t h[5];
    uint32_t pad[4];
    size_t   leftover;
    uint8_t  buffer[16];
    uint8_t  final;
} poly1305_state;

static void poly1305_init(poly1305_state *st, const uint8_t key[32]) {
    /* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
    st->r[0] = (load32_le(key +  0)     ) & 0x3ffffff;
    st->r[1] = (load32_le(key +  3) >> 2) & 0x3ffff03;
    st->r[2] = (load32_le(key +  6) >> 4) & 0x3ffc0ff;
    st->r[3] = (load32_le(key +  9) >> 6) & 0x3f03fff;
    st->r[4] = (load32_le(key + 12) >> 8) & 0x00fffff;
    st->h[0] = st->h[1] = st->h[2] = st->h[3] = st->h[4] = 0;
    st->pad[0] = load32_le(key + 16);
    st->pad[1] = load32_le(key + 20);
    st->pad[2] = load32_le(key + 24);
    st->pad[3] = load32_le(key + 28);
    st->leftover = 0;
    st->final = 0;
}

static void poly1305_blocks(poly1305_state *st, const uint8_t *m, size_t bytes) {
    const uint32_t hibit = st->final ? 0 : (1u << 24); /* 1 << 128 */
    uint32_t r0 = st->r[0], r1 = st->r[1], r2 = st->r[2], r3 = st->r[3], r4 = st->r[4];
    uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    uint32_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2], h3 = st->h[3], h4 = st->h[4];
    uint64_t d0, d1, d2, d3, d4;
    uint32_t c;

    while (bytes >= 16) {
        /* h += m[i] */
        h0 += (load32_le(m +  0)     ) & 0x3ffffff;
        h1 += (load32_le(m +  3) >> 2) & 0x3ffffff;
        h2 += (load32_le(m +  6) >> 4) & 0x3ffffff;
        h3 += (load32_le(m +  9) >> 6) & 0x3ffffff;
        h4 += (load32_le(m + 12) >> 8) | hibit;

        /* h *= r */
        d0 = ((uint64_t)h0 * r0) + ((uint64_t)h1 * s4) + ((uint64_t)h2 * s3) + ((uint64_t)h3 * s2) + ((uint64_t)h4 * s1);
        d1 = ((uint64_t)h0 * r1) + ((uint64_t)h1 * r0) + ((uint64_t)h2 * s4) + ((uint64_t)h3 * s3) + ((uint64_t)h4 * s2);
        d2 = ((uint64_t)h0 * r2) + ((uint64_t)h1 * r1) + ((uint64_t)h2 * r0) + ((uint64_t)h3 * s4) + ((uint64_t)h4 * s3);
        d3 = ((uint64_t)h0 * r3) + ((uint64_t)h1 * r2) + ((uint64_t)h2 * r1) + ((uint64_t)h3 * r0) + ((uint64_t)h4 * s4);
        d4 = ((uint64_t)h0 * r4) + ((uint64_t)h1 * r3) + ((uint64_t)h2 * r2) + ((uint64_t)h3 * r1) + ((uint64_t)h4 * r0);

        /* (partial) h %= p */
                      c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff;
        d1 += c;      c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff;
        d2 += c;      c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff;
        d3 += c;      c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff;
        d4 += c;      c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff;
        h0 += c * 5;  c = h0 >> 26;             h0 &= 0x3ffffff;
        h1 += c;

        m += 16;
        bytes -= 16;
    }
    st->h[0] = h0; st->h[1] = h1; st->h[2] = h2; st->h[3] = h3; st->h[4] = h4;
}

static void poly1305_update(poly1305_state *st, const uint8_t *m, size_t bytes) {
    size_t i;
    if (st->leftover) {
        size_t want = 16 - st->leftover;
        if (want > bytes) want = bytes;
        for (i = 0; i < want; i++) st->buffer[st->leftover + i] = m[i];
        bytes -= want; m += want; st->leftover += want;
        if (st->leftover < 16) return;
        poly1305_blocks(st, st->buffer, 16);
        st->leftover = 0;
    }
    if (bytes >= 16) {
        size_t want = bytes & ~(size_t)15;
        poly1305_blocks(st, m, want);
        m += want; bytes -= want;
    }
    if (bytes) {
        for (i = 0; i < bytes; i++) st->buffer[st->leftover + i] = m[i];
        st->leftover += bytes;
    }
}

static void poly1305_finish(poly1305_state *st, uint8_t mac[16]) {
    uint32_t h0, h1, h2, h3, h4, c;
    uint32_t g0, g1, g2, g3, g4;
    uint64_t f;
    uint32_t mask;

    if (st->leftover) {
        size_t i = st->leftover;
        st->buffer[i++] = 1;
        for (; i < 16; i++) st->buffer[i] = 0;
        st->final = 1;
        poly1305_blocks(st, st->buffer, 16);
    }

    h0 = st->h[0]; h1 = st->h[1]; h2 = st->h[2]; h3 = st->h[3]; h4 = st->h[4];

    /* fully carry h */
                 c = h1 >> 26; h1 &= 0x3ffffff;
    h2 +=     c; c = h2 >> 26; h2 &= 0x3ffffff;
    h3 +=     c; c = h3 >> 26; h3 &= 0x3ffffff;
    h4 +=     c; c = h4 >> 26; h4 &= 0x3ffffff;
    h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
    h1 +=     c;

    /* compute h + -p */
    g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    g4 = h4 + c - (1u << 26);

    /* select h if h < p, or h + -p if h >= p */
    mask = (g4 >> 31) - 1;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0; h1 = (h1 & mask) | g1; h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3; h4 = (h4 & mask) | g4;

    /* h = h % (2^128) */
    h0 = ((h0      ) | (h1 << 26)) & 0xffffffff;
    h1 = ((h1 >>  6) | (h2 << 20)) & 0xffffffff;
    h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
    h3 = ((h3 >> 18) | (h4 <<  8)) & 0xffffffff;

    /* mac = (h + pad) % (2^128) */
    f = (uint64_t)h0 + st->pad[0]            ; h0 = (uint32_t)f;
    f = (uint64_t)h1 + st->pad[1] + (f >> 32); h1 = (uint32_t)f;
    f = (uint64_t)h2 + st->pad[2] + (f >> 32); h2 = (uint32_t)f;
    f = (uint64_t)h3 + st->pad[3] + (f >> 32); h3 = (uint32_t)f;

    store32_le(mac +  0, h0);
    store32_le(mac +  4, h1);
    store32_le(mac +  8, h2);
    store32_le(mac + 12, h3);

    wipe(st, sizeof *st);
}

/* ------------------------------------------------------------------- AEAD */

static const uint8_t zeros[16] = {0};

static void aead_tag(const uint8_t otk[32], const uint8_t *aad, size_t aad_len,
                     const uint8_t *ct, size_t ct_len, uint8_t tag[16]) {
    poly1305_state st;
    uint8_t lens[16];
    poly1305_init(&st, otk);
    poly1305_update(&st, aad, aad_len);
    if (aad_len % 16) poly1305_update(&st, zeros, 16 - aad_len % 16);
    poly1305_update(&st, ct, ct_len);
    if (ct_len % 16) poly1305_update(&st, zeros, 16 - ct_len % 16);
    store64_le(lens, (uint64_t)aad_len);
    store64_le(lens + 8, (uint64_t)ct_len);
    poly1305_update(&st, lens, 16);
    poly1305_finish(&st, tag);
}

static int ct_equal16(const uint8_t *a, const uint8_t *b) {
    uint8_t d = 0;
    int i;
    for (i = 0; i < 16; i++) d |= a[i] ^ b[i];
    return d == 0;
}

/* ------------------------------------------------------------- public API */

SC_EXPORT const char *sc_version(void) { return SC_VERSION; }

/* Raw ChaCha20 (RFC 8439 2.4): out = in XOR keystream.  Returns 0. */
SC_EXPORT int sc_chacha20_xor(const uint8_t *key, uint32_t counter, const uint8_t *nonce,
                              const uint8_t *in, size_t len, uint8_t *out) {
    chacha20_xor(key, counter, nonce, in, len, out);
    return 0;
}

/* Poly1305 one-shot MAC (RFC 8439 2.5). */
SC_EXPORT int sc_poly1305(const uint8_t *key, const uint8_t *msg, size_t len, uint8_t *tag) {
    poly1305_state st;
    poly1305_init(&st, key);
    poly1305_update(&st, msg, len);
    poly1305_finish(&st, tag);
    return 0;
}

/* AEAD encrypt (RFC 8439 2.8).  out must hold pt_len + 16 bytes.  Returns 0. */
SC_EXPORT int sc_aead_encrypt(const uint8_t *key, const uint8_t *nonce,
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t *pt, size_t pt_len, uint8_t *out) {
    uint8_t otk[64];
    {
        uint32_t st[16];
        chacha20_init(st, key, 0, nonce);
        chacha20_block(st, otk);                     /* counter 0 -> Poly1305 key */
        wipe(st, sizeof st);
    }
    chacha20_xor(key, 1, nonce, pt, pt_len, out);    /* counter 1.. -> data */
    aead_tag(otk, aad, aad_len, out, pt_len, out + pt_len);
    wipe(otk, sizeof otk);
    return 0;
}

/* AEAD decrypt.  ct_len includes the 16-byte tag; out must hold ct_len - 16.
 * Returns 0 on success, -1 on authentication failure (out is left untouched),
 * -2 if ct_len < 16. */
SC_EXPORT int sc_aead_decrypt(const uint8_t *key, const uint8_t *nonce,
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t *ct, size_t ct_len, uint8_t *out) {
    uint8_t otk[64];
    uint8_t tag[16];
    size_t body;
    int ok;
    if (ct_len < 16) return -2;
    body = ct_len - 16;
    {
        uint32_t st[16];
        chacha20_init(st, key, 0, nonce);
        chacha20_block(st, otk);
        wipe(st, sizeof st);
    }
    aead_tag(otk, aad, aad_len, ct, body, tag);
    ok = ct_equal16(tag, ct + body);
    if (ok) chacha20_xor(key, 1, nonce, ct, body, out);
    wipe(otk, sizeof otk);
    wipe(tag, sizeof tag);
    return ok ? 0 : -1;
}
