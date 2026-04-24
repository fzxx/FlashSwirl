#include "FlashSwirl.h"
#include <cstring>
#include <cstdlib>
#include <random>
#include <memory>
#include <thread>
#include <mutex>
#include <vector>
#include <algorithm>
#include <cstdint>

#ifdef _WIN32
#include <windows.h>
#endif

static inline void keyToState(const uint8_t* key, uint32_t state[8]);
static inline void swirlRound(uint32_t state[8]);
void compress(uint32_t state[], const uint8_t block[], int rounds);
static void compressDirect(uint32_t state[], const uint8_t block[], int rounds);

static constexpr size_t BUFFER_SIZE = 4 << 20; // 4MB缓冲区
static constexpr size_t PARALLEL_THRESHOLD = 64 << 10; // 64KB以上启用并行处理
static constexpr size_t CACHE_LINE_SIZE = 64; // 缓存行大小
static constexpr size_t MEMORY_THRESHOLD = 64 << 20; // 64MB以下使用内存缓冲

static thread_local std::unique_ptr<uint8_t[]> tls_buffer;
static thread_local bool tls_buffer_initialized = false;

static inline uint8_t* getThreadLocalBuffer() {
    if (!tls_buffer_initialized) {
        tls_buffer = std::make_unique<uint8_t[]>(BUFFER_SIZE);
        tls_buffer_initialized = true;
    }
    return tls_buffer.get();
}

static thread_local std::unique_ptr<uint8_t[]> tls_aead_read_buffer;
static thread_local std::unique_ptr<uint8_t[]> tls_aead_decrypt_buffer;
static thread_local std::unique_ptr<uint8_t[]> tls_aead_combined_buffer;
static thread_local bool tls_aead_buffers_initialized = false;

static inline void initAeadBuffers() {
    if (!tls_aead_buffers_initialized) {
        tls_aead_read_buffer = std::make_unique<uint8_t[]>(BUFFER_SIZE);
        tls_aead_decrypt_buffer = std::make_unique<uint8_t[]>(BUFFER_SIZE);
        tls_aead_combined_buffer = std::make_unique<uint8_t[]>(BUFFER_SIZE + FlashSwirl::BLOCK_SIZE + FlashSwirl::TAG_SIZE);
        tls_aead_buffers_initialized = true;
    }
}

// 初始状态
static const uint8_t FIXED_INITIAL_STATE[FlashSwirl::KEY_SIZE] = {
    0x46, 0x6c, 0x61, 0x73, 0x68, 0x53, 0x77, 0x69,
    0x72, 0x6c, 0xe9, 0x97, 0xaa, 0xe6, 0x97, 0x8b,
    0x20, 0x46, 0x65, 0x6e, 0x67, 0x5a, 0x68, 0x69,
    0x58, 0x69, 0x61, 0x58, 0x69, 0x61, 0x6e, 0x67,
};

// 缓存的固定初始状态
static uint32_t cachedFixedState[8];

namespace {
    struct FixedStateInitializer {
        FixedStateInitializer() {
            keyToState(FIXED_INITIAL_STATE, cachedFixedState);
        }
    };
    static FixedStateInitializer init;
}

static inline void clearBuffer(void* buf, size_t len) {
    if (buf == nullptr || len == 0) return;
#ifdef _WIN32
    SecureZeroMemory(buf, len);
#elif defined(__GNUC__) || defined(__clang__)
    explicit_bzero(buf, len);
#else
    volatile uint8_t* p = static_cast<volatile uint8_t*>(buf);
    while (len--) *p++ = 0;
#endif
}

static inline bool constantTimeCompare(const uint8_t* a, const uint8_t* b, int len) {
    if (len <= 0) return false;
    uint8_t result = 0;
    for (int i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}

static bool ValidateKey(const uint8_t* key, int len) {
    return len == FlashSwirl::KEY_SIZE;
}

static bool ValidateNonce(const uint8_t* nonce, int len) {
    return len == FlashSwirl::NONCE_SIZE;
}

static bool ValidateKeyAndNonce(const uint8_t* key, int keyLen, const uint8_t* nonce, int nonceLen) {
    return ValidateKey(key, keyLen) && ValidateNonce(nonce, nonceLen);
}

static inline uint32_t readUint32LE(const uint8_t* p) {
#if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__)
    return *reinterpret_cast<const uint32_t*>(p);
#else
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
#endif
}

static inline void writeUint32LE(uint8_t* p, uint32_t v) {
#if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__)
    *reinterpret_cast<uint32_t*>(p) = v;
#else
    p[0] = v & 0xFF;
    p[1] = (v >> 8) & 0xFF;
    p[2] = (v >> 16) & 0xFF;
    p[3] = (v >> 24) & 0xFF;
#endif
}

static inline void writeUint64LE(uint8_t* p, uint64_t v) {
#if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__)
    *reinterpret_cast<uint64_t*>(p) = v;
#else
    for (int i = 0; i < 8; i++) {
        p[i] = (v >> (i * 8)) & 0xFF;
    }
#endif
}

static inline uint64_t readUint64LE(const uint8_t* p) {
#if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__)
    return *reinterpret_cast<const uint64_t*>(p);
#else
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v |= (uint64_t)p[i] << (i * 8);
    }
    return v;
#endif
}

static inline void xorBytes(uint8_t* dst, const uint8_t* src, int n) {
    if (n == 0) return;

    int i = 0;
    for (; i + 64 <= n; i += 64) {
        uint64_t* d64 = reinterpret_cast<uint64_t*>(dst + i);
        const uint64_t* s64 = reinterpret_cast<const uint64_t*>(src + i);
        d64[0] ^= s64[0];
        d64[1] ^= s64[1];
        d64[2] ^= s64[2];
        d64[3] ^= s64[3];
        d64[4] ^= s64[4];
        d64[5] ^= s64[5];
        d64[6] ^= s64[6];
        d64[7] ^= s64[7];
    }

    for (; i + 8 <= n; i += 8) {
        uint64_t v = readUint64LE(&dst[i]) ^ readUint64LE(&src[i]);
        writeUint64LE(&dst[i], v);
    }
    for (; i < n; i++) {
        dst[i] ^= src[i];
    }
}

static inline void xorBlock32(uint8_t* dst, int offset,
                               uint32_t s0, uint32_t s1, uint32_t s2, uint32_t s3,
                               uint32_t s4, uint32_t s5, uint32_t s6, uint32_t s7) {
    uint8_t* p = dst + offset;
    p[0] ^= s0 & 0xFF;
    p[1] ^= (s0 >> 8) & 0xFF;
    p[2] ^= (s0 >> 16) & 0xFF;
    p[3] ^= (s0 >> 24) & 0xFF;
    p[4] ^= s1 & 0xFF;
    p[5] ^= (s1 >> 8) & 0xFF;
    p[6] ^= (s1 >> 16) & 0xFF;
    p[7] ^= (s1 >> 24) & 0xFF;
    p[8] ^= s2 & 0xFF;
    p[9] ^= (s2 >> 8) & 0xFF;
    p[10] ^= (s2 >> 16) & 0xFF;
    p[11] ^= (s2 >> 24) & 0xFF;
    p[12] ^= s3 & 0xFF;
    p[13] ^= (s3 >> 8) & 0xFF;
    p[14] ^= (s3 >> 16) & 0xFF;
    p[15] ^= (s3 >> 24) & 0xFF;
    p[16] ^= s4 & 0xFF;
    p[17] ^= (s4 >> 8) & 0xFF;
    p[18] ^= (s4 >> 16) & 0xFF;
    p[19] ^= (s4 >> 24) & 0xFF;
    p[20] ^= s5 & 0xFF;
    p[21] ^= (s5 >> 8) & 0xFF;
    p[22] ^= (s5 >> 16) & 0xFF;
    p[23] ^= (s5 >> 24) & 0xFF;
    p[24] ^= s6 & 0xFF;
    p[25] ^= (s6 >> 8) & 0xFF;
    p[26] ^= (s6 >> 16) & 0xFF;
    p[27] ^= (s6 >> 24) & 0xFF;
    p[28] ^= s7 & 0xFF;
    p[29] ^= (s7 >> 8) & 0xFF;
    p[30] ^= (s7 >> 16) & 0xFF;
    p[31] ^= (s7 >> 24) & 0xFF;
}

static int getOptimalWorkerCount(int dataSize) {
    int cpuCount = (int)std::thread::hardware_concurrency();
    if (cpuCount <= 1) return 1;
    
    int blocks = dataSize / FlashSwirl::BLOCK_SIZE;
    if (blocks < cpuCount * 4) return 1;
    if (blocks < cpuCount * 16) return cpuCount / 2;
    if (cpuCount > 8) return 8;
    return cpuCount;
}

static inline void quarterRoundScalar(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    a += b;
    d ^= a;
    d = (d << 16) | (d >> 16);
    c += d;
    b ^= c;
    b = (b << 12) | (b >> 20);
    a += b;
    d ^= a;
    d = (d << 8) | (d >> 24);
    c += d;
    b ^= c;
    b = (b << 7) | (b >> 25);
}

static inline void quarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    quarterRoundScalar(a, b, c, d);
}

static inline void swirlRoundScalar(uint32_t state[8]) {
    quarterRoundScalar(state[0], state[1], state[2], state[3]);
    quarterRoundScalar(state[4], state[5], state[6], state[7]);
    quarterRoundScalar(state[0], state[5], state[2], state[7]);
    quarterRoundScalar(state[1], state[4], state[3], state[6]);
}

static inline void quarterRoundInline(uint32_t a, uint32_t b, uint32_t c, uint32_t d,
                                       uint32_t& oa, uint32_t& ob, uint32_t& oc, uint32_t& od) {
    a += b;
    d ^= a;
    d = (d << 16) | (d >> 16);
    c += d;
    b ^= c;
    b = (b << 12) | (b >> 20);
    a += b;
    d ^= a;
    d = (d << 8) | (d >> 24);
    c += d;
    b ^= c;
    b = (b << 7) | (b >> 25);
    oa = a; ob = b; oc = c; od = d;
}

static inline void swirlRoundInline(uint32_t s0, uint32_t s1, uint32_t s2, uint32_t s3,
                                     uint32_t s4, uint32_t s5, uint32_t s6, uint32_t s7,
                                     uint32_t& o0, uint32_t& o1, uint32_t& o2, uint32_t& o3,
                                     uint32_t& o4, uint32_t& o5, uint32_t& o6, uint32_t& o7) {
    quarterRoundInline(s0, s1, s2, s3, s0, s1, s2, s3);
    quarterRoundInline(s4, s5, s6, s7, s4, s5, s6, s7);
    quarterRoundInline(s0, s5, s2, s7, s0, s5, s2, s7);
    quarterRoundInline(s1, s4, s3, s6, s1, s4, s3, s6);

    o0 = s0; o1 = s1; o2 = s2; o3 = s3;
    o4 = s4; o5 = s5; o6 = s6; o7 = s7;
}

static inline int normalizeRounds(int rounds) {
    if (rounds == 8 || rounds == 20) {
        return rounds / 2;
    }
    return 10;
}

static inline void swirlRound(uint32_t state[8]) {
    swirlRoundScalar(state);
}

static inline void applySwirlRounds(uint32_t state[8], int rounds) {
    rounds = normalizeRounds(rounds);
    for (int i = 0; i < rounds; i++) {
        swirlRound(state);
    }
}

static inline void keyToState(const uint8_t* key, uint32_t state[8]) {
    for (int i = 0; i < 8; i++) {
        state[i] = readUint32LE(key + i * 4);
    }
}

static inline void stateToBytes(const uint32_t state[8], uint8_t* buffer) {
    for (int i = 0; i < 8; i++) {
        writeUint32LE(buffer + i * 4, state[i]);
    }
}

static int makeBaseNonce(const uint8_t* key, const uint8_t* nonce, uint32_t baseNonce[8]) {
    if (!ValidateKey(key, FlashSwirl::KEY_SIZE) || !ValidateNonce(nonce, FlashSwirl::NONCE_SIZE)) {
        return -1;
    }

    uint8_t baseNonceBytes[FlashSwirl::BLOCK_SIZE];
    for (int i = 0; i < FlashSwirl::BLOCK_SIZE; i++) {
        uint8_t nonceByte = (i < FlashSwirl::NONCE_SIZE) ? nonce[i] : 0;
        baseNonceBytes[i] = FIXED_INITIAL_STATE[i] ^ key[i] ^ nonceByte;
    }
    
    keyToState(baseNonceBytes, baseNonce);

    clearBuffer(baseNonceBytes, sizeof(baseNonceBytes));
    return 0;
}

static void generateKeystreamBlock(const uint32_t baseNonce[8], uint64_t counter, int rounds,
                                    uint8_t keystream[FlashSwirl::BLOCK_SIZE]) {
    uint32_t state[8];
    memcpy(state, baseNonce, sizeof(uint32_t) * 8);
    state[6] ^= uint32_t(counter >> 32);
    state[7] ^= uint32_t(counter);

    uint32_t original[8];
    memcpy(original, state, sizeof(uint32_t) * 8);

    applySwirlRounds(state, rounds);

    for (int i = 0; i < 8; i++) {
        state[i] += original[i];
    }

    stateToBytes(state, keystream);
}

static uint64_t processKeystreamBlocksBatch(const uint32_t baseNonce[8], uint64_t counter, int normalizedRounds,
                                             uint8_t* dst, int dstLen) {
    int numBlocks = dstLen / FlashSwirl::BLOCK_SIZE;
    if (numBlocks == 0) return counter;

    int i = 0;
    for (; i + 3 < numBlocks; i += 4) {
        uint32_t s0_0 = baseNonce[0], s1_0 = baseNonce[1], s2_0 = baseNonce[2], s3_0 = baseNonce[3];
        uint32_t s4_0 = baseNonce[4], s5_0 = baseNonce[5], s6_0 = baseNonce[6], s7_0 = baseNonce[7];
        s6_0 ^= uint32_t((counter + uint64_t(i)) >> 32);
        s7_0 ^= uint32_t(counter + uint64_t(i));
        uint32_t o0_0 = s0_0, o1_0 = s1_0, o2_0 = s2_0, o3_0 = s3_0;
        uint32_t o4_0 = s4_0, o5_0 = s5_0, o6_0 = s6_0, o7_0 = s7_0;

        uint32_t s0_1 = baseNonce[0], s1_1 = baseNonce[1], s2_1 = baseNonce[2], s3_1 = baseNonce[3];
        uint32_t s4_1 = baseNonce[4], s5_1 = baseNonce[5], s6_1 = baseNonce[6], s7_1 = baseNonce[7];
        s6_1 ^= uint32_t((counter + uint64_t(i+1)) >> 32);
        s7_1 ^= uint32_t(counter + uint64_t(i+1));
        uint32_t o0_1 = s0_1, o1_1 = s1_1, o2_1 = s2_1, o3_1 = s3_1;
        uint32_t o4_1 = s4_1, o5_1 = s5_1, o6_1 = s6_1, o7_1 = s7_1;

        uint32_t s0_2 = baseNonce[0], s1_2 = baseNonce[1], s2_2 = baseNonce[2], s3_2 = baseNonce[3];
        uint32_t s4_2 = baseNonce[4], s5_2 = baseNonce[5], s6_2 = baseNonce[6], s7_2 = baseNonce[7];
        s6_2 ^= uint32_t((counter + uint64_t(i+2)) >> 32);
        s7_2 ^= uint32_t(counter + uint64_t(i+2));
        uint32_t o0_2 = s0_2, o1_2 = s1_2, o2_2 = s2_2, o3_2 = s3_2;
        uint32_t o4_2 = s4_2, o5_2 = s5_2, o6_2 = s6_2, o7_2 = s7_2;

        uint32_t s0_3 = baseNonce[0], s1_3 = baseNonce[1], s2_3 = baseNonce[2], s3_3 = baseNonce[3];
        uint32_t s4_3 = baseNonce[4], s5_3 = baseNonce[5], s6_3 = baseNonce[6], s7_3 = baseNonce[7];
        s6_3 ^= uint32_t((counter + uint64_t(i+3)) >> 32);
        s7_3 ^= uint32_t(counter + uint64_t(i+3));
        uint32_t o0_3 = s0_3, o1_3 = s1_3, o2_3 = s2_3, o3_3 = s3_3;
        uint32_t o4_3 = s4_3, o5_3 = s5_3, o6_3 = s6_3, o7_3 = s7_3;

        int r = normalizedRounds;
        while (r >= 4) {
            swirlRoundInline(s0_0, s1_0, s2_0, s3_0, s4_0, s5_0, s6_0, s7_0, s0_0, s1_0, s2_0, s3_0, s4_0, s5_0, s6_0, s7_0);
            swirlRoundInline(s0_1, s1_1, s2_1, s3_1, s4_1, s5_1, s6_1, s7_1, s0_1, s1_1, s2_1, s3_1, s4_1, s5_1, s6_1, s7_1);
            swirlRoundInline(s0_2, s1_2, s2_2, s3_2, s4_2, s5_2, s6_2, s7_2, s0_2, s1_2, s2_2, s3_2, s4_2, s5_2, s6_2, s7_2);
            swirlRoundInline(s0_3, s1_3, s2_3, s3_3, s4_3, s5_3, s6_3, s7_3, s0_3, s1_3, s2_3, s3_3, s4_3, s5_3, s6_3, s7_3);

            swirlRoundInline(s0_0, s1_0, s2_0, s3_0, s4_0, s5_0, s6_0, s7_0, s0_0, s1_0, s2_0, s3_0, s4_0, s5_0, s6_0, s7_0);
            swirlRoundInline(s0_1, s1_1, s2_1, s3_1, s4_1, s5_1, s6_1, s7_1, s0_1, s1_1, s2_1, s3_1, s4_1, s5_1, s6_1, s7_1);
            swirlRoundInline(s0_2, s1_2, s2_2, s3_2, s4_2, s5_2, s6_2, s7_2, s0_2, s1_2, s2_2, s3_2, s4_2, s5_2, s6_2, s7_2);
            swirlRoundInline(s0_3, s1_3, s2_3, s3_3, s4_3, s5_3, s6_3, s7_3, s0_3, s1_3, s2_3, s3_3, s4_3, s5_3, s6_3, s7_3);

            swirlRoundInline(s0_0, s1_0, s2_0, s3_0, s4_0, s5_0, s6_0, s7_0, s0_0, s1_0, s2_0, s3_0, s4_0, s5_0, s6_0, s7_0);
            swirlRoundInline(s0_1, s1_1, s2_1, s3_1, s4_1, s5_1, s6_1, s7_1, s0_1, s1_1, s2_1, s3_1, s4_1, s5_1, s6_1, s7_1);
            swirlRoundInline(s0_2, s1_2, s2_2, s3_2, s4_2, s5_2, s6_2, s7_2, s0_2, s1_2, s2_2, s3_2, s4_2, s5_2, s6_2, s7_2);
            swirlRoundInline(s0_3, s1_3, s2_3, s3_3, s4_3, s5_3, s6_3, s7_3, s0_3, s1_3, s2_3, s3_3, s4_3, s5_3, s6_3, s7_3);

            swirlRoundInline(s0_0, s1_0, s2_0, s3_0, s4_0, s5_0, s6_0, s7_0, s0_0, s1_0, s2_0, s3_0, s4_0, s5_0, s6_0, s7_0);
            swirlRoundInline(s0_1, s1_1, s2_1, s3_1, s4_1, s5_1, s6_1, s7_1, s0_1, s1_1, s2_1, s3_1, s4_1, s5_1, s6_1, s7_1);
            swirlRoundInline(s0_2, s1_2, s2_2, s3_2, s4_2, s5_2, s6_2, s7_2, s0_2, s1_2, s2_2, s3_2, s4_2, s5_2, s6_2, s7_2);
            swirlRoundInline(s0_3, s1_3, s2_3, s3_3, s4_3, s5_3, s6_3, s7_3, s0_3, s1_3, s2_3, s3_3, s4_3, s5_3, s6_3, s7_3);
            r -= 4;
        }
        while (r > 0) {
            swirlRoundInline(s0_0, s1_0, s2_0, s3_0, s4_0, s5_0, s6_0, s7_0, s0_0, s1_0, s2_0, s3_0, s4_0, s5_0, s6_0, s7_0);
            swirlRoundInline(s0_1, s1_1, s2_1, s3_1, s4_1, s5_1, s6_1, s7_1, s0_1, s1_1, s2_1, s3_1, s4_1, s5_1, s6_1, s7_1);
            swirlRoundInline(s0_2, s1_2, s2_2, s3_2, s4_2, s5_2, s6_2, s7_2, s0_2, s1_2, s2_2, s3_2, s4_2, s5_2, s6_2, s7_2);
            swirlRoundInline(s0_3, s1_3, s2_3, s3_3, s4_3, s5_3, s6_3, s7_3, s0_3, s1_3, s2_3, s3_3, s4_3, s5_3, s6_3, s7_3);
            r--;
        }

        s0_0 += o0_0; s1_0 += o1_0; s2_0 += o2_0; s3_0 += o3_0;
        s4_0 += o4_0; s5_0 += o5_0; s6_0 += o6_0; s7_0 += o7_0;

        s0_1 += o0_1; s1_1 += o1_1; s2_1 += o2_1; s3_1 += o3_1;
        s4_1 += o4_1; s5_1 += o5_1; s6_1 += o6_1; s7_1 += o7_1;

        s0_2 += o0_2; s1_2 += o1_2; s2_2 += o2_2; s3_2 += o3_2;
        s4_2 += o4_2; s5_2 += o5_2; s6_2 += o6_2; s7_2 += o7_2;

        s0_3 += o0_3; s1_3 += o1_3; s2_3 += o2_3; s3_3 += o3_3;
        s4_3 += o4_3; s5_3 += o5_3; s6_3 += o6_3; s7_3 += o7_3;

        xorBlock32(dst, (i+0) * FlashSwirl::BLOCK_SIZE, s0_0, s1_0, s2_0, s3_0, s4_0, s5_0, s6_0, s7_0);
        xorBlock32(dst, (i+1) * FlashSwirl::BLOCK_SIZE, s0_1, s1_1, s2_1, s3_1, s4_1, s5_1, s6_1, s7_1);
        xorBlock32(dst, (i+2) * FlashSwirl::BLOCK_SIZE, s0_2, s1_2, s2_2, s3_2, s4_2, s5_2, s6_2, s7_2);
        xorBlock32(dst, (i+3) * FlashSwirl::BLOCK_SIZE, s0_3, s1_3, s2_3, s3_3, s4_3, s5_3, s6_3, s7_3);
    }

    for (; i < numBlocks; i++) {
        uint32_t s0 = baseNonce[0];
        uint32_t s1 = baseNonce[1];
        uint32_t s2 = baseNonce[2];
        uint32_t s3 = baseNonce[3];
        uint32_t s4 = baseNonce[4];
        uint32_t s5 = baseNonce[5];
        uint32_t s6 = baseNonce[6] ^ uint32_t((counter + uint64_t(i)) >> 32);
        uint32_t s7 = baseNonce[7] ^ uint32_t(counter + uint64_t(i));

        uint32_t o0 = s0, o1 = s1, o2 = s2, o3 = s3;
        uint32_t o4 = s4, o5 = s5, o6 = s6, o7 = s7;

        int r = normalizedRounds;
        while (r >= 4) {
            swirlRoundInline(s0, s1, s2, s3, s4, s5, s6, s7, s0, s1, s2, s3, s4, s5, s6, s7);
            swirlRoundInline(s0, s1, s2, s3, s4, s5, s6, s7, s0, s1, s2, s3, s4, s5, s6, s7);
            swirlRoundInline(s0, s1, s2, s3, s4, s5, s6, s7, s0, s1, s2, s3, s4, s5, s6, s7);
            swirlRoundInline(s0, s1, s2, s3, s4, s5, s6, s7, s0, s1, s2, s3, s4, s5, s6, s7);
            r -= 4;
        }
        while (r > 0) {
            swirlRoundInline(s0, s1, s2, s3, s4, s5, s6, s7, s0, s1, s2, s3, s4, s5, s6, s7);
            r--;
        }

        s0 += o0; s1 += o1; s2 += o2; s3 += o3;
        s4 += o4; s5 += o5; s6 += o6; s7 += o7;

        xorBlock32(dst, i * FlashSwirl::BLOCK_SIZE, s0, s1, s2, s3, s4, s5, s6, s7);
    }

    return counter + uint64_t(numBlocks);
}

static uint64_t processKeystreamBlocks(const uint32_t baseNonce[8], uint64_t counter, int rounds,
                                        uint8_t* dst, int dstLen) {
    int numBlocks = dstLen / FlashSwirl::BLOCK_SIZE;
    uint8_t keystream[FlashSwirl::BLOCK_SIZE];
    for (int i = 0; i < numBlocks; i++) {
        generateKeystreamBlock(baseNonce, counter + uint64_t(i), rounds, keystream);
        xorBytes(dst + i * FlashSwirl::BLOCK_SIZE, keystream, FlashSwirl::BLOCK_SIZE);
    }

    return counter + uint64_t(numBlocks);
}

static uint64_t processKeystreamBlocksOptimized(const uint32_t baseNonce[8], uint64_t counter, int normalizedRounds,
                                                 uint8_t* dst, int dstLen) {
    return processKeystreamBlocksBatch(baseNonce, counter, normalizedRounds, dst, dstLen);
}

static uint64_t processKeystreamBlocksParallel(const uint32_t baseNonce[8], uint64_t counter, int rounds,
                                                uint8_t* dst, int dstLen) {
    int numBlocks = dstLen / FlashSwirl::BLOCK_SIZE;
    if (numBlocks == 0) return counter;

    int workers = getOptimalWorkerCount(dstLen);
    if (workers <= 1) {
        return processKeystreamBlocksBatch(baseNonce, counter, normalizeRounds(rounds), dst, dstLen);
    }

    int blocksPerWorker = (numBlocks + workers - 1) / workers;
    int normalizedRounds = normalizeRounds(rounds);

    std::vector<std::thread> threads;
    threads.reserve(workers);

    for (int w = 0; w < workers; w++) {
        int startBlock = w * blocksPerWorker;
        int endBlock = startBlock + blocksPerWorker;
        if (endBlock > numBlocks) endBlock = numBlocks;
        if (startBlock >= numBlocks) continue;

        threads.emplace_back([=]() {
            int chunkSize = (endBlock - startBlock) * FlashSwirl::BLOCK_SIZE;
            processKeystreamBlocksBatch(baseNonce, counter + uint64_t(startBlock), normalizedRounds,
                                        dst + startBlock * FlashSwirl::BLOCK_SIZE, chunkSize);
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    return counter + uint64_t(numBlocks);
}

struct HashState {
    uint32_t state[8];
    uint8_t pending[2 * FlashSwirl::BLOCK_SIZE];
    int pendingLen;
    uint64_t total;
    int rounds;
    bool direct;

    void Clear() {
        clearBuffer(state, sizeof(state));
        clearBuffer(pending, sizeof(pending));
        pendingLen = 0;
        total = 0;
    }
};

static HashState newHashState(const uint8_t* key, int rounds) {
    HashState h;
    h.pendingLen = 0;
    h.total = 0;
    h.rounds = rounds;
    h.direct = false;

    uint32_t keyState[8];
    keyToState(key, keyState);

    for (int i = 0; i < 8; i++) {
        h.state[i] = cachedFixedState[i] ^ keyState[i];
    }

    memset(h.pending, 0, sizeof(h.pending));
    return h;
}

static HashState newHashStateWithRounds(const uint8_t* key, int normalizedRounds) {
    HashState h;
    h.pendingLen = 0;
    h.total = 0;
    h.rounds = normalizedRounds;
    h.direct = true;

    uint32_t keyState[8];
    keyToState(key, keyState);

    for (int i = 0; i < 8; i++) {
        h.state[i] = cachedFixedState[i] ^ keyState[i];
    }

    memset(h.pending, 0, sizeof(h.pending));
    return h;
}

static void hashStateWrite(HashState* h, const uint8_t* data, int len) {
    h->total += uint64_t(len);

    if (h->pendingLen > 0) {
        int need = FlashSwirl::BLOCK_SIZE - h->pendingLen;
        if (len >= need) {
            memcpy(h->pending + h->pendingLen, data, need);
            if (h->direct) {
                compressDirect(h->state, h->pending, h->rounds);
            } else {
                compress(h->state, h->pending, h->rounds);
            }
            h->pendingLen = 0;
            data += need;
            len -= need;
        } else {
            memcpy(h->pending + h->pendingLen, data, len);
            h->pendingLen += len;
            return;
        }
    }

    while (len >= FlashSwirl::BLOCK_SIZE) {
        if (h->direct) {
            compressDirect(h->state, data, h->rounds);
        } else {
            compress(h->state, data, h->rounds);
        }
        data += FlashSwirl::BLOCK_SIZE;
        len -= FlashSwirl::BLOCK_SIZE;
    }

    if (len > 0) {
        memcpy(h->pending, data, len);
        h->pendingLen = len;
    }
}

static void hashStateWriteBatch(HashState* h, const uint8_t* data, int len) {
    h->total += uint64_t(len);
    if (h->pendingLen > 0) {
        int need = FlashSwirl::BLOCK_SIZE - h->pendingLen;
        if (len >= need) {
            memcpy(h->pending + h->pendingLen, data, need);
            if (h->direct) {
                compressDirect(h->state, h->pending, h->rounds);
            } else {
                compress(h->state, h->pending, h->rounds);
            }
            h->pendingLen = 0;
            data += need;
            len -= need;
        } else {
            memcpy(h->pending + h->pendingLen, data, len);
            h->pendingLen += len;
            return;
        }
    }

    int numBlocks = len / FlashSwirl::BLOCK_SIZE;
    for (int i = 0; i < numBlocks; i++) {
        if (h->direct) {
            compressDirect(h->state, data + i * FlashSwirl::BLOCK_SIZE, h->rounds);
        } else {
            compress(h->state, data + i * FlashSwirl::BLOCK_SIZE, h->rounds);
        }
    }

    int remaining = len - numBlocks * FlashSwirl::BLOCK_SIZE;
    if (remaining > 0) {
        memcpy(h->pending, data + numBlocks * FlashSwirl::BLOCK_SIZE, remaining);
        h->pendingLen = remaining;
    }
}

static void hashStateSum(HashState* h, uint8_t out[FlashSwirl::BLOCK_SIZE]) {
    uint32_t state[8];
    memcpy(state, h->state, sizeof(state));

    uint8_t pending[2 * FlashSwirl::BLOCK_SIZE];
    memcpy(pending, h->pending, h->pendingLen);
    int pendingLen = h->pendingLen;
    uint64_t total = h->total;

    pending[pendingLen] = 0x80;
    pendingLen++;

    int pad = (FlashSwirl::BLOCK_SIZE - (pendingLen + 8) % FlashSwirl::BLOCK_SIZE) % FlashSwirl::BLOCK_SIZE;
    for (int i = 0; i < pad; i++) {
        pending[pendingLen] = 0;
        pendingLen++;
    }

    writeUint64LE(pending + pendingLen, total * 8);
    pendingLen += 8;

    for (int i = 0; i < pendingLen; i += FlashSwirl::BLOCK_SIZE) {
        if (h->direct) {
            compressDirect(state, pending + i, h->rounds);
        } else {
            compress(state, pending + i, h->rounds);
        }
    }

    stateToBytes(state, out);
}

void compress(uint32_t state[], const uint8_t block[], int rounds) {
    uint32_t s0 = state[0] ^ readUint32LE(block);
    uint32_t s1 = state[1] ^ readUint32LE(block + 4);
    uint32_t s2 = state[2] ^ readUint32LE(block + 8);
    uint32_t s3 = state[3] ^ readUint32LE(block + 12);
    uint32_t s4 = state[4] ^ readUint32LE(block + 16);
    uint32_t s5 = state[5] ^ readUint32LE(block + 20);
    uint32_t s6 = state[6] ^ readUint32LE(block + 24);
    uint32_t s7 = state[7] ^ readUint32LE(block + 28);

    uint32_t o0 = state[0], o1 = state[1], o2 = state[2], o3 = state[3];
    uint32_t o4 = state[4], o5 = state[5], o6 = state[6], o7 = state[7];

    int normalizedRounds = normalizeRounds(rounds);

    while (normalizedRounds >= 4) {
        swirlRoundInline(s0, s1, s2, s3, s4, s5, s6, s7, s0, s1, s2, s3, s4, s5, s6, s7);
        swirlRoundInline(s0, s1, s2, s3, s4, s5, s6, s7, s0, s1, s2, s3, s4, s5, s6, s7);
        swirlRoundInline(s0, s1, s2, s3, s4, s5, s6, s7, s0, s1, s2, s3, s4, s5, s6, s7);
        swirlRoundInline(s0, s1, s2, s3, s4, s5, s6, s7, s0, s1, s2, s3, s4, s5, s6, s7);
        normalizedRounds -= 4;
    }
    while (normalizedRounds > 0) {
        swirlRoundInline(s0, s1, s2, s3, s4, s5, s6, s7, s0, s1, s2, s3, s4, s5, s6, s7);
        normalizedRounds--;
    }

    state[0] = o0 ^ s0;
    state[1] = o1 ^ s1;
    state[2] = o2 ^ s2;
    state[3] = o3 ^ s3;
    state[4] = o4 ^ s4;
    state[5] = o5 ^ s5;
    state[6] = o6 ^ s6;
    state[7] = o7 ^ s7;
}

static void compressDirect(uint32_t state[], const uint8_t block[], int rounds) {
    uint32_t s0 = state[0] ^ readUint32LE(block);
    uint32_t s1 = state[1] ^ readUint32LE(block + 4);
    uint32_t s2 = state[2] ^ readUint32LE(block + 8);
    uint32_t s3 = state[3] ^ readUint32LE(block + 12);
    uint32_t s4 = state[4] ^ readUint32LE(block + 16);
    uint32_t s5 = state[5] ^ readUint32LE(block + 20);
    uint32_t s6 = state[6] ^ readUint32LE(block + 24);
    uint32_t s7 = state[7] ^ readUint32LE(block + 28);

    uint32_t o0 = state[0], o1 = state[1], o2 = state[2], o3 = state[3];
    uint32_t o4 = state[4], o5 = state[5], o6 = state[6], o7 = state[7];

    int r = rounds;
    while (r >= 4) {
        swirlRoundInline(s0, s1, s2, s3, s4, s5, s6, s7, s0, s1, s2, s3, s4, s5, s6, s7);
        swirlRoundInline(s0, s1, s2, s3, s4, s5, s6, s7, s0, s1, s2, s3, s4, s5, s6, s7);
        swirlRoundInline(s0, s1, s2, s3, s4, s5, s6, s7, s0, s1, s2, s3, s4, s5, s6, s7);
        swirlRoundInline(s0, s1, s2, s3, s4, s5, s6, s7, s0, s1, s2, s3, s4, s5, s6, s7);
        r -= 4;
    }
    while (r > 0) {
        swirlRoundInline(s0, s1, s2, s3, s4, s5, s6, s7, s0, s1, s2, s3, s4, s5, s6, s7);
        r--;
    }

    state[0] = o0 ^ s0;
    state[1] = o1 ^ s1;
    state[2] = o2 ^ s2;
    state[3] = o3 ^ s3;
    state[4] = o4 ^ s4;
    state[5] = o5 ^ s5;
    state[6] = o6 ^ s6;
    state[7] = o7 ^ s7;
}

static int hashWithState(const uint32_t initialState[8],
                          ReadCallback readCtx, void* ctx,
                          int rounds, uint8_t out[FlashSwirl::BLOCK_SIZE]) {
    uint32_t state[8];
    memcpy(state, initialState, sizeof(uint32_t) * 8);

    uint8_t buf[FlashSwirl::BLOCK_SIZE];
    uint8_t pending[2 * FlashSwirl::BLOCK_SIZE];
    int pendingLen = 0;
    uint64_t totalBytes = 0;

    while (true) {
        int n = readCtx(ctx, buf, FlashSwirl::BLOCK_SIZE);
        if (n < 0) return -1;
        if (n == 0) break;

        totalBytes += uint64_t(n);

        const uint8_t* src = buf;
        int remaining = n;
        while (remaining > 0) {
            int space = FlashSwirl::BLOCK_SIZE - pendingLen;
            int copyLen = remaining;
            if (copyLen > space) copyLen = space;

            memcpy(pending + pendingLen, src, copyLen);
            pendingLen += copyLen;
            src += copyLen;
            remaining -= copyLen;

            if (pendingLen == FlashSwirl::BLOCK_SIZE) {
                compress(state, pending, rounds);
                pendingLen = 0;
            }
        }
    }

    uint64_t totalBits = totalBytes * 8;
    pending[pendingLen] = 0x80;
    pendingLen++;
    int pad = (FlashSwirl::BLOCK_SIZE - (pendingLen + 8) % FlashSwirl::BLOCK_SIZE) % FlashSwirl::BLOCK_SIZE;
    for (int i = 0; i < pad; i++) {
        pending[pendingLen] = 0;
        pendingLen++;
    }
    writeUint64LE(pending + pendingLen, totalBits);
    pendingLen += 8;

    for (int i = 0; i < pendingLen; i += FlashSwirl::BLOCK_SIZE) {
        compress(state, pending + i, rounds);
    }

    stateToBytes(state, out);
    return 0;
}

struct MemReadCtx {
    const uint8_t* data;
    int64_t pos;
    int64_t len;
};

static int memReadCallback(void* ctx, uint8_t* buf, int len) {
    MemReadCtx* mc = static_cast<MemReadCtx*>(ctx);
    int available = int(mc->len - mc->pos);
    if (available <= 0) return 0;
    if (len > available) len = available;
    memcpy(buf, mc->data + mc->pos, len);
    mc->pos += len;
    return len;
}

struct MemWriteCtx {
    uint8_t* data;
    int64_t pos;
    int64_t capacity;
};

static int memWriteCallback(void* ctx, const uint8_t* buf, int len) {
    MemWriteCtx* mw = static_cast<MemWriteCtx*>(ctx);
    if (mw->pos + len > mw->capacity) return -1;
    memcpy(mw->data + mw->pos, buf, len);
    mw->pos += len;
    return len;
}

extern "C" {

FLASHSWIRL_API int FlashSwirl_Hash(const uint8_t* input, int64_t inputLen, int rounds,
                                     uint8_t out[FlashSwirl::BLOCK_SIZE]) {
    MemReadCtx ctx{input, 0, inputLen};
    return hashWithState(cachedFixedState, memReadCallback, &ctx, rounds, out);
}

FLASHSWIRL_API int FlashSwirl_HashStream(ReadCallback readCtx, void* ctx, int rounds,
                                          uint8_t out[FlashSwirl::BLOCK_SIZE]) {
    return hashWithState(cachedFixedState, readCtx, ctx, rounds, out);
}

static int hmacHashTo(const uint8_t* key, int keyLen,
                      ReadCallback readCtx, void* ctx,
                      int rounds, uint8_t out[FlashSwirl::BLOCK_SIZE]) {
    uint32_t keyState[8];
    keyToState(key, keyState);

    uint32_t initialState[8];
    for (int i = 0; i < 8; i++) {
        initialState[i] = cachedFixedState[i] ^ keyState[i];
    }

    return hashWithState(initialState, readCtx, ctx, rounds, out);
}

static void prepareHmacPads(const uint8_t* key, int keyLen, int rounds,
                            uint8_t ipad[FlashSwirl::BLOCK_SIZE],
                            uint8_t opad[FlashSwirl::BLOCK_SIZE]) {
    const uint8_t* useKey = key;
    int useKeyLen = keyLen;
    uint8_t hashedKeyBuf[FlashSwirl::BLOCK_SIZE];

    if (keyLen > FlashSwirl::BLOCK_SIZE) {
        FlashSwirl_Hash(key, keyLen, rounds, hashedKeyBuf);
        useKey = hashedKeyBuf;
        useKeyLen = FlashSwirl::BLOCK_SIZE;
    }

    for (int i = 0; i < FlashSwirl::BLOCK_SIZE; i++) {
        uint8_t k = (i < useKeyLen) ? useKey[i] : 0;
        ipad[i] = k ^ 0x36;
        opad[i] = k ^ 0x5C;
    }
}

FLASHSWIRL_API int FlashSwirl_HMAC(const uint8_t* key, int keyLen,
                                     const uint8_t* data, int64_t dataLen,
                                     int rounds, uint8_t out[FlashSwirl::BLOCK_SIZE]) {
    uint8_t keyIpad[FlashSwirl::BLOCK_SIZE];
    uint8_t keyOpad[FlashSwirl::BLOCK_SIZE];
    prepareHmacPads(key, keyLen, rounds, keyIpad, keyOpad);

    uint32_t keyState[8];
    keyToState(keyIpad, keyState);
    uint32_t innerInitialState[8];
    for (int i = 0; i < 8; i++) {
        innerInitialState[i] = cachedFixedState[i] ^ keyState[i];
    }

    keyToState(keyOpad, keyState);
    uint32_t outerInitialState[8];
    for (int i = 0; i < 8; i++) {
        outerInitialState[i] = cachedFixedState[i] ^ keyState[i];
    }

    uint8_t innerHash[FlashSwirl::BLOCK_SIZE];
    MemReadCtx dataCtx{data, 0, dataLen};
    hashWithState(innerInitialState, memReadCallback, &dataCtx, rounds, innerHash);

    MemReadCtx hashCtx{innerHash, 0, FlashSwirl::BLOCK_SIZE};
    return hashWithState(outerInitialState, memReadCallback, &hashCtx, rounds, out);
}

FLASHSWIRL_API int FlashSwirl_HMACStream(const uint8_t* key, int keyLen,
                                          ReadCallback readCtx, void* ctx,
                                          int rounds, uint8_t out[FlashSwirl::BLOCK_SIZE]) {
    uint8_t keyIpad[FlashSwirl::BLOCK_SIZE];
    uint8_t keyOpad[FlashSwirl::BLOCK_SIZE];
    prepareHmacPads(key, keyLen, rounds, keyIpad, keyOpad);

    uint32_t keyState[8];
    keyToState(keyIpad, keyState);
    uint32_t innerInitialState[8];
    for (int i = 0; i < 8; i++) {
        innerInitialState[i] = cachedFixedState[i] ^ keyState[i];
    }

    keyToState(keyOpad, keyState);
    uint32_t outerInitialState[8];
    for (int i = 0; i < 8; i++) {
        outerInitialState[i] = cachedFixedState[i] ^ keyState[i];
    }

    uint8_t innerHash[FlashSwirl::BLOCK_SIZE];
    hashWithState(innerInitialState, readCtx, ctx, rounds, innerHash);

    MemReadCtx hashCtx{innerHash, 0, FlashSwirl::BLOCK_SIZE};
    return hashWithState(outerInitialState, memReadCallback, &hashCtx, rounds, out);
}

FLASHSWIRL_API int FlashSwirl_HKDF(const uint8_t* masterKey, int masterKeyLen,
                                     const uint8_t* salt, int saltLen,
                                     const uint8_t* info, int infoLen,
                                     int length, int rounds, uint8_t* out) {
    if (length <= 0 || length > 255 * (int)FlashSwirl::BLOCK_SIZE) return -1;
    uint8_t saltBuf[FlashSwirl::BLOCK_SIZE];
    const uint8_t* useSalt = salt;
    int useSaltLen = saltLen;

    if (saltLen == 0) {
        memset(saltBuf, 0, FlashSwirl::BLOCK_SIZE);
        useSalt = saltBuf;
        useSaltLen = FlashSwirl::BLOCK_SIZE;
    } else if (saltLen != (int)FlashSwirl::BLOCK_SIZE) {
        FlashSwirl_Hash(salt, saltLen, rounds, saltBuf);
        useSalt = saltBuf;
        useSaltLen = FlashSwirl::BLOCK_SIZE;
    }
    uint8_t prk[FlashSwirl::BLOCK_SIZE];
    MemReadCtx mkCtx{masterKey, 0, masterKeyLen};
    FlashSwirl_HMACStream(useSalt, useSaltLen, memReadCallback, &mkCtx, rounds, prk);

    int numBlocks = (length + FlashSwirl::BLOCK_SIZE - 1) / FlashSwirl::BLOCK_SIZE;
    int pos = 0;
    uint8_t prevBlock[FlashSwirl::BLOCK_SIZE] = {0};
    uint8_t currentBlock[FlashSwirl::BLOCK_SIZE];
    uint8_t blockInputBuf[FlashSwirl::BLOCK_SIZE + 256 + 1];

    for (int i = 1; i <= numBlocks; i++) {
        int blockInputLen = (i == 1) ? infoLen + 1 : FlashSwirl::BLOCK_SIZE + infoLen + 1;
        int offset = 0;

        if (i != 1) {
            memcpy(blockInputBuf, prevBlock, FlashSwirl::BLOCK_SIZE);
            offset += FlashSwirl::BLOCK_SIZE;
        }
        if (infoLen > 0) {
            memcpy(blockInputBuf + offset, info, infoLen);
            offset += infoLen;
        }
        blockInputBuf[offset] = (uint8_t)i;

        MemReadCtx biCtx{blockInputBuf, 0, blockInputLen};
        FlashSwirl_HMACStream(prk, FlashSwirl::BLOCK_SIZE, memReadCallback, &biCtx, rounds, currentBlock);

        int copyLen = FlashSwirl::BLOCK_SIZE;
        if (pos + copyLen > length) copyLen = length - pos;
        memcpy(out + pos, currentBlock, copyLen);
        pos += copyLen;

        memcpy(prevBlock, currentBlock, FlashSwirl::BLOCK_SIZE);
    }

    clearBuffer(prk, FlashSwirl::BLOCK_SIZE);
    return 0;
}

FLASHSWIRL_API int FlashSwirl_PBKDF2(const uint8_t* password, int passwordLen,
                                       const uint8_t* salt, int saltLen,
                                       int iterations, int keyLength,
                                       int rounds, uint8_t* out) {
    if (iterations <= 0) return -1;
    if (keyLength <= 0) return -1;

    int numBlocks = (keyLength + FlashSwirl::BLOCK_SIZE - 1) / FlashSwirl::BLOCK_SIZE;
    int pos = 0;

    uint8_t u[FlashSwirl::BLOCK_SIZE];
    uint8_t f[FlashSwirl::BLOCK_SIZE];
    uint8_t blockInputBuf[256 + 4];

    for (int i = 1; i <= numBlocks; i++) {
        int blockInputLen = saltLen + 4;
        if (saltLen > 0) memcpy(blockInputBuf, salt, saltLen);
        writeUint32LE(blockInputBuf + saltLen, (uint32_t)i);

        MemReadCtx biCtx{blockInputBuf, 0, blockInputLen};
        FlashSwirl_HMACStream(password, passwordLen, memReadCallback, &biCtx, rounds, u);

        memcpy(f, u, FlashSwirl::BLOCK_SIZE);

        for (int j = 1; j < iterations; j++) {
            MemReadCtx uCtx{u, 0, FlashSwirl::BLOCK_SIZE};
            FlashSwirl_HMACStream(password, passwordLen, memReadCallback, &uCtx, rounds, u);
            for (int k = 0; k < FlashSwirl::BLOCK_SIZE; k++) {
                f[k] ^= u[k];
            }
        }

        int copyLen = FlashSwirl::BLOCK_SIZE;
        if (pos + copyLen > keyLength) copyLen = keyLength - pos;
        memcpy(out + pos, f, copyLen);
        pos += copyLen;
    }

    clearBuffer(u, sizeof(u));
    clearBuffer(f, sizeof(f));

    return 0;
}

static int streamProcess(const uint8_t* key, int keyLen, int rounds,
                         ReadCallback readCtx, void* readCtxData,
                         WriteCallback writeCtx, void* writeCtxData,
                         const uint8_t* randomNonce) {
    uint32_t baseNonce[8];
    if (makeBaseNonce(key, randomNonce, baseNonce) != 0) return -1;

    uint8_t* buffer = getThreadLocalBuffer();
    uint64_t counter = 0;

    while (true) {
        int n = readCtx(readCtxData, buffer, (int)BUFFER_SIZE);
        if (n < 0) {
            clearBuffer(baseNonce, sizeof(baseNonce));
            return -1;
        }
        if (n == 0) break;

        int fullBlocks = n / FlashSwirl::BLOCK_SIZE;
        if (fullBlocks > 0) {
            if (n >= (int)PARALLEL_THRESHOLD) {
                counter = processKeystreamBlocksParallel(baseNonce, counter, rounds, buffer, fullBlocks * FlashSwirl::BLOCK_SIZE);
            } else {
                counter = processKeystreamBlocksBatch(baseNonce, counter, normalizeRounds(rounds), buffer, fullBlocks * FlashSwirl::BLOCK_SIZE);
            }
        }

        int remaining = n % FlashSwirl::BLOCK_SIZE;
        if (remaining > 0) {
            uint8_t keystream[FlashSwirl::BLOCK_SIZE];
            generateKeystreamBlock(baseNonce, counter, rounds, keystream);
            xorBytes(buffer + fullBlocks * FlashSwirl::BLOCK_SIZE, keystream, remaining);
            counter++;
        }

        if (writeCtx(writeCtxData, buffer, n) != n) {
            clearBuffer(baseNonce, sizeof(baseNonce));
            return -1;
        }
    }

    clearBuffer(baseNonce, sizeof(baseNonce));
    return 0;
}

FLASHSWIRL_API int FlashSwirl_Encrypt(const uint8_t* key, int keyLen,
                                       const uint8_t* nonce, int nonceLen,
                                       ReadCallback readCtx, void* readCtxData,
                                       WriteCallback writeCtx, void* writeCtxData,
                                       int rounds) {
    return streamProcess(key, keyLen, rounds, readCtx, readCtxData, writeCtx, writeCtxData, nonce);
}

FLASHSWIRL_API int FlashSwirl_Decrypt(const uint8_t* key, int keyLen,
                                       const uint8_t* nonce, int nonceLen,
                                       ReadCallback readCtx, void* readCtxData,
                                       WriteCallback writeCtx, void* writeCtxData,
                                       int rounds) {
    return FlashSwirl_Encrypt(key, keyLen, nonce, nonceLen, readCtx, readCtxData, writeCtx, writeCtxData, rounds);
}

FLASHSWIRL_API int FlashSwirl_EncryptBuffer(const uint8_t* key, int keyLen,
                                             const uint8_t* nonce, int nonceLen,
                                             uint8_t* data, int dataLen,
                                             int rounds) {
    MemReadCtx rctx{data, 0, dataLen};
    MemWriteCtx wctx{data, 0, dataLen};
    return streamProcess(key, keyLen, rounds, memReadCallback, &rctx, memWriteCallback, &wctx, nonce);
}

FLASHSWIRL_API int FlashSwirl_DecryptBuffer(const uint8_t* key, int keyLen,
                                             const uint8_t* nonce, int nonceLen,
                                             uint8_t* data, int dataLen,
                                             int rounds) {
    return FlashSwirl_EncryptBuffer(key, keyLen, nonce, nonceLen, data, dataLen, rounds);
}

static int deriveKeys(const uint8_t* masterKey, int rounds,
                       uint8_t encryptionKey[FlashSwirl::BLOCK_SIZE],
                       uint8_t authKey[FlashSwirl::BLOCK_SIZE]) {
    if (!ValidateKey(masterKey, FlashSwirl::KEY_SIZE)) return -1;
    int normalizedRounds = normalizeRounds(rounds);

    uint8_t aeadKeyInfo[] = {'a', 'e', 'a', 'd', '-', 'k', 'e', 'y'};
    if (FlashSwirl_HKDF(masterKey, FlashSwirl::KEY_SIZE, nullptr, 0,
                        aeadKeyInfo, 8, FlashSwirl::BLOCK_SIZE, normalizedRounds, encryptionKey) != 0) {
        return -1;
    }

    uint8_t tagKeyInfo[] = {'t', 'a', 'g', '-', 'k', 'e', 'y'};
    if (FlashSwirl_HKDF(masterKey, FlashSwirl::KEY_SIZE, nullptr, 0,
                        tagKeyInfo, 7, FlashSwirl::BLOCK_SIZE, normalizedRounds, authKey) != 0) {
        clearBuffer(encryptionKey, FlashSwirl::BLOCK_SIZE);
        return -1;
    }

    return 0;
}

FLASHSWIRL_API int FlashSwirl_EncryptAEAD(const uint8_t* key, int keyLen,
                                           const uint8_t* nonce, int nonceLen,
                                           ReadCallback readCtx, void* readCtxData,
                                           WriteCallback writeCtx, void* writeCtxData,
                                           const uint8_t* ad, int adLen,
                                           int rounds) {
    if (!ValidateKeyAndNonce(key, keyLen, nonce, nonceLen)) return -1;

    uint8_t encryptionKey[FlashSwirl::BLOCK_SIZE];
    uint8_t authKey[FlashSwirl::BLOCK_SIZE];
    if (deriveKeys(key, rounds, encryptionKey, authKey) != 0) return -1;

    uint8_t ipad[FlashSwirl::BLOCK_SIZE];
    uint8_t opad[FlashSwirl::BLOCK_SIZE];
    prepareHmacPads(authKey, FlashSwirl::BLOCK_SIZE, rounds, ipad, opad);

    int normalizedRounds = normalizeRounds(rounds);
    int hashRounds = normalizedRounds / 2;
    if (hashRounds < 1) hashRounds = 1;

    HashState inner = newHashStateWithRounds(ipad, hashRounds);
    if (adLen > 0 && ad != nullptr) {
        hashStateWrite(&inner, ad, adLen);
    }

    uint32_t encBaseNonce[8];
    if (makeBaseNonce(encryptionKey, nonce, encBaseNonce) != 0) {
        clearBuffer(encryptionKey, FlashSwirl::BLOCK_SIZE);
        clearBuffer(authKey, FlashSwirl::BLOCK_SIZE);
        return -1;
    }

    uint8_t* buffer = getThreadLocalBuffer();
    uint64_t counter = 0;

    while (true) {
        int n = readCtx(readCtxData, buffer, (int)BUFFER_SIZE);
        if (n < 0) {
            clearBuffer(encryptionKey, FlashSwirl::BLOCK_SIZE);
            clearBuffer(authKey, FlashSwirl::BLOCK_SIZE);
            clearBuffer(encBaseNonce, sizeof(encBaseNonce));
            return -1;
        }
        if (n == 0) break;

        int fullBlocks = n / FlashSwirl::BLOCK_SIZE;
        if (fullBlocks > 0) {
            if (n >= (int)PARALLEL_THRESHOLD) {
                counter = processKeystreamBlocksParallel(encBaseNonce, counter, rounds, buffer, fullBlocks * FlashSwirl::BLOCK_SIZE);
            } else {
                counter = processKeystreamBlocksBatch(encBaseNonce, counter, normalizedRounds, buffer, fullBlocks * FlashSwirl::BLOCK_SIZE);
            }
            hashStateWriteBatch(&inner, buffer, fullBlocks * FlashSwirl::BLOCK_SIZE);
        }

        int remaining = n % FlashSwirl::BLOCK_SIZE;
        if (remaining > 0) {
            uint8_t keystream[FlashSwirl::BLOCK_SIZE];
            generateKeystreamBlock(encBaseNonce, counter, rounds, keystream);
            xorBytes(buffer + fullBlocks * FlashSwirl::BLOCK_SIZE, keystream, remaining);
            hashStateWrite(&inner, buffer + fullBlocks * FlashSwirl::BLOCK_SIZE, remaining);
            counter++;
        }

        if (writeCtx(writeCtxData, buffer, n) != n) {
            clearBuffer(encryptionKey, FlashSwirl::BLOCK_SIZE);
            clearBuffer(authKey, FlashSwirl::BLOCK_SIZE);
            clearBuffer(encBaseNonce, sizeof(encBaseNonce));
            return -1;
        }
    }

    uint8_t innerHash[FlashSwirl::BLOCK_SIZE];
    hashStateSum(&inner, innerHash);

    HashState outer = newHashStateWithRounds(opad, hashRounds);
    hashStateWrite(&outer, innerHash, FlashSwirl::BLOCK_SIZE);

    uint8_t tag[FlashSwirl::BLOCK_SIZE];
    hashStateSum(&outer, tag);

    if (writeCtx(writeCtxData, tag, FlashSwirl::TAG_SIZE) != FlashSwirl::TAG_SIZE) {
        clearBuffer(encryptionKey, FlashSwirl::BLOCK_SIZE);
        clearBuffer(authKey, FlashSwirl::BLOCK_SIZE);
        clearBuffer(encBaseNonce, sizeof(encBaseNonce));
        return -1;
    }

    clearBuffer(encryptionKey, FlashSwirl::BLOCK_SIZE);
    clearBuffer(authKey, FlashSwirl::BLOCK_SIZE);
    clearBuffer(encBaseNonce, sizeof(encBaseNonce));
    return 0;
}

FLASHSWIRL_API int FlashSwirl_DecryptAEAD(const uint8_t* key, int keyLen,
                                           const uint8_t* nonce, int nonceLen,
                                           ReadCallback readCtx, void* readCtxData,
                                           WriteCallback writeCtx, void* writeCtxData,
                                           const uint8_t* ad, int adLen,
                                           int rounds) {
    if (!ValidateKeyAndNonce(key, keyLen, nonce, nonceLen)) return -1;

    uint8_t encryptionKey[FlashSwirl::BLOCK_SIZE];
    uint8_t authKey[FlashSwirl::BLOCK_SIZE];
    if (deriveKeys(key, rounds, encryptionKey, authKey) != 0) return -1;

    uint8_t ipad[FlashSwirl::BLOCK_SIZE];
    uint8_t opad[FlashSwirl::BLOCK_SIZE];
    prepareHmacPads(authKey, FlashSwirl::BLOCK_SIZE, rounds, ipad, opad);

    int normalizedRounds = normalizeRounds(rounds);
    int hashRounds = normalizedRounds / 2;
    if (hashRounds < 1) hashRounds = 1;

    HashState inner = newHashStateWithRounds(ipad, hashRounds);
    if (adLen > 0 && ad != nullptr) {
        hashStateWrite(&inner, ad, adLen);
    }

    uint32_t encBaseNonce[8];
    if (makeBaseNonce(encryptionKey, nonce, encBaseNonce) != 0) {
        clearBuffer(encryptionKey, FlashSwirl::BLOCK_SIZE);
        clearBuffer(authKey, FlashSwirl::BLOCK_SIZE);
        return -1;
    }

    initAeadBuffers();
    uint8_t* readBuffer = tls_aead_read_buffer.get();
    uint8_t* decryptBuffer = tls_aead_decrypt_buffer.get();
    uint8_t* combinedBuffer = tls_aead_combined_buffer.get();

    std::vector<uint8_t> memoryBuffer;
    memoryBuffer.reserve(MEMORY_THRESHOLD);

    FILE* tmpF = nullptr;
#ifdef _WIN32
    wchar_t tempFile[MAX_PATH] = {0};
#else
    char tempFile[256] = {0};
#endif
    bool useTempFile = false;
    uint8_t pendingTail[FlashSwirl::BLOCK_SIZE + FlashSwirl::TAG_SIZE];
    int pendingLen = 0;
    int64_t totalPlaintextLen = 0;
    uint64_t counter = 0;

    while (true) {
        int n = readCtx(readCtxData, readBuffer, (int)BUFFER_SIZE);
        if (n < 0) {
            if (tmpF) { fclose(tmpF);
#ifdef _WIN32
                if (tempFile[0]) _wremove(tempFile);
#else
                if (tempFile[0]) remove(tempFile);
#endif
            }
            clearBuffer(encryptionKey, FlashSwirl::BLOCK_SIZE);
            clearBuffer(authKey, FlashSwirl::BLOCK_SIZE);
            clearBuffer(encBaseNonce, sizeof(encBaseNonce));
            return -1;
        }
        if (n == 0) break;

        uint8_t* processData = nullptr;
        int processDataLen = 0;

        if (pendingLen > 0) {
            std::memcpy(combinedBuffer, pendingTail, pendingLen);
            std::memcpy(combinedBuffer + pendingLen, readBuffer, n);
            processData = combinedBuffer;
            processDataLen = pendingLen + n;
            pendingLen = 0;
        } else {
            processData = readBuffer;
            processDataLen = n;
        }

        if (processDataLen <= FlashSwirl::TAG_SIZE) {
            std::memcpy(pendingTail, processData, processDataLen);
            pendingLen = processDataLen;
            continue;
        }
        int ciphertextLen = processDataLen - FlashSwirl::TAG_SIZE;
        int remainingBytes = ciphertextLen % FlashSwirl::BLOCK_SIZE;
        int processableLen = ciphertextLen - remainingBytes;
        int plaintextLen = processableLen;
        hashStateWriteBatch(&inner, processData, processableLen);
        std::memcpy(decryptBuffer, processData, processableLen);
        int fullBlocks = processableLen / FlashSwirl::BLOCK_SIZE;
        if (fullBlocks > 0) {
            if (processableLen >= (int)PARALLEL_THRESHOLD) {
                counter = processKeystreamBlocksParallel(encBaseNonce, counter, rounds, decryptBuffer, fullBlocks * FlashSwirl::BLOCK_SIZE);
            } else {
                counter = processKeystreamBlocksBatch(encBaseNonce, counter, normalizedRounds, decryptBuffer, fullBlocks * FlashSwirl::BLOCK_SIZE);
            }
        }

        if (!useTempFile && totalPlaintextLen + plaintextLen <= (int64_t)MEMORY_THRESHOLD) {
            memoryBuffer.insert(memoryBuffer.end(), decryptBuffer, decryptBuffer + plaintextLen);
        } else {
            if (!useTempFile) {
                useTempFile = true;
#ifdef _WIN32
                wchar_t tempPath[MAX_PATH];
                GetTempPathW(MAX_PATH, tempPath);
                GetTempFileNameW(tempPath, L"fsa", 0, tempFile);
                tmpF = _wfopen(tempFile, L"w+b");
#else
                strcpy(tempFile, "/tmp/flashswirl_XXXXXX");
                int tmpFd = mkstemp(tempFile);
                tmpF = fdopen(tmpFd, "w+b");
#endif
                if (!tmpF) {
                    clearBuffer(encryptionKey, FlashSwirl::BLOCK_SIZE);
                    clearBuffer(authKey, FlashSwirl::BLOCK_SIZE);
                    clearBuffer(encBaseNonce, sizeof(encBaseNonce));
                    return -1;
                }
                if (!memoryBuffer.empty()) {
                    fwrite(memoryBuffer.data(), 1, memoryBuffer.size(), tmpF);
                }
                memoryBuffer.clear();
                memoryBuffer.shrink_to_fit();
            }
            fwrite(decryptBuffer, 1, plaintextLen, tmpF);
        }

        totalPlaintextLen += plaintextLen;
        std::memcpy(pendingTail, processData + processableLen, remainingBytes + FlashSwirl::TAG_SIZE);
        pendingLen = remainingBytes + FlashSwirl::TAG_SIZE;
    }

    if (pendingLen < FlashSwirl::TAG_SIZE) {
        if (tmpF) { fclose(tmpF);
#ifdef _WIN32
            if (tempFile[0]) _wremove(tempFile);
#else
            if (tempFile[0]) remove(tempFile);
#endif
        }
        clearBuffer(encryptionKey, FlashSwirl::BLOCK_SIZE);
        clearBuffer(authKey, FlashSwirl::BLOCK_SIZE);
        clearBuffer(encBaseNonce, sizeof(encBaseNonce));
        return -1;
    }

    int finalRemaining = pendingLen - FlashSwirl::TAG_SIZE;
    if (finalRemaining > 0) {
        hashStateWriteBatch(&inner, pendingTail, finalRemaining);
    }
    const uint8_t* expectedTag = pendingTail + finalRemaining;

    uint8_t innerHash[FlashSwirl::BLOCK_SIZE];
    hashStateSum(&inner, innerHash);

    HashState outer = newHashStateWithRounds(opad, hashRounds);
    hashStateWrite(&outer, innerHash, FlashSwirl::BLOCK_SIZE);

    uint8_t computedTag[FlashSwirl::BLOCK_SIZE];
    hashStateSum(&outer, computedTag);

    if (!constantTimeCompare(computedTag, expectedTag, FlashSwirl::TAG_SIZE)) {
        if (tmpF) { fclose(tmpF);
#ifdef _WIN32
            if (tempFile[0]) _wremove(tempFile);
#else
            if (tempFile[0]) remove(tempFile);
#endif
        }
        clearBuffer(encryptionKey, FlashSwirl::BLOCK_SIZE);
        clearBuffer(authKey, FlashSwirl::BLOCK_SIZE);
        clearBuffer(encBaseNonce, sizeof(encBaseNonce));
        return 1;
    }

    if (finalRemaining > 0) {
        uint8_t keystream[FlashSwirl::BLOCK_SIZE];
        generateKeystreamBlock(encBaseNonce, counter, rounds, keystream);
        xorBytes(pendingTail, keystream, finalRemaining);
        counter++;

        if (!useTempFile && totalPlaintextLen + finalRemaining <= (int64_t)MEMORY_THRESHOLD) {
            memoryBuffer.insert(memoryBuffer.end(), pendingTail, pendingTail + finalRemaining);
        } else {
            if (!useTempFile) {
                useTempFile = true;
#ifdef _WIN32
                wchar_t tempPath[MAX_PATH];
                GetTempPathW(MAX_PATH, tempPath);
                GetTempFileNameW(tempPath, L"fsa", 0, tempFile);
                tmpF = _wfopen(tempFile, L"w+b");
#else
                strcpy(tempFile, "/tmp/flashswirl_XXXXXX");
                int tmpFd = mkstemp(tempFile);
                tmpF = fdopen(tmpFd, "w+b");
#endif
                if (!tmpF) {
                    clearBuffer(encryptionKey, FlashSwirl::BLOCK_SIZE);
                    clearBuffer(authKey, FlashSwirl::BLOCK_SIZE);
                    clearBuffer(encBaseNonce, sizeof(encBaseNonce));
                    return -1;
                }
                if (!memoryBuffer.empty()) {
                    fwrite(memoryBuffer.data(), 1, memoryBuffer.size(), tmpF);
                }
                memoryBuffer.clear();
                memoryBuffer.shrink_to_fit();
            }
            fwrite(pendingTail, 1, finalRemaining, tmpF);
        }
        totalPlaintextLen += finalRemaining;
    }

    if (useTempFile && tmpF) {
#ifdef _WIN32
        _fseeki64(tmpF, 0, SEEK_SET);
#else
        fseeko(tmpF, 0, SEEK_SET);
#endif
    }

    int64_t remainingToWrite = totalPlaintextLen;
    int64_t memoryPos = 0;

    while (remainingToWrite > 0) {
        int chunkSize = (int)((remainingToWrite > (int64_t)BUFFER_SIZE) ? (int64_t)BUFFER_SIZE : remainingToWrite);
        const uint8_t* writeData = nullptr;

        if (!useTempFile) {
            writeData = memoryBuffer.data() + memoryPos;
            memoryPos += chunkSize;
        } else {
            size_t readCount = fread(decryptBuffer, 1, chunkSize, tmpF);
            if ((int)readCount != chunkSize) {
                fclose(tmpF);
#ifdef _WIN32
                _wremove(tempFile);
#else
                remove(tempFile);
#endif
                clearBuffer(encryptionKey, FlashSwirl::BLOCK_SIZE);
                clearBuffer(authKey, FlashSwirl::BLOCK_SIZE);
                clearBuffer(encBaseNonce, sizeof(encBaseNonce));
                return -1;
            }
            writeData = decryptBuffer;
        }

        if (writeCtx(writeCtxData, writeData, chunkSize) != chunkSize) {
            if (tmpF) { fclose(tmpF);
#ifdef _WIN32
                if (tempFile[0]) _wremove(tempFile);
#else
                if (tempFile[0]) remove(tempFile);
#endif
            }
            clearBuffer(encryptionKey, FlashSwirl::BLOCK_SIZE);
            clearBuffer(authKey, FlashSwirl::BLOCK_SIZE);
            clearBuffer(encBaseNonce, sizeof(encBaseNonce));
            return -1;
        }

        remainingToWrite -= chunkSize;
    }

    if (tmpF) {
        fclose(tmpF);
#ifdef _WIN32
        _wremove(tempFile);
#else
        remove(tempFile);
#endif
    }
    clearBuffer(encryptionKey, FlashSwirl::BLOCK_SIZE);
    clearBuffer(authKey, FlashSwirl::BLOCK_SIZE);
    clearBuffer(encBaseNonce, sizeof(encBaseNonce));
    return 0;
}

FLASHSWIRL_API int FlashSwirl_EncryptAEADBuffer(const uint8_t* key, int keyLen,
                                                 const uint8_t* nonce, int nonceLen,
                                                 const uint8_t* plaintext, int plaintextLen,
                                                 uint8_t* out, int* outLen,
                                                 const uint8_t* ad, int adLen,
                                                 int rounds) {
    if (*outLen < plaintextLen + (int)FlashSwirl::TAG_SIZE) return -1;

    MemReadCtx rctx{plaintext, 0, plaintextLen};
    MemWriteCtx wctx{out, 0, *outLen};

    int ret = FlashSwirl_EncryptAEAD(key, keyLen, nonce, nonceLen,
                                      memReadCallback, &rctx,
                                      memWriteCallback, &wctx,
                                      ad, adLen, rounds);
    if (ret == 0) {
        *outLen = (int)wctx.pos;
    }
    return ret;
}

FLASHSWIRL_API int FlashSwirl_DecryptAEADBuffer(const uint8_t* key, int keyLen,
                                                 const uint8_t* nonce, int nonceLen,
                                                 const uint8_t* ciphertext, int ciphertextLen,
                                                 uint8_t* plaintext, int* plaintextLen,
                                                 const uint8_t* ad, int adLen,
                                                 int rounds) {
    if (*plaintextLen < ciphertextLen - (int)FlashSwirl::TAG_SIZE) return -1;

    MemReadCtx rctx{ciphertext, 0, ciphertextLen};
    MemWriteCtx wctx{plaintext, 0, *plaintextLen};

    int ret = FlashSwirl_DecryptAEAD(key, keyLen, nonce, nonceLen,
                                      memReadCallback, &rctx,
                                      memWriteCallback, &wctx,
                                      ad, adLen, rounds);
    if (ret == 0) {
        *plaintextLen = (int)wctx.pos;
    }
    return ret;
}

}
