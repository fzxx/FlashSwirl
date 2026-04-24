#pragma once

#include <cstdint>
#include <cstddef>

#if defined(_WIN32) || defined(_WIN64)
    #ifdef FLASHSWIRLLIB_EXPORTS
        #define FLASHSWIRL_API __declspec(dllexport)
    #else
        #define FLASHSWIRL_API __declspec(dllimport)
    #endif
#else
    #define FLASHSWIRL_API
#endif

// 常量定义
namespace FlashSwirl {
    constexpr size_t BLOCK_SIZE = 32;        // 块大小（字节）
    constexpr size_t KEY_SIZE = 32;          // 密钥长度（字节）
    constexpr size_t NONCE_SIZE = 24;        // Nonce长度（字节）
    constexpr size_t TAG_SIZE = 16;          // 认证标签长度（字节）
    constexpr size_t RANDOM_NONCE_SIZE = 24; // 随机Nonce长度
}

// 回调函数类型：读取数据
// 返回实际读取的字节数，0表示结束，-1表示错误
typedef int (*ReadCallback)(void* ctx, uint8_t* buf, int len);

// 回调函数类型：写入数据
// 返回实际写入的字节数，-1表示错误
typedef int (*WriteCallback)(void* ctx, const uint8_t* buf, int len);

extern "C" {

// ==================== Hash哈希 ====================

// 计算Hash值（32字节输出）
// 返回: 0成功, -1失败
FLASHSWIRL_API int FlashSwirl_Hash(const uint8_t* input, int64_t inputLen, int rounds, uint8_t out[FlashSwirl::BLOCK_SIZE]);

// 流式Hash计算（使用回调）
FLASHSWIRL_API int FlashSwirl_HashStream(ReadCallback readCtx, void* ctx, int rounds, uint8_t out[FlashSwirl::BLOCK_SIZE]);

//  HMAC认证码
FLASHSWIRL_API int FlashSwirl_HMAC(const uint8_t* key, int keyLen,
                                    const uint8_t* data, int64_t dataLen,
                                    int rounds, uint8_t out[FlashSwirl::BLOCK_SIZE]);

FLASHSWIRL_API int FlashSwirl_HMACStream(const uint8_t* key, int keyLen,
                                          ReadCallback readCtx, void* ctx,
                                          int rounds, uint8_t out[FlashSwirl::BLOCK_SIZE]);

// HKDF密钥派生
FLASHSWIRL_API int FlashSwirl_HKDF(const uint8_t* masterKey, int masterKeyLen,
                                    const uint8_t* salt, int saltLen,
                                    const uint8_t* info, int infoLen,
                                    int length, int rounds, uint8_t* out);

// PBKDF2密钥派生
FLASHSWIRL_API int FlashSwirl_PBKDF2(const uint8_t* password, int passwordLen,
                                      const uint8_t* salt, int saltLen,
                                      int iterations, int keyLength,
                                      int rounds, uint8_t* out);

// 流加密
FLASHSWIRL_API int FlashSwirl_Encrypt(const uint8_t* key, int keyLen,
                                       const uint8_t* nonce, int nonceLen,
                                       ReadCallback readCtx, void* readCtxData,
                                       WriteCallback writeCtx, void* writeCtxData,
                                       int rounds);

// 流解密
FLASHSWIRL_API int FlashSwirl_Decrypt(const uint8_t* key, int keyLen,
                                       const uint8_t* nonce, int nonceLen,
                                       ReadCallback readCtx, void* readCtxData,
                                       WriteCallback writeCtx, void* writeCtxData,
                                       int rounds);

FLASHSWIRL_API int FlashSwirl_EncryptBuffer(const uint8_t* key, int keyLen,
                                             const uint8_t* nonce, int nonceLen,
                                             uint8_t* data, int dataLen,
                                             int rounds);

FLASHSWIRL_API int FlashSwirl_DecryptBuffer(const uint8_t* key, int keyLen,
                                             const uint8_t* nonce, int nonceLen,
                                             uint8_t* data, int dataLen,
                                             int rounds);

// AEAD加密
FLASHSWIRL_API int FlashSwirl_EncryptAEAD(const uint8_t* key, int keyLen,
                                           const uint8_t* nonce, int nonceLen,
                                           ReadCallback readCtx, void* readCtxData,
                                           WriteCallback writeCtx, void* writeCtxData,
                                           const uint8_t* ad, int adLen,
                                           int rounds);

// AEAD解密
FLASHSWIRL_API int FlashSwirl_DecryptAEAD(const uint8_t* key, int keyLen,
                                           const uint8_t* nonce, int nonceLen,
                                           ReadCallback readCtx, void* readCtxData,
                                           WriteCallback writeCtx, void* writeCtxData,
                                           const uint8_t* ad, int adLen,
                                           int rounds);

// AEAD内存加密
FLASHSWIRL_API int FlashSwirl_EncryptAEADBuffer(const uint8_t* key, int keyLen,
                                                 const uint8_t* nonce, int nonceLen,
                                                 const uint8_t* plaintext, int plaintextLen,
                                                 uint8_t* out, int* outLen,
                                                 const uint8_t* ad, int adLen,
                                                 int rounds);

// AEAD内存解密
FLASHSWIRL_API int FlashSwirl_DecryptAEADBuffer(const uint8_t* key, int keyLen,
                                                 const uint8_t* nonce, int nonceLen,
                                                 const uint8_t* ciphertext, int ciphertextLen,
                                                 uint8_t* plaintext, int* plaintextLen,
                                                 const uint8_t* ad, int adLen,
                                                 int rounds);

} // extern "C"
