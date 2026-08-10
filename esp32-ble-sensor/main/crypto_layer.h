/**
 * @file  crypto_layer.h
 * @brief 数据层加密模块 — AES-256-GCM + SM4-GCM
 *
 * 协议无关: MQTT / HTTP / CoAP 均可复用
 * 密钥来源: 后面由 ECDH + HKDF 动态派生 (目前用静态占位密钥)
 *
 * 用法:
 *   crypto_layer.h 中定义 KEY, 编译时选择算法:
 *   #define CRYPTO_USE_SM4  0   → AES-256-GCM
 *   #define CRYPTO_USE_SM4  1   → SM4-GCM
 */
#ifndef CRYPTO_LAYER_H
#define CRYPTO_LAYER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* ======================== 算法选择 ======================== */
#define CRYPTO_USE_SM4_DEFAULT  1   /* 0=AES, 1=SM4 (初始默认) */

/* 运行时切换算法 (大禹前端按钮触发) */
void crypto_set_mode(bool use_sm4);
bool crypto_get_mode(void);

/* 运行时更新密钥 (ECDH 协商后调用) */
void crypto_update_aes_key(const uint8_t new_key[32]);
void crypto_update_sm4_key(const uint8_t new_key[16]);
const uint8_t* crypto_get_dynamic_sm4_key(void);

/* 解密容错: 动态密钥失败时自动回退静态密钥 (切换瞬间兜底) */
bool crypto_decrypt_fallback(const uint8_t *ct, size_t ct_len,
                             const uint8_t *iv, size_t iv_len,
                             const uint8_t *tag, size_t tag_len,
                             uint8_t *pt, size_t *pt_len);

/* 仅用静态SM4密钥解密 (调试用) */
bool crypto_decrypt_static_sm4(const uint8_t *ct, size_t ct_len,
                               const uint8_t *iv, size_t iv_len,
                               const uint8_t *tag, size_t tag_len,
                               uint8_t *pt, size_t *pt_len);

/* ======================== 密钥/IV/Tag 长度 ======================== */
#define AES_KEY_LEN     32  /* AES-256: 256 bits */
#define AES_IV_LEN      12  /* GCM 推荐 96 bits nonce */
#define AES_TAG_LEN     16  /* GCM 认证标签 128 bits */

#define SM4_KEY_LEN     16  /* SM4: 128 bits */
#define SM4_IV_LEN      12  /* GCM 推荐 96 bits nonce */
#define SM4_TAG_LEN     16  /* GCM 认证标签 128 bits */

/* ======================== 占位密钥 (密钥层 ECDH 实现后替换) ======================== */
/* TODO: 这些密钥将被 ECDH + HKDF 动态替换, 目前仅用于开发测试 */
static const uint8_t CRYPTO_AES_KEY[AES_KEY_LEN] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,
};
static const uint8_t CRYPTO_SM4_KEY[SM4_KEY_LEN] = {
    0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
    0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10,
};

/* ======================== API ======================== */

/**
 * @brief AES-256-GCM 加密
 * @param plaintext  明文字节
 * @param plain_len  明文长度
 * @param iv        12 字节随机 nonce (每次加密需不同)
 * @param ciphertext 输出密文 (可 == plaintext, 原地加密)
 * @param cipher_len 输出密文长度 (= plain_len)
 * @param tag       输出 16 字节认证标签
 * @return true 成功, false 失败
 */
bool crypto_aes_encrypt(const uint8_t *plaintext,  size_t  plain_len,
                        const uint8_t *iv,          size_t  iv_len,
                        uint8_t       *ciphertext, size_t *cipher_len,
                        uint8_t       *tag,         size_t  tag_len);

/**
 * @brief AES-256-GCM 解密
 * @param ciphertext 密文字节
 * @param cipher_len 密文长度
 * @param iv        加密时用的 12 字节 nonce
 * @param tag       加密时输出的 16 字节认证标签
 * @param plaintext  输出明文 (可 == ciphertext, 原地解密)
 * @param plain_len  输出明文长度 (= cipher_len)
 * @return true 成功且认证通过, false 失败(密钥错/篡改)
 */
bool crypto_aes_decrypt(const uint8_t *ciphertext, size_t  cipher_len,
                        const uint8_t *iv,          size_t  iv_len,
                        const uint8_t *tag,         size_t  tag_len,
                        uint8_t       *plaintext,  size_t *plain_len);

/**
 * @brief SM4-GCM 加密 (国密)
 * @note 参数同 AES
 */
bool crypto_sm4_encrypt(const uint8_t *plaintext,  size_t  plain_len,
                        const uint8_t *iv,          size_t  iv_len,
                        uint8_t       *ciphertext, size_t *cipher_len,
                        uint8_t       *tag,         size_t  tag_len);

/**
 * @brief SM4-GCM 解密 (国密)
 * @note 参数同 AES
 */
bool crypto_sm4_decrypt(const uint8_t *ciphertext, size_t  cipher_len,
                        const uint8_t *iv,          size_t  iv_len,
                        const uint8_t *tag,         size_t  tag_len,
                        uint8_t       *plaintext,  size_t *plain_len);

#endif /* CRYPTO_LAYER_H */
