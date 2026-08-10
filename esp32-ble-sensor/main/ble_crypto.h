/**
 * @file  ble_crypto.h
 * @brief BLE 独立 ECDH 密钥协商 + AES/SM4 加解密
 *
 * 与 WiFi/MQTT/HTTP 密钥完全隔离, 不互相影响。
 */
#ifndef BLE_CRYPTO_H
#define BLE_CRYPTO_H
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* 密钥长度 */
#define BLE_AES_KEY_LEN  32
#define BLE_SM4_KEY_LEN  16
#define BLE_IV_LEN       12
#define BLE_TAG_LEN      16

/* 初始化 BLE 密钥模块 (生成 P-256 密钥对) */
void ble_crypto_init(const char *device_id);

/* 是否有有效的 BLE 会话密钥 */
bool ble_crypto_ready(void);
int  ble_crypto_epoch(void);

/* 执行 ECDH 密钥交换 (base64 公钥 + epoch) */
void ble_crypto_do_ecdh(const char *pub_b64, int epoch);

/* 激活 pending 密钥 (key confirm 后调用) */
void ble_crypto_activate(void);
/* BLE 断开时重置, 恢复 MQTT 传感器上报 */
void ble_crypto_reset(void);

/* 获取本机公钥 Base64 (用于 key exchange response) */
int ble_crypto_get_pubkey_b64(char *out, size_t sz);

/* BLE SM4-GCM 解密: [IV(12B)][TAG(16B)][CT] → plaintext */
bool ble_crypto_sm4_decrypt(const uint8_t *ct, size_t ct_len,
                             const uint8_t *iv, const uint8_t *tag,
                             uint8_t *pt, size_t *pt_len);
/* BLE SM4-GCM 加密: plaintext → [IV(12B)][TAG(16B)][CT] */
int ble_crypto_sm4_encrypt(const uint8_t *pt, size_t pt_len,
                            uint8_t *out, size_t out_size);
/* BLE AES-GCM 解密 */
bool ble_crypto_aes_decrypt(const uint8_t *ct, size_t ct_len,
                             const uint8_t *iv, const uint8_t *tag,
                             uint8_t *pt, size_t *pt_len);
/* BLE AES-GCM 加密 */
int ble_crypto_aes_encrypt(const uint8_t *pt, size_t pt_len,
                            uint8_t *out, size_t out_size);

/* 兼容旧名 */
#define ble_crypto_decrypt ble_crypto_sm4_decrypt
#define ble_crypto_encrypt ble_crypto_sm4_encrypt

#endif
