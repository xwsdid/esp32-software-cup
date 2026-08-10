/**
 * @file  key_layer.h
 * @brief 密钥层保护 — ECDH 协商 + HKDF 派生 + 动态轮换 + NVS 存储
 *
 * 流程:
 *   ESP32                             大禹终端
 *    │ 1. 生成 ECDH 密钥对                │
 *    │ 2. 发布公钥 → key/ecdh/pub        │
 *    │                                   │ 3. 收到 ESP32 公钥
 *    │                                   │ 4. 生成自己的密钥对
 *    │ 5. ← 大禹公钥 key/ecdh/pub       │
 *    │ 6. ECDH 计算共享密钥               │ 7. ECDH 计算共享密钥 (相同)
 *    │ 8. HKDF 派生 AES+SM4 密钥          │ 9. HKDF 派生 AES+SM4 密钥
 *    │                                   │
 *    │ ←── AES/SM4 加密通信开始 ───────→ │
 *
 * 密钥轮换: 定时或收到 rotate 指令后重新走 1-9 步
 */
#ifndef KEY_LAYER_H
#define KEY_LAYER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "psa/crypto.h"

/* ======================== 配置 ======================== */
#define KEY_ECDH_CURVE       PSA_ECC_FAMILY_SECP_R1   /* P-256 */
#define KEY_ECDH_KEY_BITS    256
#define KEY_PUBKEY_MAX_LEN   65   /* P-256 未压缩公钥: 0x04||x||y */

#define KEY_MQTT_TOPIC_PREFIX "key/ecdh/pub"   /* topic前缀, ESP32发布到 /{deviceId} */

/* 密钥轮换间隔 (秒) — 0=不自动轮换 */
#define KEY_ROTATE_INTERVAL_SEC  1800   /* 30 分钟 */

/* ======================== 派生密钥结构 ======================== */
typedef struct {
    uint8_t aes_key[32];   /* AES-256 密钥 */
    uint8_t sm4_key[16];   /* SM4 密钥     */
    uint8_t aes_iv[12];    /* AES 初始 IV  */
    uint8_t sm4_iv[12];    /* SM4 初始 IV  */
    bool    valid;          /* 密钥是否有效  */
} key_material_t;

/* ======================== API ======================== */

/**
 * @brief 初始化密钥层: 生成 ECDH 密钥对 + 尝试从 NVS 恢复
 * @return true 成功
 */
bool key_layer_init(void);

/**
 * @brief 获取本机公钥 (P-256 uncompressed, 65 bytes)
 * @param[out] pubkey 65 字节缓冲区
 * @param[out] len   实际长度 (65)
 * @return true 成功
 */
bool key_layer_get_pubkey(uint8_t *pubkey, size_t *len);
psa_key_id_t key_layer_get_private_key(void);

/**
 * @brief 处理收到的大禹公钥, 计算共享密钥 + HKDF 派生
 *
 * 调用后:
 *   - 内部完成 ECDH + HKDF
 *   - crypto_layer 的 AES/SM4 密钥被更新
 *   - 密钥存入 NVS
 *
 * @param peer_pubkey  大禹公钥 (65 bytes uncompressed)
 * @param peer_pub_len 公钥长度
 * @return true 协商成功, false 失败
 */
bool key_layer_negotiate(const uint8_t *peer_pubkey, size_t peer_pub_len);

/**
 * @brief 仅计算 ECDH 共享密钥 (不派生, 不更新 crypto 层)
 *
 * 供 BLE 等独立通道复用 WiFi 密钥对做 ECDH,
 * 避免 PSA Crypto 第二个 P-256 密钥对的兼容性问题。
 *
 * @param peer_pubkey  对端公钥 (65 bytes uncompressed)
 * @param peer_pub_len 公钥长度
 * @param[out] shared_secret  共享密钥 (32 bytes)
 * @param[out] shared_len     实际长度
 * @return true 成功
 */
bool key_layer_compute_shared_secret(const uint8_t *peer_pubkey, size_t peer_pub_len,
                                      uint8_t *shared_secret, size_t *shared_len);

/**
 * @brief 获取当前派生密钥 (供 crypto_layer 使用)
 */
const key_material_t *key_layer_get_keys(void);

/**
 * @brief 获取当前协商 epoch (每次协商递增)
 */
int key_layer_get_epoch(void);

/**
 * @brief 触发密钥轮换 (重新生成密钥对 + 发布新公钥)
 * @note 会把新公钥写入 pubkey_tx_buf, 外部负责 publish
 * @param[out] new_pubkey 新公钥 (65 bytes)
 * @param[out] len        长度
 * @return true 成功
 */
bool key_layer_rotate(uint8_t *new_pubkey, size_t *len);

/**
 * @brief 保存密钥到 NVS
 */
bool key_layer_save_nvs(void);

/**
 * @brief 从 NVS 恢复密钥
 */
bool key_layer_load_nvs(void);

/**
 * @brief Reset 后回退到静态密钥 (epoch=0, keySource=static)
 *        发 boot 通知后调用, 等大禹重新发起 ECDH
 */
void key_layer_reset_boot(void);

#endif /* KEY_LAYER_H */
