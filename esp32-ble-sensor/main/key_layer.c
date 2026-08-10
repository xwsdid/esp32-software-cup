/**
 * @file  key_layer.c
 * @brief 密钥层实现 — PSA Crypto ECDH + HKDF + NVS
 */
#include "key_layer.h"
#include "crypto_layer.h"
#include "esp_log.h"
#include "esp_random.h"
#include "nvs_flash.h"
#include "nvs.h"
#include <string.h>

#include "psa/crypto.h"

static const char *TAG_KEY = "KEY";

/* NVS 命名空间 */
#define KEY_NVS_NAMESPACE  "key_store"
#define KEY_NVS_AES_KEY    "aes_key"
#define KEY_NVS_SM4_KEY    "sm4_key"
#define KEY_NVS_AES_IV     "aes_iv"
#define KEY_NVS_SM4_IV     "sm4_iv"

/* ======================== 全局状态 ======================== */
static psa_key_id_t s_ecdh_private_key = 0;   /* 本机 ECDH 私钥 */
static uint8_t      s_our_pubkey[KEY_PUBKEY_MAX_LEN];  /* 本机公钥 */
static size_t       s_our_pubkey_len = 0;
static key_material_t s_keys = {0};            /* 派生密钥 */
static bool s_initialized = false;
static int  g_key_epoch = 0;                   /* 协商计数 */

/* HKDF 固定盐值 (后面可从 NVS 随机生成) */
static const uint8_t HKDF_SALT[16] = {
    0xC0,0xFF,0xEE,0xCA,0xFE,0xBA,0xBE,0xDA,
    0xCE,0xDE,0xAD,0xBE,0xEF,0xFE,0xED,0xFA,
};

/* ======================== ECDH 初始化 ======================== */

bool key_layer_init(void)
{
    if (s_initialized) return true;

    /* 1. 初始化 PSA Crypto */
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG_KEY, "PSA Crypto 初始化失败: %d", (int)status);
        return false;
    }

    /* 2. 尝试从 NVS 恢复密钥 (如果之前协商过) */
    if (key_layer_load_nvs()) {
        ESP_LOGI(TAG_KEY, "从 NVS 恢复了之前的密钥");
    }

    /* 3. 生成 ECDH 密钥对 (P-256) */
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_EXPORT
                                  | PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, KEY_ECDH_KEY_BITS);

    status = psa_generate_key(&attr, &s_ecdh_private_key);
    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG_KEY, "ECDH 密钥对生成失败: %d", (int)status);
        return false;
    }
    ESP_LOGI(TAG_KEY, "ECDH 密钥对已生成 (PSA ID=%lu, P-256)", s_ecdh_private_key);

    /* 4. 导出公钥 (uncompressed: 0x04||x||y = 65 bytes) */
    status = psa_export_public_key(s_ecdh_private_key,
                                   s_our_pubkey, sizeof(s_our_pubkey),
                                   &s_our_pubkey_len);
    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG_KEY, "公钥导出失败: %d", (int)status);
        return false;
    }
    ESP_LOGI(TAG_KEY, "本机公钥: %d 字节 (首字节=0x%02X)", s_our_pubkey_len, s_our_pubkey[0]);

    s_initialized = true;
    return true;
}

/* ======================== 公钥导出 ======================== */

bool key_layer_get_pubkey(uint8_t *pubkey, size_t *len)
{
    if (!s_initialized) return false;
    memcpy(pubkey, s_our_pubkey, s_our_pubkey_len);
    *len = s_our_pubkey_len;
    return true;
}

/* ======================== ECDH 协商 + HKDF 派生 ======================== */

/**
 * @brief 从共享密钥 (shared secret) 通过 HKDF 派生 AES/SM4 密钥
 */
static bool hkdf_derive_key(const uint8_t *shared_secret, size_t secret_len,
                             const char *info, uint8_t *out_key, size_t key_len)
{
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_status_t status;

    status = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (status != PSA_SUCCESS) { psa_key_derivation_abort(&op); return false; }

    status = psa_key_derivation_input_bytes(&op,
                        PSA_KEY_DERIVATION_INPUT_SALT,
                        HKDF_SALT, sizeof(HKDF_SALT));
    if (status != PSA_SUCCESS) { psa_key_derivation_abort(&op); return false; }

    status = psa_key_derivation_input_bytes(&op,
                        PSA_KEY_DERIVATION_INPUT_SECRET,
                        shared_secret, secret_len);
    if (status != PSA_SUCCESS) { psa_key_derivation_abort(&op); return false; }

    status = psa_key_derivation_input_bytes(&op,
                        PSA_KEY_DERIVATION_INPUT_INFO,
                        (const uint8_t *)info, strlen(info));
    if (status != PSA_SUCCESS) { psa_key_derivation_abort(&op); return false; }

    status = psa_key_derivation_output_bytes(&op, out_key, key_len);
    psa_key_derivation_abort(&op);
    return (status == PSA_SUCCESS);
}

static bool hkdf_derive_keys(const uint8_t *shared_secret, size_t secret_len,
                             key_material_t *out)
{
    if (!hkdf_derive_key(shared_secret, secret_len, "aes-key", out->aes_key, 32)) {
        ESP_LOGE(TAG_KEY, "HKDF AES 密钥派生失败");
        return false;
    }
    if (!hkdf_derive_key(shared_secret, secret_len, "sm4-key", out->sm4_key, 16)) {
        ESP_LOGE(TAG_KEY, "HKDF SM4 密钥派生失败");
        return false;
    }
    out->valid = true;
    ESP_LOGI(TAG_KEY, "HKDF 派生完成: AES(32B)+SM4(16B)");
    return true;
}

bool key_layer_negotiate(const uint8_t *peer_pubkey, size_t peer_pub_len)
{
    if (!s_initialized) {
        ESP_LOGE(TAG_KEY, "密钥层未初始化");
        return false;
    }

    /* 1. 导入大禹公钥 */
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, KEY_ECDH_KEY_BITS);

    psa_key_id_t peer_key_id = 0;
    psa_status_t status = psa_import_key(&attr, peer_pubkey, peer_pub_len,
                                         &peer_key_id);
    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG_KEY, "导入大禹公钥失败: %d", (int)status);
        return false;
    }
    /* 打印完整 65B hex: 方便对比 BLE 通道 */
    ESP_LOG_BUFFER_HEX_LEVEL(TAG_KEY, peer_pubkey, peer_pub_len, ESP_LOG_INFO);
    ESP_LOGI(TAG_KEY, "[WiFi peer pk] len=%d pk[0]=0x%02X", (int)peer_pub_len, peer_pubkey[0]);

    /* 2. ECDH 密钥协商: 计算共享密钥 */
    uint8_t shared_secret[32];  /* P-256 共享密钥 = 32 bytes */
    size_t shared_len = 0;

    status = psa_raw_key_agreement(PSA_ALG_ECDH,
                                   s_ecdh_private_key,
                                   peer_pubkey, peer_pub_len,
                                   shared_secret, sizeof(shared_secret),
                                   &shared_len);
    psa_destroy_key(peer_key_id);  /* 公钥用完就销毁 */

    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG_KEY, "ECDH 协商失败: %d", (int)status);
        return false;
    }
    ESP_LOGI(TAG_KEY, "ECDH 共享密钥: %d 字节", shared_len);

    /* 3. HKDF 派生 AES + SM4 密钥 */
    if (!hkdf_derive_keys(shared_secret, shared_len, &s_keys)) {
        return false;
    }

    /* 4. 更新 crypto 层加密密钥 (后续数据用新密钥) */
    crypto_update_aes_key(s_keys.aes_key);
    crypto_update_sm4_key(s_keys.sm4_key);

    /* 5. 持久化到 NVS */
    key_layer_save_nvs();
    g_key_epoch++;  /* 协商完成, epoch递增 */

    return true;
}

int key_layer_get_epoch(void) { return g_key_epoch; }

/* ---- 供 BLE 复用 WiFi 密钥对做 ECDH (导出→重新导入为独立 key, 绕过 PSA 单次限制) ---- */
bool key_layer_compute_shared_secret(const uint8_t *peer_pubkey, size_t peer_pub_len,
                                      uint8_t *shared_secret, size_t *shared_len)
{
    if (!s_initialized) {
        ESP_LOGE(TAG_KEY, "密钥层未初始化");
        return false;
    }

    /* 打印完整 65B hex */
    ESP_LOG_BUFFER_HEX_LEVEL(TAG_KEY, peer_pubkey, peer_pub_len, ESP_LOG_INFO);
    ESP_LOGI(TAG_KEY, "[BLE peer pk] len=%d pk[0]=0x%02X", (int)peer_pub_len, peer_pubkey[0]);

    /* 1. 导出 WiFi 私钥 → 重新导入为独立 key (新 key 未用过, 不受 PSA 单次限制) */
    uint8_t priv[32]; size_t priv_len = 0;
    psa_status_t ps = psa_export_key(s_ecdh_private_key, priv, sizeof(priv), &priv_len);
    if (ps != PSA_SUCCESS) {
        ESP_LOGE(TAG_KEY, "导出私钥失败: %d", (int)ps);
        return false;
    }

    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);

    psa_key_id_t ble_key = 0;
    ps = psa_import_key(&attr, priv, priv_len, &ble_key);
    if (ps != PSA_SUCCESS) {
        ESP_LOGE(TAG_KEY, "导入私钥失败: %d", (int)ps);
        return false;
    }

    /* 2. ECDH: 用新 key 计算共享密钥 */
    *shared_len = 0;
    ps = psa_raw_key_agreement(PSA_ALG_ECDH,
                               ble_key,
                               peer_pubkey, peer_pub_len,
                               shared_secret, 32,
                               shared_len);

    if (ps != PSA_SUCCESS) {
        ESP_LOGE(TAG_KEY, "ECDH fail: %d | peer_len=%d pk[0]=0x%02X alg=PSA_ALG_ECDH(%d) "
                 "key_type=ECC_PUBKEY(r1) bits=256 usage=DERIVE",
                 (int)ps, (int)peer_pub_len, peer_pubkey[0], (int)PSA_ALG_ECDH);

        /* 自检: 用自己的公钥做 ECDH, 确认 PSA/密钥本身没坏 */
        uint8_t self_shared[32]; size_t self_len = 0;
        psa_status_t st3 = psa_raw_key_agreement(PSA_ALG_ECDH,
                            ble_key, s_our_pubkey, s_our_pubkey_len,
                            self_shared, sizeof(self_shared), &self_len);
        ESP_LOGE(TAG_KEY, "自检(用自己的公钥做ECDH): %d (0=OK)", (int)st3);
        psa_destroy_key(ble_key);
        return false;
    }

    psa_destroy_key(ble_key);
    ESP_LOGI(TAG_KEY, "ECDH 共享密钥: %d bytes (via reimported key)", (int)*shared_len);
    return true;
}

/* ======================== 密钥轮换 ======================== */

bool key_layer_rotate(uint8_t *new_pubkey, size_t *len)
{
    /* 销毁旧密钥 */
    if (s_ecdh_private_key != 0) {
        psa_destroy_key(s_ecdh_private_key);
        s_ecdh_private_key = 0;
    }

    /* 重新生成密钥对 */
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_EXPORT
                                  | PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, KEY_ECDH_KEY_BITS);

    psa_status_t status = psa_generate_key(&attr, &s_ecdh_private_key);
    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG_KEY, "密钥轮换: 生成新密钥对失败: %d", (int)status);
        return false;
    }

    size_t new_len = 0;
    status = psa_export_public_key(s_ecdh_private_key,
                                   new_pubkey, KEY_PUBKEY_MAX_LEN, &new_len);
    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG_KEY, "密钥轮换: 导出新公钥失败: %d", (int)status);
        return false;
    }

    *len = new_len;
    s_keys.valid = false;  /* 旧密钥失效, 等新协商完成 */

    ESP_LOGI(TAG_KEY, "密钥轮换: 新密钥对已生成, 等待重新协商");
    return true;
}

/* ======================== 密钥访问 ======================== */

const key_material_t *key_layer_get_keys(void)
{
    return s_keys.valid ? &s_keys : NULL;
}

/* ======================== NVS 持久化 ======================== */

bool key_layer_save_nvs(void)
{
    if (!s_keys.valid) return false;

    nvs_handle_t handle;
    esp_err_t err = nvs_open(KEY_NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGW(TAG_KEY, "NVS 打开失败: %d", err);
        return false;
    }

    nvs_set_blob(handle, KEY_NVS_AES_KEY, s_keys.aes_key, 32);
    nvs_set_blob(handle, KEY_NVS_SM4_KEY, s_keys.sm4_key, 16);
    nvs_set_blob(handle, KEY_NVS_AES_IV,  s_keys.aes_iv,  12);
    nvs_set_blob(handle, KEY_NVS_SM4_IV,  s_keys.sm4_iv,  12);
    nvs_commit(handle);
    nvs_close(handle);

    ESP_LOGI(TAG_KEY, "密钥已存入 NVS");
    return true;
}

bool key_layer_load_nvs(void)
{
    nvs_handle_t handle;
    esp_err_t err = nvs_open(KEY_NVS_NAMESPACE, NVS_READONLY, &handle);
    if (err != ESP_OK) return false;

    size_t len = 32;
    err = nvs_get_blob(handle, KEY_NVS_AES_KEY, s_keys.aes_key, &len);
    if (err != ESP_OK) { nvs_close(handle); return false; }

    len = 16;
    nvs_get_blob(handle, KEY_NVS_SM4_KEY, s_keys.sm4_key, &len);
    len = 12;
    nvs_get_blob(handle, KEY_NVS_AES_IV,  s_keys.aes_iv,  &len);
    len = 12;
    nvs_get_blob(handle, KEY_NVS_SM4_IV,  s_keys.sm4_iv,  &len);

    s_keys.valid = true;
    nvs_close(handle);
    return true;
}

void key_layer_reset_boot(void)
{
    g_key_epoch = 0;
    s_keys.valid = false;
    /* 回退到静态密钥, 让大禹重新发起 ECDH */
    crypto_update_aes_key((uint8_t *)CRYPTO_AES_KEY);
    crypto_update_sm4_key((uint8_t *)CRYPTO_SM4_KEY);
    ESP_LOGI(TAG_KEY, "Boot reset: epoch=0 keySource=static");
}
psa_key_id_t key_layer_get_private_key(void) { return s_ecdh_private_key; }
