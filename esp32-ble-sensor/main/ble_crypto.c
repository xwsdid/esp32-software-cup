/**
 * @file  ble_crypto.c
 * @brief BLE 独立 ECDH + HKDF + AES/SM4 加解密 (与 WiFi 密钥隔离)
 */
#include "ble_crypto.h"
#include "crypto_layer.h"
#include "key_layer.h"
#include "esp_log.h"
#include "esp_random.h"
#include <string.h>
#include <stdio.h>
#include "psa/crypto.h"

static const char *T = "BLE_CRYPT";

/* BLE 独立密钥 */
static uint8_t  ble_aes_key[BLE_AES_KEY_LEN];
static uint8_t  ble_sm4_key[BLE_SM4_KEY_LEN];
static uint8_t  ble_pending_aes[BLE_AES_KEY_LEN];
static uint8_t  ble_pending_sm4[BLE_SM4_KEY_LEN];
static int      ble_epoch = 0;
static bool     ble_ready = false;
static bool     ble_pending = false;

/* BLE ECDH — 复用 WiFi 密钥对 (避免 PSA Crypto 第二个 P-256 密钥对的 ECDH bug) */
static uint8_t      ble_pubkey[65];
static size_t       ble_pubkey_len = 0;
static char         ble_device_id[40];

/* HKDF 固定盐 (与 WiFi 一致) */
static const uint8_t HKDF_SALT[16] = {
    0xC0,0xFF,0xEE,0xCA,0xFE,0xBA,0xBE,0xDA,
    0xCE,0xDE,0xAD,0xBE,0xEF,0xFE,0xED,0xFA,
};

/* ---- base64 解码 ---- */
static uint8_t *b64d(const char *in, int *olen) {
    static const signed char d[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
    };
    int il = (int)strlen(in);
    int ol = ((il + 3) / 4) * 3; uint8_t *o = malloc(ol + 1);
    if (!o) { *olen = 0; return NULL; }
    int ip = 0, op = 0;
    while (ip < il) {
        int v = 0, b = 0;
        for (int i = 0; i < 4 && ip < il; i++, ip++) {
            if (in[ip] == '=') continue;  /* skip padding, don't add bits */
            int c = d[(uint8_t)in[ip]];
            if (c < 0) { free(o); *olen = 0; return NULL; }
            v = (v << 6) | c; b++;
        }
        /* 补齐到 24 位: b=3 → 18→24, b=2 → 12→24 */
        if (b < 4) v <<= (4 - b) * 6;
        if (b >= 2) { o[op++] = (v >> 16) & 0xFF; v <<= 8; b--; }
        if (b >= 2) { o[op++] = (v >> 16) & 0xFF; v <<= 8; b--; }
        if (b >= 2) { o[op++] = (v >> 16) & 0xFF; v <<= 8; b--; }
    }
    ESP_LOGI(T, "[BLE-ECDH] b64d: in=%d out=%d", il, op);
    *olen = op; return o;
}

/* ---- HKDF ---- */
static bool hkdf_derive(const uint8_t *secret, size_t slen, const char *info,
                        uint8_t *key, size_t klen) {
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_status_t s;
    s = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (s) { psa_key_derivation_abort(&op); return false; }
    s = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT, HKDF_SALT, 16);
    if (s) { psa_key_derivation_abort(&op); return false; }
    s = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SECRET, secret, slen);
    if (s) { psa_key_derivation_abort(&op); return false; }
    s = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO, (const uint8_t *)info, strlen(info));
    if (s) { psa_key_derivation_abort(&op); return false; }
    s = psa_key_derivation_output_bytes(&op, key, klen);
    psa_key_derivation_abort(&op);
    return (s == PSA_SUCCESS);
}

/* ---- 初始化: 复用 WiFi 密钥对 (避免 PSA 第二个 P-256 密钥对的 raw_key_agreement bug) ---- */
void ble_crypto_init(const char *did) {
    snprintf(ble_device_id, sizeof(ble_device_id), "%s", did);

    /* 复用 WiFi/MQTT 密钥对的公钥 — key_layer_init() 在本函数之前已调用 */
    size_t pk_len = 0;
    if (!key_layer_get_pubkey(ble_pubkey, &pk_len)) {
        ESP_LOGE(T, "获取 WiFi 公钥失败 (key_layer 可能未初始化)");
        return;
    }
    ble_pubkey_len = pk_len;
    ESP_LOGI(T, "BLE ECDH ready (reuse WiFi key): pubkey=%d bytes", (int)ble_pubkey_len);
}

bool ble_crypto_ready(void) { return ble_ready; }
int  ble_crypto_epoch(void) { return ble_epoch; }

/* ---- JSON 字段提取 ---- */
static bool j_str(const char *j, const char *k, char *o, size_t sz) {
    char p[32]; snprintf(p, sizeof(p), "\"%s\":\"", k);
    const char *s = strstr(j, p); if (!s) return false;
    s += strlen(p); const char *e = strchr(s, '"'); if (!e) return false;
    size_t l = (size_t)(e - s); if (l >= sz) l = sz - 1;
    memcpy(o, s, l); o[l] = '\0'; return true;
}
static bool j_int(const char *j, const char *k, int *o) {
    char p[32]; snprintf(p, sizeof(p), "\"%s\":", k);
    const char *s = strstr(j, p); if (!s) return false;
    *o = (int)strtol(s + strlen(p), NULL, 10); return true;
}

/* ---- 处理密钥交换消息 ---- */
void ble_crypto_do_ecdh(const char *pub_b64, int epoch)
{
    if (!pub_b64 || !pub_b64[0]) { ESP_LOGE(T, "do_ecdh: empty key"); return; }

    int pklen = 0; uint8_t *pk = b64d(pub_b64, &pklen);
    if (!pk || pklen != 65) { ESP_LOGE(T, "do_ecdh: bad pubkey len=%d", pklen); free(pk); return; }

    /* 复用 WiFi 密钥对做 ECDH — 共享密钥与 WiFi 相同 (大禹发相同公钥) */
    uint8_t shared[32]; size_t slen = 0;
    if (!key_layer_compute_shared_secret(pk, pklen, shared, &slen)) {
        ESP_LOGE(T, "[BLE-ECDH] ECDH fail");
        free(pk); return;
    }
    free(pk);
    ESP_LOGI(T, "[BLE-ECDH] ECDH OK (shared=%d bytes)", (int)slen);
    ESP_LOG_BUFFER_HEX_LEVEL(T, shared, slen, ESP_LOG_INFO);
    ESP_LOGI(T, "[BLE-ECDH] shared_secret hex above ^");

    /* BLE 用独立 HKDF info, 确保派生密钥与 WiFi 隔离 */
    bool aok = hkdf_derive(shared, slen, "ble-aes-key", ble_pending_aes, BLE_AES_KEY_LEN);
    bool sok = hkdf_derive(shared, slen, "ble-sm4-key", ble_pending_sm4, BLE_SM4_KEY_LEN);
    if (!aok || !sok) { ESP_LOGE(T, "HKDF fail"); return; }

    ESP_LOGI(T, "[BLE-ECDH] ble-aes-key:");
    ESP_LOG_BUFFER_HEX_LEVEL(T, ble_pending_aes, BLE_AES_KEY_LEN, ESP_LOG_INFO);
    ESP_LOGI(T, "[BLE-ECDH] ble-sm4-key:");
    ESP_LOG_BUFFER_HEX_LEVEL(T, ble_pending_sm4, BLE_SM4_KEY_LEN, ESP_LOG_INFO);

    ble_epoch = epoch;
    ble_pending = true;
    ble_ready = false;
    ESP_LOGI(T, "Key exchange: epoch=%d pending AES+SM4 derived", epoch);

    /* 发送本机公钥给大禹 (由 ble_bridge 调用 device_event Notify) */
}

/* 获取本机公钥 Base64 (用于 key exchange response) */
int ble_crypto_get_pubkey_b64(char *out, size_t sz)
{
    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int bp = 0;
    for (int i = 0; i < (int)ble_pubkey_len; i += 3) {
        uint32_t v = (uint32_t)ble_pubkey[i] << 16;
        if (i + 1 < (int)ble_pubkey_len) v |= (uint32_t)ble_pubkey[i + 1] << 8;
        if (i + 2 < (int)ble_pubkey_len) v |= (uint32_t)ble_pubkey[i + 2];
        if (bp + 4 >= (int)sz) break;
        out[bp++] = b64[(v >> 18) & 0x3F];
        out[bp++] = b64[(v >> 12) & 0x3F];
        out[bp++] = (i + 1 < (int)ble_pubkey_len) ? b64[(v >> 6) & 0x3F] : '=';
        out[bp++] = (i + 2 < (int)ble_pubkey_len) ? b64[v & 0x3F] : '=';
    }
    out[bp] = '\0'; return bp;
}

/* 激活 pending 密钥 (key confirm 成功后调用) */
void ble_crypto_activate(void)
{
    if (!ble_pending) return;
    memcpy(ble_aes_key, ble_pending_aes, BLE_AES_KEY_LEN);
    memcpy(ble_sm4_key, ble_pending_sm4, BLE_SM4_KEY_LEN);
    ble_ready = true;
    ble_pending = false;
    ESP_LOGI(T, "BLE keys activated: epoch=%d", ble_epoch);
}

/* BLE 断开时重置, 恢复 MQTT 传感器上报 */
void ble_crypto_reset(void)
{
    ble_ready = false;
    ble_pending = false;
    ESP_LOGI(T, "BLE crypto reset (disconnect)");
}

/* BLE SM4-GCM 解密 */
bool ble_crypto_sm4_decrypt(const uint8_t *ct, size_t ct_len,
                             const uint8_t *iv, const uint8_t *tag,
                             uint8_t *pt, size_t *pt_len)
{
    if (!ble_ready) return false;
    crypto_update_sm4_key(ble_sm4_key);
    return crypto_sm4_decrypt(ct, ct_len, iv, BLE_IV_LEN,
                               tag, BLE_TAG_LEN, pt, pt_len);
}

/* BLE SM4-GCM 加密: [IV(12B)][TAG(16B)][CT] */
int ble_crypto_sm4_encrypt(const uint8_t *pt, size_t pt_len, uint8_t *out, size_t out_size)
{
    if (!ble_ready) return -1;
    uint8_t iv[BLE_IV_LEN];
    uint32_t r0 = esp_random(), r1 = esp_random(), r2 = esp_random();
    memcpy(iv, &r0, 4); memcpy(iv + 4, &r1, 4); memcpy(iv + 8, &r2, 4);
    size_t ct_cap = out_size - BLE_IV_LEN - BLE_TAG_LEN;
    uint8_t *ct_buf = out + BLE_IV_LEN + BLE_TAG_LEN;
    size_t actual_ct = ct_cap;
    uint8_t *tag_out = out + BLE_IV_LEN;
    crypto_update_sm4_key(ble_sm4_key);
    bool ok = crypto_sm4_encrypt(pt, pt_len, iv, BLE_IV_LEN,
                                  ct_buf, &actual_ct, tag_out, BLE_TAG_LEN);
    if (!ok) return -1;
    memcpy(out, iv, BLE_IV_LEN);
    return (int)(BLE_IV_LEN + BLE_TAG_LEN + actual_ct);
}

/* BLE AES-GCM 解密: 临时切到 AES 模式, 绕过 g_sm4_mode 全局开关 */
bool ble_crypto_aes_decrypt(const uint8_t *ct, size_t ct_len,
                             const uint8_t *iv, const uint8_t *tag,
                             uint8_t *pt, size_t *pt_len)
{
    if (!ble_ready) return false;
    crypto_update_aes_key(ble_aes_key);
    bool saved = crypto_get_mode();
    crypto_set_mode(false);  /* 强制 AES */
    bool ok = crypto_aes_decrypt(ct, ct_len, iv, BLE_IV_LEN,
                                  tag, BLE_TAG_LEN, pt, pt_len);
    crypto_set_mode(saved);
    return ok;
}

/* BLE AES-GCM 加密: [IV(12B)][TAG(16B)][CT], 临时切到 AES 模式 */
int ble_crypto_aes_encrypt(const uint8_t *pt, size_t pt_len, uint8_t *out, size_t out_size)
{
    if (!ble_ready) return -1;
    uint8_t iv[BLE_IV_LEN];
    uint32_t r0 = esp_random(), r1 = esp_random(), r2 = esp_random();
    memcpy(iv, &r0, 4); memcpy(iv + 4, &r1, 4); memcpy(iv + 8, &r2, 4);
    size_t ct_cap = out_size - BLE_IV_LEN - BLE_TAG_LEN;
    uint8_t *ct_buf = out + BLE_IV_LEN + BLE_TAG_LEN;
    size_t actual_ct = ct_cap;
    uint8_t *tag_out = out + BLE_IV_LEN;
    crypto_update_aes_key(ble_aes_key);
    bool saved = crypto_get_mode();
    crypto_set_mode(false);  /* 强制 AES */
    bool ok = crypto_aes_encrypt(pt, pt_len, iv, BLE_IV_LEN,
                                  ct_buf, &actual_ct, tag_out, BLE_TAG_LEN);
    crypto_set_mode(saved);
    if (!ok) return -1;
    memcpy(out, iv, BLE_IV_LEN);
    return (int)(BLE_IV_LEN + BLE_TAG_LEN + actual_ct);
}
