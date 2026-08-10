/**
 * @file  ble_bridge.c
 * @brief BLE 日常通信桥接: 明文/加密/密钥交换
 */
#include "ble_bridge.h"
#include "ble_peripheral.h"
#include "ble_crypto.h"
#include "door.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "driver/gpio.h"
#include <string.h>
#include <stdio.h>

static const char *TAG = "BLE_BRG";
#define LED_GPIO GPIO_NUM_21
static bool s_initialized = false;

static void send_notify_text(const char *text)
{
    ble_notify_device_event((const uint8_t *)text, (uint16_t)strlen(text));
    ESP_LOGI(TAG, "Notify text: %s", text);
}

void ble_bridge_init(const char *device_id)
{
    snprintf(s_device_id, sizeof(s_device_id), "%s", device_id);
    s_initialized = true;
    ble_set_business_cmd_callback(ble_bridge_on_command);
    ESP_LOGI(TAG, "BLE bridge init for %s", s_device_id);
}

/* ---- JSON util ---- */
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

/* ---- 处理业务命令 (明文 JSON) ---- */
static void handle_plain_cmd(const char *json, bool use_aes)
{
    char cmd[16] = {0}; int val = -1, seq = 0;
    j_str(json, "cmd", cmd, sizeof(cmd));
    j_int(json, "val", &val);
    j_int(json, "seq", &seq);

    if (strcmp(cmd, "led") == 0 && val >= 0) {
        gpio_set_level(LED_GPIO, val ? 1 : 0);
        /* 同步更新全局状态 (传感器上报 l 字段用) */
        if (xSemaphoreTake(s_sys_mutex, pdMS_TO_TICKS(50)) == pdTRUE) {
            s_sys_data.led_on = (uint8_t)(val ? 1 : 0);
            xSemaphoreGive(s_sys_mutex);
        }
        ESP_LOGI(TAG, "LED → %d", val);
        char ack[128];
        int alen = snprintf(ack, sizeof(ack),
            "{\"type\":\"ack\",\"cmd\":\"led\",\"ok\":true,\"val\":%d,\"seq\":%d}",
            val, seq);
        if (ble_crypto_ready()) {
            /* 加密 ACK (用请求相同的算法) */
            uint8_t enc[512];
            int elen = use_aes
                ? ble_crypto_aes_encrypt((const uint8_t *)ack, (size_t)alen, enc, sizeof(enc))
                : ble_crypto_sm4_encrypt((const uint8_t *)ack, (size_t)alen, enc, sizeof(enc));
            if (elen > 0) {
                char b64_out[700], b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                int bp = 0;
                for (int i = 0; i < elen; i += 3) {
                    uint32_t v = (uint32_t)enc[i] << 16;
                    if (i + 1 < elen) v |= (uint32_t)enc[i + 1] << 8;
                    if (i + 2 < elen) v |= (uint32_t)enc[i + 2];
                    b64_out[bp++] = b64[(v >> 18) & 0x3F];
                    b64_out[bp++] = b64[(v >> 12) & 0x3F];
                    b64_out[bp++] = (i + 1 < elen) ? b64[(v >> 6) & 0x3F] : '=';
                    b64_out[bp++] = (i + 2 < elen) ? b64[v & 0x3F] : '=';
                }
                b64_out[bp] = '\0';
                char secure[800];
                snprintf(secure, sizeof(secure),
                    "{\"type\":\"ble_secure\",\"version\":1,\"crypto\":\"%s\","
                    "\"epoch\":%d,\"payloadBase64\":\"%s\"}",
                    use_aes ? "AES" : "SM4", ble_crypto_epoch(), b64_out);
                send_notify_text(secure);
                return;
            }
        }
        /* 明文 ACK */
        send_notify_text(ack);
    } else if (strcmp(cmd, "door") == 0 && (val == 0 || val == 1)) {
        int pri = 10;
        j_int(json, "priority", &pri);

        bool ok;
        if (val == 1) ok = door_unlock(pri, 0, seq);
        else          ok = door_lock(pri, seq);

        bool locked = door_is_locked();
        bool is_open = door_is_open();
        char ack[256];
        int alen = snprintf(ack, sizeof(ack),
            "{\"type\":\"ack\",\"cmd\":\"door\",\"ok\":%s,"
            "\"locked\":%s,\"doorOpen\":%s,\"seq\":%d}",
            ok ? "true" : "false", locked ? "true" : "false",
            is_open ? "true" : "false", seq);
        ESP_LOGI(TAG, "Door→%s ok=%s locked=%s doorOpen=%s seq=%d",
                 val ? "UNLOCK" : "LOCK", ok ? "true" : "false",
                 locked ? "true" : "false", is_open ? "true" : "false", seq);

        if (ble_crypto_ready()) {
            uint8_t enc[512];
            int elen = use_aes
                ? ble_crypto_aes_encrypt((const uint8_t *)ack, (size_t)alen, enc, sizeof(enc))
                : ble_crypto_sm4_encrypt((const uint8_t *)ack, (size_t)alen, enc, sizeof(enc));
            if (elen > 0) {
                char b64_out[700];
                static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                int bp = 0;
                for (int i = 0; i < elen; i += 3) {
                    uint32_t v = (uint32_t)enc[i] << 16;
                    if (i + 1 < elen) v |= (uint32_t)enc[i + 1] << 8;
                    if (i + 2 < elen) v |= (uint32_t)enc[i + 2];
                    b64_out[bp++] = b64[(v >> 18) & 0x3F];
                    b64_out[bp++] = b64[(v >> 12) & 0x3F];
                    b64_out[bp++] = (i + 1 < elen) ? b64[(v >> 6) & 0x3F] : '=';
                    b64_out[bp++] = (i + 2 < elen) ? b64[v & 0x3F] : '=';
                }
                b64_out[bp] = '\0';
                char secure[800];
                snprintf(secure, sizeof(secure),
                    "{\"type\":\"ble_secure\",\"version\":1,\"crypto\":\"%s\","
                    "\"epoch\":%d,\"payloadBase64\":\"%s\"}",
                    use_aes ? "AES" : "SM4", ble_crypto_epoch(), b64_out);
                send_notify_text(secure);
                return;
            }
        }
        send_notify_text(ack);
    } else {
        ESP_LOGW(TAG, "Unknown cmd=%s val=%d", cmd, val);
    }
}

/* ---- BLE 传感器主动上报 ---- */
static int g_ble_sensor_seq = 0;
static int64_t g_ble_sensor_suppress_until = 0;  /* 协商后 3s 内不上报, 让 ACK 先出去 */

void ble_bridge_report_sensor(float temp, float hum, int pir, float lux)
{
    if (!ble_crypto_ready()) return;
    if (esp_timer_get_time() < g_ble_sensor_suppress_until) return;

    bool door_open = door_is_open();
    bool door_locked = door_is_locked();
    int led_state = 0;
    if (xSemaphoreTake(s_sys_mutex, pdMS_TO_TICKS(50)) == pdTRUE) {
        led_state = s_sys_data.led_on;
        xSemaphoreGive(s_sys_mutex);
    }
    char json[200];
    int jlen = snprintf(json, sizeof(json),
        "{\"tp\":%.1f,\"h\":%.1f,\"p\":%d,\"l\":%d,\"lx\":%.1f,"
        "\"do\":%d,\"dl\":%d,\"sq\":%d}",
        temp, hum, pir, led_state, lux,
        door_open ? 1 : 0, door_locked ? 1 : 0,
        ++g_ble_sensor_seq);

    /* 加密 → ble_secure → Notify (默认 SM4, 与灯光 ACK 一致) */
    uint8_t enc[512];
    int elen = ble_crypto_sm4_encrypt((const uint8_t *)json, (size_t)jlen, enc, sizeof(enc));
    if (elen <= 0) return;

    char b64_out[700];
    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int bp = 0;
    for (int i = 0; i < elen; i += 3) {
        uint32_t v = (uint32_t)enc[i] << 16;
        if (i + 1 < elen) v |= (uint32_t)enc[i + 1] << 8;
        if (i + 2 < elen) v |= (uint32_t)enc[i + 2];
        b64_out[bp++] = b64[(v >> 18) & 0x3F];
        b64_out[bp++] = b64[(v >> 12) & 0x3F];
        b64_out[bp++] = (i + 1 < elen) ? b64[(v >> 6) & 0x3F] : '=';
        b64_out[bp++] = (i + 2 < elen) ? b64[v & 0x3F] : '=';
    }
    b64_out[bp] = '\0';

    char secure[800];
    snprintf(secure, sizeof(secure),
        "{\"type\":\"ble_secure\",\"version\":1,\"crypto\":\"SM4\","
        "\"epoch\":%d,\"payloadBase64\":\"%s\"}",
        ble_crypto_epoch(), b64_out);
    send_notify_text(secure);
    ESP_LOGI(TAG, "Sensor report: temp=%.1f hum=%.1f pir=%d lux=%.1f seq=%d",
             temp, hum, pir, lux, g_ble_sensor_seq);
}

/* ---- business_cmd 入口 ---- */
bool ble_bridge_on_command(const uint8_t *data, uint16_t len)
{
    if (!s_initialized) return false;

    char json[512] = {0};
    uint16_t copy_len = len < 511 ? len : 511;
    memcpy(json, data, copy_len);
    json[copy_len] = '\0';  /* 确保 null-terminated */
    ESP_LOGI(TAG, "rx len=%d str=%d last4=%02X%02X%02X%02X", (int)len, (int)strlen(json),
             (uint8_t)json[copy_len-4], (uint8_t)json[copy_len-3], (uint8_t)json[copy_len-2], (uint8_t)json[copy_len-1]);

    char type_buf[32] = {0};
    j_str(json, "type", type_buf, sizeof(type_buf));

    /* 1. 密钥交换 — 提取公钥后直接传给 crypto 模块 */
    if (strcmp(type_buf, "ble_key_exchange") == 0) {
        int epoch = 0; j_int(json, "epoch", &epoch);
        /* 提取 publicKeyBase64: json 末尾 "\":\"...\"" → 最后一个":"到最后一个" 之间 */
        char dayu_b64[200] = {0};
        const char *last_colon = NULL;
        for (const char *p = json; *p; p++) {
            if (p[0] == '"' && p[1] == ':' && p[2] == '"') last_colon = p + 3;
        }
        if (last_colon) {
            const char *end_quote = strchr(last_colon, '"');
            if (end_quote) { size_t l = (size_t)(end_quote - last_colon);
                if (l > 0 && l < sizeof(dayu_b64)) { memcpy(dayu_b64, last_colon, l); dayu_b64[l] = '\0'; }
            }
        }
        ESP_LOGI(TAG, "[BLE-ECDH] epoch=%d last_col=%p val_len=%d key=%.20s",
                 epoch, last_colon, last_colon ? (int)strlen(dayu_b64) : -1, dayu_b64);
        ble_crypto_do_ecdh(dayu_b64, epoch);

        /* 暂停周期上报 5s, 让公钥和 ACK 独占通道 */
        g_ble_sensor_suppress_until = esp_timer_get_time() + 5000000;

        /* Notify 队列负责真实的帧间隔；GATT 回调中不能阻塞 NimBLE。 */
        char pk_b64[180]; ble_crypto_get_pubkey_b64(pk_b64, sizeof(pk_b64));
        char resp[400];
        snprintf(resp, sizeof(resp),
            "{\"type\":\"ble_key_exchange\",\"action\":\"public-key\","
            "\"epoch\":%d,\"publicKeyBase64\":\"%s\"}", epoch, pk_b64);
        send_notify_text(resp);
        ESP_LOGI(TAG, "[BLE-ECDH] queued public key (epoch=%d)", epoch);

        /* 激活并排队一份紧凑确认，避免重复公钥扰乱对端状态机。 */
        ble_crypto_activate();
        char ack[200];
        int alen = snprintf(ack, sizeof(ack),
            "{\"type\":\"ack\",\"cmd\":\"key\",\"ok\":true,\"epoch\":%d}", epoch);
        uint8_t enc[512];
        int elen = ble_crypto_encrypt((const uint8_t *)ack, (size_t)alen, enc, sizeof(enc));
        if (elen > 0) {
            char b64_out[700], b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            int bp = 0;
            for (int i = 0; i < elen; i += 3) {
                uint32_t v = (uint32_t)enc[i] << 16;
                if (i + 1 < elen) v |= (uint32_t)enc[i + 1] << 8;
                if (i + 2 < elen) v |= (uint32_t)enc[i + 2];
                b64_out[bp++] = b64[(v >> 18) & 0x3F];
                b64_out[bp++] = b64[(v >> 12) & 0x3F];
                b64_out[bp++] = (i + 1 < elen) ? b64[(v >> 6) & 0x3F] : '=';
                b64_out[bp++] = (i + 2 < elen) ? b64[v & 0x3F] : '=';
            }
            b64_out[bp] = '\0';
            char secure[800];
            snprintf(secure, sizeof(secure),
                "{\"type\":\"ble_secure\",\"version\":1,\"crypto\":\"SM4\","
                "\"epoch\":%d,\"payloadBase64\":\"%s\"}", epoch, b64_out);
            send_notify_text(secure);
            ESP_LOGI(TAG, "[BLE-ECDH] queued key ACK (epoch=%d len=%d)", epoch, (int)strlen(secure));
        }
        ESP_LOGI(TAG, "[BLE-ECDH] key exchange done epoch=%d", epoch);
        return true;
    }

    /* 2. 加密业务指令 */
    if (strcmp(type_buf, "ble_secure") == 0) {
        char crypto[8] = {0};
        j_str(json, "crypto", crypto, sizeof(crypto));
        bool use_aes = (strcmp(crypto, "AES") == 0);
        ESP_LOGI(TAG, "Secure: crypto=%s", crypto[0] ? crypto : "SM4(default)");

        char b64[512] = {0};
        j_str(json, "payloadBase64", b64, sizeof(b64));
        int dlen = 0; uint8_t *raw = NULL;
        /* base64 decode */ {
            static const signed char d[256] = {
                -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
                -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
                -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
                -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
            };
            int il = (int)strlen(b64); while (il > 0 && b64[il - 1] == '=') il--;
            int ol = (il * 3) / 4; raw = malloc(ol + 1);
            if (raw) {
                int ip = 0, op = 0;
                while (ip < il) { int v = 0, b = 0;
                    for (int i = 0; i < 4 && ip < il; i++, ip++) {
                        int c = d[(uint8_t)b64[ip]]; if (c < 0) goto b64fail;
                        v = (v << 6) | c; b++; }
                    if (b < 4) v <<= (4 - b) * 6;  /* 补齐到 24 位 */
                    if (b >= 2) { raw[op++] = (v >> 16) & 0xFF; v <<= 8; b--; }
                    if (b >= 2) { raw[op++] = (v >> 16) & 0xFF; v <<= 8; b--; }
                    if (b >= 2) { raw[op++] = (v >> 16) & 0xFF; v <<= 8; b--; }
                }
                dlen = op;
            }
            b64fail:;
        }
        if (!raw || dlen == 0) {
            ESP_LOGW(TAG, "Secure: base64 decode fail or empty");
        } else if (!ble_crypto_ready()) {
            ESP_LOGW(TAG, "Secure: BLE crypto not ready (need key exchange)");
        } else {
            /* 解密: [IV(12B)][TAG(16B)][CT] */
            if (dlen >= 12 + 16 + 1) {
                const uint8_t *iv  = raw;
                const uint8_t *tag = raw + 12;
                const uint8_t *ct  = raw + 28;
                uint8_t pt[512]; size_t pt_len = sizeof(pt);
                bool ok = use_aes
                    ? ble_crypto_aes_decrypt(ct, (size_t)(dlen - 28), iv, tag, pt, &pt_len)
                    : ble_crypto_sm4_decrypt(ct, (size_t)(dlen - 28), iv, tag, pt, &pt_len);
                if (ok) {
                    ESP_LOGI(TAG, "Secure decrypt OK (%s): %.*s", use_aes?"AES":"SM4", (int)pt_len, pt);
                    char inner_type[32] = {0};
                    j_str((const char *)pt, "type", inner_type, sizeof(inner_type));
                    if (strcmp(inner_type, "ble_key_exchange") != 0) {
                        handle_plain_cmd((const char *)pt, use_aes);
                    }
                } else ESP_LOGE(TAG, "Secure decrypt failed (%s)", use_aes?"AES":"SM4");
            }
        }
        free(raw);
        return true;
    }

    /* 3. 明文命令 (fallback) */
    handle_plain_cmd(json, false);
    return true;
}
