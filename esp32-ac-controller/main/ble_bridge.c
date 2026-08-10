/**
 * @file  ble_bridge.c — AC Controller BLE 通信桥接
 * 密钥交换 + 加密指令 (AC/窗帘/报警) + 烟雾/水浸传感器上报
 */
#include "ble_bridge.h"
#include "ble_peripheral.h"
#include "ble_crypto.h"
#include "crypto_layer.h"
#include "alarm.h"
#include "stepper.h"
#include "main_config.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>
#include <stdio.h>

static const char *TAG = "BLE_BRG";
static bool s_initialized = false;

static void send_notify_text(const char *text)
{
    ble_notify_device_event((const uint8_t *)text, (uint16_t)strlen(text));
    ESP_LOGI(TAG, "Notify text: %s", text);
}

void ble_bridge_init(const char *device_id)
{
    s_initialized = true;
    ble_set_business_cmd_callback(ble_bridge_on_command);
    ESP_LOGI(TAG, "BLE bridge init for %s", device_id);
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
static bool j_float(const char *j, const char *k, float *o) {
    char buf[32]; if (!j_str(j, k, buf, sizeof(buf))) {
        char p[32]; snprintf(p, sizeof(p), "\"%s\":", k);
        const char *s = strstr(j, p); if (!s) return false;
        *o = strtof(s + strlen(p), NULL); return true;
    }
    *o = strtof(buf, NULL); return true;
}

/* ---- 加密 ACK 发送 ---- */
static void send_encrypted_ack(const char *ack, int alen, bool use_aes)
{
    uint8_t enc[512];
    int elen = use_aes
        ? ble_crypto_aes_encrypt((const uint8_t *)ack, (size_t)alen, enc, sizeof(enc))
        : ble_crypto_sm4_encrypt((const uint8_t *)ack, (size_t)alen, enc, sizeof(enc));
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
        "{\"type\":\"ble_secure\",\"version\":1,\"crypto\":\"%s\","
        "\"epoch\":%d,\"payloadBase64\":\"%s\"}",
        use_aes ? "AES" : "SM4", ble_crypto_epoch(), b64_out);
    send_notify_text(secure);
}

/* ---- 处理明文业务命令 ---- */
extern void ac_apply_state(const ac_state_t *target);
extern ac_state_t s_ac_state;
extern SemaphoreHandle_t s_ac_mutex;

static void handle_plain_cmd(const char *json, bool use_aes)
{
    char cmd[16] = {0}; int val = -1, seq = 0;
    j_str(json, "cmd", cmd, sizeof(cmd));
    j_int(json, "seq", &seq);

    /* ---- 空调控制 ---- */
    if (strcmp(cmd, "ac") == 0) {
        ac_state_t tgt;
        memcpy(&tgt, &s_ac_state, sizeof(tgt));
        /* power: true/false */
        { const char *p = strstr(json, "\"power\":"); if (p) {
            if (strstr(p, "true")  && strstr(p, "true")  < p + 20) tgt.power = 1;
            if (strstr(p, "false") && strstr(p, "false") < p + 20) tgt.power = 0; }}
        j_float(json, "temp", &tgt.target_temp);
        /* mode: "cool"/"heat" */
        { char mbuf[8] = {0}; if (j_str(json, "mode", mbuf, sizeof(mbuf))) {
            if (strcmp(mbuf, "cool") == 0) tgt.mode = 0;
            else if (strcmp(mbuf, "heat") == 0) tgt.mode = 1; }}

        if (xSemaphoreTake(s_ac_mutex, pdMS_TO_TICKS(500)) == pdTRUE) {
            ac_apply_state(&tgt);
            xSemaphoreGive(s_ac_mutex);
        }
        char ack[256];
        int alen = snprintf(ack, sizeof(ack),
            "{\"type\":\"ack\",\"cmd\":\"ac\",\"ok\":true,"
            "\"power\":%s,\"temp\":%.0f,\"mode\":\"%s\","
            "\"seq\":%d,\"deviceId\":\"%s\"}",
            tgt.power ? "true" : "false", tgt.target_temp,
            tgt.mode == 0 ? "cool" : "heat", seq, s_device_id);
        ESP_LOGI(TAG, "AC: power=%d temp=%.0f mode=%d seq=%d",
                 tgt.power, tgt.target_temp, tgt.mode, seq);
        if (ble_crypto_ready()) { send_encrypted_ack(ack, alen, use_aes); return; }
        send_notify_text(ack);
        return;
    }

    /* ---- 窗帘控制 ---- */
    if (strcmp(cmd, "curtain") == 0) {
        j_int(json, "val", &val);
        if (val >= 0 && val <= 100) {
            stepper_set_target((uint8_t)val);
            char ack[256];
            int alen = snprintf(ack, sizeof(ack),
                "{\"type\":\"ack\",\"cmd\":\"curtain\",\"ok\":true,\"val\":%d,"
                "\"seq\":%d,\"deviceId\":\"%s\"}", val, seq, s_device_id);
            ESP_LOGI(TAG, "Curtain → %d%% (seq=%d)", val, seq);
            if (ble_crypto_ready()) { send_encrypted_ack(ack, alen, use_aes); return; }
            send_notify_text(ack);
            return;
        }
    }

    /* ---- 报警清除 ---- */
    if (strcmp(cmd, "alarm") == 0) {
        char abuf[8] = {0}; j_str(json, "action", abuf, sizeof(abuf));
        if (strcmp(abuf, "off") == 0) {
            alarm_clear();
            char ack[256];
            int alen = snprintf(ack, sizeof(ack),
                "{\"type\":\"ack\",\"cmd\":\"alarm\",\"action\":\"off\",\"ok\":true,"
                "\"seq\":%d,\"deviceId\":\"%s\"}", seq, s_device_id);
            ESP_LOGI(TAG, "Alarm cleared (seq=%d)", seq);
            if (ble_crypto_ready()) { send_encrypted_ack(ack, alen, use_aes); return; }
            send_notify_text(ack);
        }
        /* alarm received ACK */
        if (strcmp(abuf, "received") == 0) {
            bool sm = false, wt = false;
            { const char *p = strstr(json, "\"smoke\":"); if (p && strstr(p, "true") && strstr(p, "true") < p + 20) sm = true; }
            { const char *p = strstr(json, "\"water\":"); if (p && strstr(p, "true") && strstr(p, "true") < p + 20) wt = true; }
            ESP_LOGI(TAG, "Alarm ACK received: smoke=%d water=%d seq=%d", sm, wt, seq);
        }
        return;
    }

    ESP_LOGW(TAG, "Unknown cmd=%s seq=%d", cmd, seq);
}

/* ---- 协商后传感器抑制计时器 ---- */
static int64_t g_ble_sensor_suppress_until = 0;

/* ---- business_cmd 入口 ---- */
bool ble_bridge_on_command(const uint8_t *data, uint16_t len)
{
    if (!s_initialized) return false;

    char json[512] = {0};
    uint16_t copy_len = len < 511 ? len : 511;
    memcpy(json, data, copy_len);
    json[copy_len] = '\0';
    ESP_LOGI(TAG, "rx len=%d str=%d", (int)len, (int)strlen(json));

    char type_buf[32] = {0};
    j_str(json, "type", type_buf, sizeof(type_buf));

    /* 1. 密钥交换 */
    if (strcmp(type_buf, "ble_key_exchange") == 0) {
        int epoch = 0; j_int(json, "epoch", &epoch);
        char dayu_b64[200] = {0};
        const char *last_colon = NULL;
        for (const char *p = json; *p; p++)
            if (p[0] == '"' && p[1] == ':' && p[2] == '"') last_colon = p + 3;
        if (last_colon) {
            const char *end_quote = strchr(last_colon, '"');
            if (end_quote) { size_t l = (size_t)(end_quote - last_colon);
                if (l > 0 && l < sizeof(dayu_b64)) { memcpy(dayu_b64, last_colon, l); dayu_b64[l] = '\0'; }
            }
        }
        ESP_LOGI(TAG, "[BLE-ECDH] epoch=%d val_len=%d", epoch, last_colon ? (int)strlen(dayu_b64) : -1);
        ble_crypto_do_ecdh(dayu_b64, epoch);

        char pk_b64[180]; ble_crypto_get_pubkey_b64(pk_b64, sizeof(pk_b64));
        char resp[400];
        snprintf(resp, sizeof(resp),
            "{\"type\":\"ble_key_exchange\",\"action\":\"public-key\","
            "\"deviceId\":\"%s\",\"epoch\":%d,\"publicKeyBase64\":\"%s\"}",
            s_device_id, epoch, pk_b64);
        send_notify_text(resp);

        /* 延迟200ms 防网关连续Notify丢首帧 */
        vTaskDelay(pdMS_TO_TICKS(200));

        ble_crypto_activate();
        g_ble_sensor_suppress_until = esp_timer_get_time() + 3000000;
        char ack[200];
        int alen = snprintf(ack, sizeof(ack),
            "{\"type\":\"ack\",\"cmd\":\"key\",\"ok\":true,\"transport\":\"ble\","
            "\"epoch\":%d,\"deviceId\":\"%s\"}", epoch, s_device_id);
        if (ble_crypto_ready()) send_encrypted_ack(ack, alen, false);
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
        {
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
                    if (b < 4) v <<= (4 - b) * 6;
                    if (b >= 2) { raw[op++] = (v >> 16) & 0xFF; v <<= 8; b--; }
                    if (b >= 2) { raw[op++] = (v >> 16) & 0xFF; v <<= 8; b--; }
                    if (b >= 2) { raw[op++] = (v >> 16) & 0xFF; v <<= 8; b--; }
                }
                dlen = op;
            }
            b64fail:;
        }
        if (!raw || dlen == 0) {
            ESP_LOGW(TAG, "Secure: base64 decode fail");
        } else if (!ble_crypto_ready()) {
            ESP_LOGW(TAG, "Secure: BLE crypto not ready (need key exchange)");
        } else if (dlen >= 12 + 16 + 1) {
            const uint8_t *iv  = raw;
            const uint8_t *tag = raw + 12;
            const uint8_t *ct  = raw + 28;
            uint8_t pt[512]; size_t pt_len = sizeof(pt);
            bool ok = use_aes
                ? ble_crypto_aes_decrypt(ct, (size_t)(dlen - 28), iv, tag, pt, &pt_len)
                : ble_crypto_sm4_decrypt(ct, (size_t)(dlen - 28), iv, tag, pt, &pt_len);
            if (ok) {
                ESP_LOGI(TAG, "Secure decrypt OK (%s): %.*s", use_aes?"AES":"SM4", (int)pt_len, pt);
                handle_plain_cmd((const char *)pt, use_aes);
            } else ESP_LOGE(TAG, "Secure decrypt failed (%s)", use_aes?"AES":"SM4");
        }
        free(raw);
        return true;
    }

    /* 3. 明文 fallback */
    handle_plain_cmd(json, false);
    return true;
}

/* ---- BLE 传感器上报 (烟雾/水浸) ---- */
static int g_ble_sensor_seq = 0;
extern alarm_data_t s_alarm_data;
extern SemaphoreHandle_t s_alarm_mutex;

void ble_bridge_report_sensor(void)
{
    if (!ble_crypto_ready()) return;
    if (esp_timer_get_time() < g_ble_sensor_suppress_until) return;

    alarm_data_t ad = {0};
    if (xSemaphoreTake(s_alarm_mutex, pdMS_TO_TICKS(50)) == pdTRUE) {
        memcpy(&ad, &s_alarm_data, sizeof(ad));
        xSemaphoreGive(s_alarm_mutex);
    }

    char json[200];
    int jlen = snprintf(json, sizeof(json),
        "{\"t\":\"a\",\"s\":%d,\"w\":%d,"
        "\"sr\":%d,\"wr\":%d,\"sv\":%.2f,\"wv\":%.2f,\"sq\":%d}",
        ad.smoke_alarm ? 1 : 0, ad.water_alarm ? 1 : 0,
        ad.smoke_raw, ad.water_raw,
        ad.smoke_voltage, ad.water_voltage,
        ++g_ble_sensor_seq);

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
    ESP_LOGI(TAG, "Alarm report: s=%d/%d/%.2f w=%d/%d/%.2f sq=%d",
             ad.smoke_alarm, ad.smoke_raw, ad.smoke_voltage,
             ad.water_alarm, ad.water_raw, ad.water_voltage, g_ble_sensor_seq);
}
