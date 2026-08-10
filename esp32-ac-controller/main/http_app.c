/**
 * @file  http_app.c
 * @brief HTTP 数据上报 + 命令轮询 — AC 控制器 + 多设备支持
 */
#include "http_app.h"
#include <string.h>
#include <stdlib.h>

extern bool ble_is_connected(void);

#if PROTO_ENABLE_HTTP

extern void ac_apply_state(const ac_state_t *target);

static const char b64_tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int base64_encode(const uint8_t *src, int slen, char *dst, int dlen) {
    int i, j = 0;
    for (i = 0; i < slen; i += 3) {
        int a = src[i], b = (i+1 < slen) ? src[i+1] : 0, c = (i+2 < slen) ? src[i+2] : 0;
        uint32_t t = ((uint32_t)a << 16) | ((uint32_t)b << 8) | c;
        if (j < dlen) dst[j++] = b64_tbl[(t >> 18) & 0x3F];
        if (j < dlen) dst[j++] = b64_tbl[(t >> 12) & 0x3F];
        if (j < dlen) dst[j++] = (i+1 < slen) ? b64_tbl[(t >> 6) & 0x3F] : '=';
        if (j < dlen) dst[j++] = (i+2 < slen) ? b64_tbl[t & 0x3F] : '=';
    }
    if (j < dlen) dst[j] = '\0';
    return j;
}

static int base64_decode(const char *src, int slen, uint8_t *dst, int dlen) {
    int j = 0;
    for (int i = 0; i < slen; i += 4) {
        int v[4] = {-1,-1,-1,-1};
        for (int k = 0; k < 4 && i+k < slen; k++) {
            char c = src[i+k];
            if (c == '=') { continue; }
            char *p = strchr(b64_tbl, c);
            if (p) { v[k] = (int)(p - b64_tbl); }
        }
        if (v[0] >= 0) {
            uint32_t t = ((uint32_t)v[0] << 18) | ((v[1] >= 0 ? (uint32_t)v[1] : 0) << 12);
            if (v[2] >= 0) t |= ((v[2] >= 0 ? (uint32_t)v[2] : 0) << 6);
            if (v[2] >= 0) t |= (uint32_t)(v[3] >= 0 ? v[3] : 0);
            if (j < dlen) dst[j++] = (uint8_t)(t >> 16);
            if (v[2] >= 0 && j < dlen) dst[j++] = (uint8_t)(t >> 8);
            if (v[3] >= 0 && j < dlen) dst[j++] = (uint8_t)t;
        }
    }
    return j;
}

/* 通用 HTTP ACK 发送: 加密后 POST /api/http/sensor */
static void send_http_ack_raw(const char *ack_json)
{
    int ack_len = strlen(ack_json);
    uint8_t ack_iv[AES_IV_LEN], ack_ct[256], ack_tag[AES_TAG_LEN];
    size_t ack_ct_len = 0;
    esp_fill_random(ack_iv, sizeof(ack_iv));
    if (!crypto_aes_encrypt((uint8_t *)ack_json, ack_len,
                           ack_iv, sizeof(ack_iv),
                           ack_ct, &ack_ct_len,
                           ack_tag, sizeof(ack_tag))) return;
    uint8_t *ack_pkt = malloc(AES_IV_LEN + AES_TAG_LEN + ack_ct_len);
    if (!ack_pkt) return;
    memcpy(ack_pkt, ack_iv, AES_IV_LEN);
    memcpy(ack_pkt + AES_IV_LEN, ack_tag, AES_TAG_LEN);
    memcpy(ack_pkt + AES_IV_LEN + AES_TAG_LEN, ack_ct, ack_ct_len);
    int ack_pkt_len = AES_IV_LEN + AES_TAG_LEN + (int)ack_ct_len;
    int b64_max = (ack_pkt_len + 2) / 3 * 4 + 4;
    char *b64 = malloc(b64_max);
    if (!b64) { free(ack_pkt); return; }
    base64_encode(ack_pkt, ack_pkt_len, b64, b64_max);
    free(ack_pkt);
    char *body = malloc(b64_max + 300);
    if (!body) { free(b64); return; }
    char t[64]; snprintf(t, sizeof(t), "device/%s/ac", s_device_id);
    int body_len = snprintf(body, b64_max + 300,
        "{\"deviceId\":\"%s\",\"topic\":\"%s\","
        "\"payloadBase64\":\"%s\",\"crypto\":\"%s\"}",
        s_device_id, t, b64, crypto_get_mode() ? "sm4" : "aes");
    free(b64);
    char ack_url[256];
    snprintf(ack_url, sizeof(ack_url), "%s/api/http/sensor", g_pairing_config.http_url);
    esp_http_client_config_t ack_cfg = {
        .url = ack_url, .timeout_ms = 3000,
        .cert_pem = s_mqtt_ca_cert,
    };
    esp_http_client_handle_t ack_cli = esp_http_client_init(&ack_cfg);
    esp_http_client_set_method(ack_cli, HTTP_METHOD_POST);
    esp_http_client_set_header(ack_cli, "Content-Type", "application/json");
    esp_http_client_set_post_field(ack_cli, body, body_len);
    esp_err_t ack_err = esp_http_client_perform(ack_cli);
    ESP_LOGI(TAG_HTTP, "HTTP ACK POST %s (status=%d)",
             ack_err == ESP_OK ? "OK" : "FAIL",
             ack_err == ESP_OK ? esp_http_client_get_status_code(ack_cli) : 0);
    esp_http_client_cleanup(ack_cli);
    free(body);
}

/* 解析并执行大禹指令 */
static void process_cmd(const char *plain)
{
    ESP_LOGI(TAG_HTTP, "HTTP解密成功 [%s]: %s",
             crypto_get_mode()?"SM4":"AES", plain);
    ESP_LOGI(TAG_HTTP, "[CMD] crypto=%s epoch=%d keySource=%s",
             crypto_get_mode() ? "SM4" : "AES",
             key_layer_get_epoch(),
             key_layer_get_epoch() > 0 ? "dynamic" : "static");

    /* proto */
    if (strstr(plain, "\"cmd\":\"proto\"")) {
        const char *val = strstr(plain, "\"val\":\"http\"") ? "http" : "mqtt";
        g_proto_mode = (val[0] == 'h') ? PROTO_MODE_HTTP_ONLY : PROTO_MODE_MQTT_ONLY;
        ESP_LOGI(TAG_HTTP, "proto→%s", val);
        int sq = 0; char *sp = strstr(plain, "\"seq\":"); if (sp) sq = atoi(sp + 6);
        char ack[200];
        snprintf(ack, sizeof(ack),
            "{\"type\":\"ack\",\"cmd\":\"proto\",\"ok\":true,\"val\":\"%s\","
            "\"seq\":%d,\"deviceId\":\"%s\"}", val, sq, s_device_id);
        send_http_ack_raw(ack);
    }
    /* crypto */
    else if (strstr(plain, "\"cmd\":\"crypto\"")) {
        bool sm4 = strstr(plain, "\"val\":\"sm4\"") != NULL;
        if (sm4 || strstr(plain, "\"val\":\"aes\"")) {
            crypto_set_mode(sm4);
            const char *val = sm4 ? "sm4" : "aes";
            ESP_LOGI(TAG_HTTP, "crypto→%s", val);
            int sq = 0; char *sp = strstr(plain, "\"seq\":"); if (sp) sq = atoi(sp + 6);
            char ack[200];
            snprintf(ack, sizeof(ack),
                "{\"type\":\"ack\",\"cmd\":\"crypto\",\"ok\":true,\"val\":\"%s\","
                "\"seq\":%d,\"deviceId\":\"%s\"}", val, sq, s_device_id);
            send_http_ack_raw(ack);
        }
    }
    /* AC */
    else if (strstr(plain, "\"cmd\":\"ac\"")) {
        ac_state_t target;
        if (xSemaphoreTake(s_ac_mutex, pdMS_TO_TICKS(200)) == pdTRUE) {
            memcpy(&target, &s_ac_state, sizeof(target));
            xSemaphoreGive(s_ac_mutex);
        } else { memset(&target, 0, sizeof(target)); target.target_temp = 26.0f; }

        char *pp = strstr(plain, "\"power\":");
        if (pp) { char *ts=strstr(pp,"true"),*fs=strstr(pp,"false");
                  if(ts&&ts<pp+20) target.power=1; else if(fs&&fs<pp+20) target.power=0; }
        char *tp = strstr(plain, "\"temp\":"); if(tp) target.target_temp = (float)atof(tp+7);
        char *mp = strstr(plain, "\"mode\":\""); if(mp) { mp+=8;
            if(strncmp(mp,"cool",4)==0) target.mode=0;
            else if(strncmp(mp,"heat",4)==0) target.mode=1;
            else if(strncmp(mp,"fan",3)==0) target.mode=2;
            else if(strncmp(mp,"dry",3)==0) target.mode=3; }
        char *fp2=strstr(plain,"\"fan\":\""); if(fp2){fp2+=6;
            if(strncmp(fp2,"auto",4)==0) target.fan_speed=0;
            else if(strncmp(fp2,"low",3)==0) target.fan_speed=1;
            else if(strncmp(fp2,"mid",3)==0) target.fan_speed=2;
            else if(strncmp(fp2,"high",4)==0) target.fan_speed=3; }
        char *sp=strstr(plain,"\"swing\":"); if(sp){char*ts=strstr(sp,"true"),*fs=strstr(sp,"false");
                 if(ts&&ts<sp+20) target.swing=1; else if(fs&&fs<sp+20) target.swing=0; }
        int seq=0; char*sq=strstr(plain,"\"seq\":"); if(sq) seq=atoi(sq+6);

        ESP_LOGI(TAG_HTTP, "AC→power=%d temp=%.0f mode=%d fan=%d swing=%d",
                 target.power, target.target_temp, target.mode, target.fan_speed, target.swing);
        if (xSemaphoreTake(s_ac_mutex, pdMS_TO_TICKS(500)) == pdTRUE) {
            ac_apply_state(&target); xSemaphoreGive(s_ac_mutex); }

        char ack[300];
        snprintf(ack, sizeof(ack),
            "{\"type\":\"ack\",\"cmd\":\"ac\",\"ok\":true,"
            "\"power\":%s,\"temp\":%.0f,\"mode\":\"%s\","
            "\"fan\":\"%s\",\"swing\":%s,\"seq\":%d,\"deviceId\":\"%s\"}",
            target.power?"true":"false", target.target_temp,
            target.mode==0?"cool":target.mode==1?"heat":target.mode==2?"fan":"dry",
            target.fan_speed==0?"auto":target.fan_speed==1?"low":target.fan_speed==2?"mid":"high",
            target.swing?"true":"false", seq, s_device_id);
        send_http_ack_raw(ack);
    }
    /* alarm */
    else if (strstr(plain, "\"cmd\":\"alarm\"") && strstr(plain, "\"action\":\"off\"")) {
        int seq=0; char*sq=strstr(plain,"\"seq\":"); if(sq) seq=atoi(sq+6);
        alarm_clear();
        char ack[200];
        snprintf(ack, sizeof(ack),
            "{\"type\":\"ack\",\"cmd\":\"alarm\","
            "\"action\":\"off\",\"ok\":true,"
            "\"seq\":%d,\"deviceId\":\"%s\","
            "\"msg\":\"alarm cleared\"}", seq, s_device_id);
        send_http_ack_raw(ack);
        ESP_LOGI(TAG_HTTP, "报警解除 ACK 已发送");
    }
    /* factory_reset */
    else if (strstr(plain, "\"cmd\":\"factory_reset\"")) {
        int seq=0; char*sq=strstr(plain,"\"seq\":"); if(sq) seq=atoi(sq+6);
        char ack[200];
        snprintf(ack, sizeof(ack),
            "{\"type\":\"ack\",\"cmd\":\"factory_reset\",\"ok\":true,"
            "\"seq\":%d,\"deviceId\":\"%s\","
            "\"msg\":\"erasing and reboot\"}", seq, s_device_id);
        send_http_ack_raw(ack);
        vTaskDelay(pdMS_TO_TICKS(500));
        pairing_factory_reset();
    }
    /* curtain */
    else if (strstr(plain, "\"cmd\":\"curtain\"")) {
        int seq=0; char*sq=strstr(plain,"\"seq\":"); if(sq) seq=atoi(sq+6);
        char *vp = strstr(plain, "\"val\":");
        int val = vp ? atoi(vp + 6) : -1;
        if (val >= 0 && val <= 100) {
            stepper_set_target((uint8_t)val);
            uint8_t actual = stepper_get_position();
            char ack[200];
            snprintf(ack, sizeof(ack),
                "{\"type\":\"ack\",\"cmd\":\"curtain\",\"ok\":true,"
                "\"val\":%d,\"seq\":%d,\"deviceId\":\"%s\"}",
                actual, seq, s_device_id);
            send_http_ack_raw(ack);
        } else {
            char ack[200];
            snprintf(ack, sizeof(ack),
                "{\"type\":\"ack\",\"cmd\":\"curtain\",\"ok\":false,"
                "\"msg\":\"missing val\",\"seq\":%d,"
                "\"deviceId\":\"%s\"}", seq, s_device_id);
            send_http_ack_raw(ack);
        }
    }
    /* IR */
    else if (strstr(plain, "\"cmd\":\"ir\"")) {
        char *akp = strstr(plain, "\"action\":\"");
        char *ikp = strstr(plain, "\"index\":");
        int idx = ikp ? atoi(ikp + 8) : -1;
        int seq = 0; char *sq = strstr(plain, "\"seq\":"); if (sq) seq = atoi(sq + 6);

        if (akp) {
            char action[16] = {0};
            strncpy(action, akp + 10, sizeof(action) - 1);
            char *eq = strchr(action, '"'); if (eq) *eq = '\0';

            if (strcmp(action, "learn") == 0 && idx >= 1 && idx <= 6) {
                ESP_LOGI(TAG_HTTP, "IR learn idx=%d", idx);
                if (ir_enter_learn((uint8_t)idx) != 0) {
                    char ack[200]; snprintf(ack, sizeof(ack),
                        "{\"type\":\"ack\",\"cmd\":\"ir\",\"action\":\"learn\","
                        "\"ok\":false,\"index\":%d,\"msg\":\"enter failed\","
                        "\"seq\":%d,\"deviceId\":\"%s\"}", idx, seq, s_device_id);
                    send_http_ack_raw(ack);
                } else {
                    ir_report_t report;
                    int ret = ir_wait_learn_report(&report, 65000);
                    if (ret == 0 && report.flag == IR_REPORT_LEARN_OK && report.status == 0) {
                        char ack[200]; snprintf(ack, sizeof(ack),
                            "{\"type\":\"ack\",\"cmd\":\"ir\",\"action\":\"learn\","
                            "\"ok\":true,\"index\":%d,\"keyName\":\"%s\",\"msg\":\"learned\","
                            "\"seq\":%d,\"deviceId\":\"%s\"}", idx, ac_key_names[idx], seq, s_device_id);
                        send_http_ack_raw(ack);
                    } else {
                        ir_exit_learn();
                        char ack[200]; snprintf(ack, sizeof(ack),
                            "{\"type\":\"ack\",\"cmd\":\"ir\",\"action\":\"learn\","
                            "\"ok\":false,\"index\":%d,\"msg\":\"timeout\","
                            "\"seq\":%d,\"deviceId\":\"%s\"}", idx, seq, s_device_id);
                        send_http_ack_raw(ack);
                    }
                }
            }
            else if (strcmp(action, "send") == 0 && idx >= 1 && idx <= 6) {
                int ret = ir_send_stored_code((uint8_t)idx);
                char ack[200]; snprintf(ack, sizeof(ack),
                    "{\"type\":\"ack\",\"cmd\":\"ir\",\"action\":\"send\","
                    "\"ok\":%s,\"index\":%d,\"keyName\":\"%s\","
                    "\"seq\":%d,\"deviceId\":\"%s\"}",
                    ret==0?"true":"false", idx, ac_key_names[idx], seq, s_device_id);
                send_http_ack_raw(ack);
            }
            else if (strcmp(action, "read") == 0 && idx >= 1 && idx <= 6) {
                uint8_t code[512]; uint16_t clen = 0;
                if (ir_read_code((uint8_t)idx, code, sizeof(code), &clen) == 0 && clen > 0) {
                    char hex[128], *hp = hex;
                    for (uint16_t i = 0; i < clen && i < 32; i++) hp += snprintf(hp, 3, "%02X", code[i]);
                    if (clen > 32) { *hp++ = '.'; *hp++ = '.'; *hp = '\0'; }
                    char ack[300]; snprintf(ack, sizeof(ack),
                        "{\"type\":\"ack\",\"cmd\":\"ir\",\"action\":\"read\","
                        "\"ok\":true,\"index\":%d,\"len\":%d,\"hex\":\"%s\","
                        "\"seq\":%d,\"deviceId\":\"%s\"}", idx, clen, hex, seq, s_device_id);
                    send_http_ack_raw(ack);
                } else {
                    char ack[200]; snprintf(ack, sizeof(ack),
                        "{\"type\":\"ack\",\"cmd\":\"ir\",\"action\":\"read\","
                        "\"ok\":false,\"index\":%d,\"msg\":\"empty\","
                        "\"seq\":%d,\"deviceId\":\"%s\"}", idx, seq, s_device_id);
                    send_http_ack_raw(ack);
                }
            }
            else if (strcmp(action, "learn-all") == 0) {
                char ack[200];
                snprintf(ack, sizeof(ack),
                    "{\"type\":\"ack\",\"cmd\":\"ir\",\"action\":\"learn-all\","
                    "\"ok\":true,\"msg\":\"learning 1~6, ~6min\","
                    "\"seq\":%d,\"deviceId\":\"%s\"}", seq, s_device_id);
                send_http_ack_raw(ack);
                ESP_LOGI(TAG_HTTP, "IR learn-all start");
                for (int i = 1; i <= 6; i++) {
                    ESP_LOGI(TAG_HTTP, "learn idx=%d (%s)...", i, ac_key_names[i]);
                    if (ir_enter_learn((uint8_t)i) != 0) { continue; }
                    ir_report_t report;
                    int ret = ir_wait_learn_report(&report, 65000);
                    if (ret == 0 && report.flag == IR_REPORT_LEARN_OK && report.status == 0) {
                        snprintf(ack, sizeof(ack),
                            "{\"type\":\"ack\",\"cmd\":\"ir\",\"action\":\"learn\","
                            "\"ok\":true,\"index\":%d,\"keyName\":\"%s\","
                            "\"msg\":\"learned\",\"seq\":%d,\"deviceId\":\"%s\"}",
                            i, ac_key_names[i], seq, s_device_id);
                    } else {
                        ir_exit_learn();
                        snprintf(ack, sizeof(ack),
                            "{\"type\":\"ack\",\"cmd\":\"ir\",\"action\":\"learn\","
                            "\"ok\":false,\"index\":%d,\"keyName\":\"%s\","
                            "\"msg\":\"timeout\",\"seq\":%d,\"deviceId\":\"%s\"}",
                            i, ac_key_names[i], seq, s_device_id);
                    }
                    send_http_ack_raw(ack);
                    if (i < 6) vTaskDelay(pdMS_TO_TICKS(3000));
                }
                ESP_LOGI(TAG_HTTP, "IR learn-all done");
            }
            else if (strcmp(action, "exit") == 0 || strcmp(action, "format") == 0 || strcmp(action, "reset") == 0) {
                int ret = 0;
                if (strcmp(action, "exit") == 0) ret = ir_exit_learn();
                else if (strcmp(action, "format") == 0) ret = ir_format();
                else ret = ir_reset();
                char ack[200]; snprintf(ack, sizeof(ack),
                    "{\"type\":\"ack\",\"cmd\":\"ir\",\"action\":\"%s\","
                    "\"ok\":%s,\"seq\":%d,\"deviceId\":\"%s\"}",
                    action, ret==0?"true":"false", seq, s_device_id);
                send_http_ack_raw(ack);
            }
        }
    }
}

/* ======================== HTTP 任务 ======================== */

void http_task(void *pvParameters)
{
    char sensor_url[256];
    snprintf(sensor_url, sizeof(sensor_url), "%s/api/http/sensor", g_pairing_config.http_url);
    ESP_LOGI(TAG_HTTP, "HTTP task start → %s", sensor_url);

    int poll_seq = 0;

    while (1) {
        alarm_read();

        if (g_proto_mode == PROTO_MODE_MQTT_ONLY) {
            vTaskDelay(pdMS_TO_TICKS(TASK_LOOP_INTERVAL_MS));
            continue;
        }

        /* 读 AC 状态 */
        ac_state_t cur;
        if (xSemaphoreTake(s_ac_mutex, pdMS_TO_TICKS(200)) == pdTRUE) {
            memcpy(&cur, &s_ac_state, sizeof(cur));
            xSemaphoreGive(s_ac_mutex);
        } else { vTaskDelay(pdMS_TO_TICKS(100)); continue; }

        /* 报警数据 */
        alarm_data_t alm;
        if (xSemaphoreTake(s_alarm_mutex, pdMS_TO_TICKS(50)) == pdTRUE) {
            memcpy(&alm, &s_alarm_data, sizeof(alm));
            xSemaphoreGive(s_alarm_mutex);
        } else { memset(&alm, 0, sizeof(alm)); }

        /* 报警事件 — BLE 连接时走 BLE 上报, 不重复发 */
        if (!ble_is_connected() && alarm_check_and_send()) {
            char alarm_json[300];
            snprintf(alarm_json, sizeof(alarm_json),
                "{\"type\":\"alarm\",\"dev\":\"%s\","
                "\"smoke\":{\"alarm\":%s,\"raw\":%d,\"voltage\":%.2f},"
                "\"water\":{\"alarm\":%s,\"raw\":%d,\"voltage\":%.2f},"
                "\"deviceId\":\"%s\"}",
                s_device_id,
                alm.smoke_alarm?"true":"false", alm.smoke_raw, alm.smoke_voltage,
                alm.water_alarm?"true":"false", alm.water_raw, alm.water_voltage,
                s_device_id);
            send_http_ack_raw(alarm_json);
        }

        /* 状态上报 JSON */
        char json_buf[512];
        int json_len = snprintf(json_buf, sizeof(json_buf),
            "{\"proto\":\"http\",\"dev\":\"%s\","
            "\"power\":%s,\"temp\":%.0f,\"mode\":\"%s\","
            "\"fan\":\"%s\",\"swing\":%s,"
            "\"smoke\":{\"raw\":%d,\"voltage\":%.2f,\"alarm\":%s},"
            "\"water\":{\"raw\":%d,\"voltage\":%.2f,\"alarm\":%s},"
            "\"deviceId\":\"%s\"}",
            s_device_id, cur.power?"true":"false", cur.target_temp,
            cur.mode==0?"cool":cur.mode==1?"heat":cur.mode==2?"fan":"dry",
            cur.fan_speed==0?"auto":cur.fan_speed==1?"low":cur.fan_speed==2?"mid":"high",
            cur.swing?"true":"false",
            alm.smoke_raw, alm.smoke_voltage, alm.smoke_alarm?"true":"false",
            alm.water_raw, alm.water_voltage, alm.water_alarm?"true":"false",
            s_device_id);

        uint8_t iv[AES_IV_LEN], ct[256], tag[AES_TAG_LEN];
        size_t ct_len = 0;
        esp_fill_random(iv, sizeof(iv));
        if (!crypto_aes_encrypt((uint8_t *)json_buf, json_len, iv, sizeof(iv),
                                ct, &ct_len, tag, sizeof(tag))) {
            vTaskDelay(pdMS_TO_TICKS(TASK_LOOP_INTERVAL_MS));
            continue;
        }
        uint8_t enc_pkt[350];
        memcpy(enc_pkt, iv, AES_IV_LEN);
        memcpy(enc_pkt + AES_IV_LEN, tag, AES_TAG_LEN);
        memcpy(enc_pkt + AES_IV_LEN + AES_TAG_LEN, ct, ct_len);
        int enc_len = AES_IV_LEN + AES_TAG_LEN + (int)ct_len;

        char b64[512];
        base64_encode(enc_pkt, enc_len, b64, sizeof(b64));

        char t[64]; snprintf(t, sizeof(t), "device/%s/ac", s_device_id);
        char post_body[800];
        int body_len = snprintf(post_body, sizeof(post_body),
            "{\"deviceId\":\"%s\",\"topic\":\"%s\",\"payloadBase64\":\"%s\",\"crypto\":\"%s\"}",
            s_device_id, t, b64, crypto_get_mode() ? "sm4" : "aes");

        /* POST 上报 */
        esp_http_client_config_t cfg = {
            .url = sensor_url, .timeout_ms = 5000,
            .cert_pem = s_mqtt_ca_cert,
        };
        esp_http_client_handle_t cli = esp_http_client_init(&cfg);
        esp_http_client_set_method(cli, HTTP_METHOD_POST);
        esp_http_client_set_header(cli, "Content-Type", "application/json");
        esp_http_client_set_post_field(cli, post_body, body_len);
        esp_err_t err = esp_http_client_perform(cli);
        if (err == ESP_OK) ESP_LOGI(TAG_HTTP, "POST OK (%d)", esp_http_client_get_status_code(cli));
        else ESP_LOGW(TAG_HTTP, "POST fail %d", err);
        esp_http_client_cleanup(cli);

        /* GET 轮询本机命令 */
        poll_seq++;
        char poll_url[256];
        snprintf(poll_url, sizeof(poll_url),
                 "%s/api/http/command?deviceId=%s",
                 g_pairing_config.http_url, s_device_id);
        esp_http_client_config_t gcfg = {
            .url = poll_url, .timeout_ms = 3000,
            .cert_pem = s_mqtt_ca_cert,
        };
        esp_http_client_handle_t gcli = esp_http_client_init(&gcfg);
        esp_http_client_set_method(gcli, HTTP_METHOD_GET);
        esp_err_t gerr = esp_http_client_open(gcli, 0);
        if (gerr == ESP_OK) {
            int rlen = esp_http_client_fetch_headers(gcli);
            if (rlen < 0) rlen = 4096;
            uint8_t *rbuf = malloc(rlen + 1);
            int actual = 0;
            if (rbuf) {
                actual = esp_http_client_read(gcli, (char *)rbuf, rlen);
                if (actual < 0) actual = 0;
                rbuf[actual] = '\0';
            }
            if (rbuf && actual > 30 && rbuf[0] == '{') {
                if (!strstr((char *)rbuf, "\"hasCommand\":true")) {
                    free(rbuf); rbuf = NULL;
                    goto poll_done;
                }
                {   char *did = strstr((char *)rbuf, "\"deviceId\":\"");
                    if (!did || strncmp(did + 12, s_device_id, strlen(s_device_id)) != 0) {
                        free(rbuf); rbuf = NULL;
                        goto poll_done;
                    }
                }
                char *b64s = strstr((char *)rbuf, "\"payloadBase64\":\"");
                if (b64s) {
                    b64s += 17;
                    char *b64e = strchr(b64s, '"');
                    if (b64e) {
                        *b64e = '\0';
                        int b64len = strlen(b64s);
                        uint8_t *dec = malloc(b64len);
                        int dlen = base64_decode(b64s, b64len, dec, b64len);
                        /* ECDH 公钥 (65B, 0x04开头) → 绕过GCM */
                        if (dlen == 65 && dec[0] == 0x04) {
                            ESP_LOGI(TAG_HTTP, "HTTP ECDH pubkey bypass");
                            key_layer_negotiate(dec, dlen);
                        }
                        else if (dlen >= 29) {
                            const uint8_t *ivp = dec, *tgp = dec + AES_IV_LEN;
                            const uint8_t *ctp = dec + AES_IV_LEN + AES_TAG_LEN;
                            size_t clen = dlen - AES_IV_LEN - AES_TAG_LEN;
                            uint8_t plain[256]; size_t plen = 0;
                            bool ok = crypto_decrypt_fallback(ctp, clen, ivp, AES_IV_LEN,
                                                               tgp, AES_TAG_LEN, plain, &plen);
                            if (ok) plen = clen;
                            if (ok) {
                                plain[plen] = '\0';
                                ESP_LOGI(TAG_HTTP, "解密OK: %s", plain);
                                process_cmd((char *)plain);
                            }
                        }
                        free(dec);
                    }
                }
            }
            poll_done:
            if (rbuf) free(rbuf);
        }
        esp_http_client_close(gcli);
        esp_http_client_cleanup(gcli);

        vTaskDelay(pdMS_TO_TICKS(TASK_LOOP_INTERVAL_MS));
    }
}
#endif /* PROTO_ENABLE_HTTP */
