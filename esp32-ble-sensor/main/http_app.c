/**
 * @file  http_app.c
 * @brief HTTP 数据上报 + 命令轮询
 */
#include "http_app.h"
#include <string.h>
#include <stdlib.h>
#include "door.h"

/* Topic strings (from mqtt_app.c) */
extern char t_sensor[64], t_ack[64], t_status[64], t_cmd[64];

#if PROTO_ENABLE_HTTP

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
    int j = 0, pads = 0;
    for (int i = 0; i < slen; i += 4) {
        int v[4] = {-1,-1,-1,-1};
        int valid = 0;
        for (int k = 0; k < 4 && i+k < slen; k++) {
            char c = src[i+k];
            if (c == '=') { pads++; continue; }
            pads = 0;
            char *p = strchr(b64_tbl, c);
            if (p) { v[k] = (int)(p - b64_tbl); valid++; }
        }
        if (v[0] >= 0) {
            uint32_t t = ((uint32_t)v[0] << 18) | ((v[1] >= 0 ? (uint32_t)v[1] : 0) << 12);
            if (v[1] >= 0) t |= ((v[2] >= 0 ? (uint32_t)v[2] : 0) << 6);
            if (v[1] >= 0) t |= (uint32_t)(v[3] >= 0 ? v[3] : 0);
            if (j < dlen) dst[j++] = (uint8_t)(t >> 16);
            if (valid >= 3 && j < dlen) dst[j++] = (uint8_t)(t >> 8);
            if (valid == 4 && j < dlen) dst[j++] = (uint8_t)t;
        }
    }
    return j;
}

static void build_sensor_url(char *buf, size_t size) {
    snprintf(buf, size, "%s/api/http/sensor", g_pairing_config.http_url);
}

/* 通用 HTTP ACK 发送: 接收完整明文 JSON, 加密后 POST 到 /api/http/sensor */
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
    char *body = malloc(b64_max + 256);
    if (!body) { free(b64); return; }
    int body_len = snprintf(body, b64_max + 256,
        "{\"deviceId\":\"%s\",\"topic\":\"%s\","
        "\"payloadBase64\":\"%s\",\"crypto\":\"%s\"}",
        s_device_id, t_ack, b64, crypto_get_mode() ? "sm4" : "aes");
    free(b64);
    char ack_url[256];
    build_sensor_url(ack_url, sizeof(ack_url));
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

static void send_http_ack(const char *cmd, const char *val, int sq)
{
    char ack[128];
    snprintf(ack, sizeof(ack),
        "{\"type\":\"ack\",\"cmd\":\"%s\",\"ok\":true,"
        "\"val\":\"%s\",\"seq\":%d}", cmd, val, sq);
    send_http_ack_raw(ack);
}

static void process_cmd(const char *plain) {
    ESP_LOGI(TAG_HTTP, "HTTP解密成功 [%s]: %s",
             crypto_get_mode()?"SM4":"AES", plain);
    if (strstr(plain, "\"cmd\":\"proto\"")) {
        const char *val = strstr(plain, "\"val\":\"http\"") ? "http" : "mqtt";
        g_proto_mode = (val[0] == 'h') ? PROTO_MODE_HTTP_ONLY : PROTO_MODE_MQTT_ONLY;
        ESP_LOGI(TAG_HTTP, "proto→%s", val);
        int sq = 0; char *sp = strstr(plain, "\"seq\":"); if (sp) sq = atoi(sp + 6);
        send_http_ack("proto", val, sq);
    }
    else if (strstr(plain, "\"cmd\":\"crypto\"")) {
        bool sm4 = strstr(plain, "\"val\":\"sm4\"") != NULL;
        if (sm4 || strstr(plain, "\"val\":\"aes\"")) {
            crypto_set_mode(sm4);
            const char *val = sm4 ? "sm4" : "aes";
            ESP_LOGI(TAG_HTTP, "crypto→%s", val);
            int sq = 0; char *sp = strstr(plain, "\"seq\":"); if (sp) sq = atoi(sp + 6);
            send_http_ack("crypto", val, sq);
        }
    }
    else if (strstr(plain, "\"cmd\":\"led\"")) {
        int v = -1, pr = 10, lm = 5000, sq = 0;
        char *vp = strstr(plain, "\"val\":"); if(vp)v=atoi(vp+6);
        char *pp = strstr(plain, "\"priority\":"); if(pp)pr=atoi(pp+11);
        char *lp = strstr(plain, "\"lockMs\":"); if(lp)lm=atoi(lp+9);
        char *sp = strstr(plain, "\"seq\":"); if(sp)sq=atoi(sp+6);
        if (v==0||v==1) {
            gpio_set_level(LED_GPIO, v?LED_ON_LEVEL:(1-LED_ON_LEVEL));
            ESP_LOGI(TAG_HTTP, "LED→%s pr=%d", v?"ON":"OFF", pr);
            if (xSemaphoreTake(s_sys_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
                s_sys_data.led_cmd=v; s_sys_data.led_on=v;
                strncpy(s_sys_data.led_lock.owner, "dayu", 15);
                s_sys_data.led_lock.priority=pr;
                s_sys_data.led_lock.lock_until_ms=xTaskGetTickCount()+pdMS_TO_TICKS((uint32_t)lm);
                s_sys_data.led_lock.last_seq=sq;
                xSemaphoreGive(s_sys_mutex);
            }
            /* HTTP LED ACK */
            char ack[200];
            snprintf(ack, sizeof(ack),
                "{\"type\":\"ack\",\"cmd\":\"led\",\"val\":%d,"
                "\"ok\":true,\"source\":\"esp32\","
                "\"appliedSource\":\"dayu\",\"priority\":%d,"
                "\"lockMs\":%d,\"seq\":%d,\"deviceId\":\"%s\"}",
                v, pr, lm, sq, s_device_id);
            send_http_ack_raw(ack);
        }
    }
    else if (strstr(plain, "\"cmd\":\"door\"")) {
        int v = -1, sq = 0, pr = 10, lm = 5000;
        char *vp = strstr(plain, "\"val\":"); if(vp)v=atoi(vp+6);
        char *sp = strstr(plain, "\"seq\":"); if(sp)sq=atoi(sp+6);
        char *pp = strstr(plain, "\"priority\":"); if(pp)pr=atoi(pp+11);
        char *lp = strstr(plain, "\"lockMs\":"); if(lp)lm=atoi(lp+9);

        bool ok = false;
        if (v == 1) {
            ok = door_unlock(pr, (uint32_t)lm, sq);
        } else if (v == 0) {
            ok = door_lock(pr, sq);
        }

        bool locked = door_is_locked();

        /* HTTP Door ACK */
        char ack[256];
        door_build_ack(ack, sizeof(ack), sq, ok, locked,
            ok ? NULL : (v == -1 ? "val 参数无效" : "GPIO 操作失败"));
        send_http_ack_raw(ack);

        ESP_LOGI(TAG_HTTP, "Door ACK: ok=%s locked=%s seq=%d",
                 ok ? "true" : "false", locked ? "true" : "false", sq);
    }
}

void http_task(void *pvParameters)
{
    char sensor_url[256];
    build_sensor_url(sensor_url, sizeof(sensor_url));
    ESP_LOGI(TAG_HTTP, "HTTP task start → %s", sensor_url);

    /* Boot 通知: HTTP POST 加密 boot JSON */
    {
        char boot[128];
        int blen = snprintf(boot, sizeof(boot),
            "{\"type\":\"boot\",\"deviceId\":\"%s\","
            "\"epoch\":0,\"keySource\":\"static\","
            "\"crypto\":\"%s\",\"transport\":\"http\"}",
            s_device_id, crypto_get_mode() ? "sm4" : "aes");
        uint8_t biv[AES_IV_LEN], bct[256], btg[AES_TAG_LEN];
        size_t bcl = 0;
        esp_fill_random(biv, sizeof(biv));
        if (crypto_aes_encrypt((uint8_t *)boot, blen,
                               biv, sizeof(biv), bct, &bcl,
                               btg, sizeof(btg))) {
            uint8_t bpkt[400];
            memcpy(bpkt, biv, AES_IV_LEN);
            memcpy(bpkt + AES_IV_LEN, btg, AES_TAG_LEN);
            memcpy(bpkt + AES_IV_LEN + AES_TAG_LEN, bct, bcl);
            int bpkt_len = AES_IV_LEN + AES_TAG_LEN + (int)bcl;
            char *b64 = malloc((bpkt_len + 2) / 3 * 4 + 4);
            if (b64) {
                base64_encode(bpkt, bpkt_len, b64, (bpkt_len + 2) / 3 * 4 + 4);
                char *body = malloc(strlen(b64) + 256);
                if (body) {
                    snprintf(body, strlen(b64) + 256,
                        "{\"deviceId\":\"%s\",\"topic\":\"%s\","
                        "\"payloadBase64\":\"%s\",\"crypto\":\"%s\"}",
                        s_device_id, t_status, b64, crypto_get_mode() ? "sm4" : "aes");
                    esp_http_client_config_t bcfg = {
                        .url = sensor_url, .timeout_ms = 3000,
                        .cert_pem = s_mqtt_ca_cert,
                    };
                    esp_http_client_handle_t bcli = esp_http_client_init(&bcfg);
                    esp_http_client_set_method(bcli, HTTP_METHOD_POST);
                    esp_http_client_set_header(bcli, "Content-Type", "application/json");
                    esp_http_client_set_post_field(bcli, body, strlen(body));
                    esp_http_client_perform(bcli);
                    esp_http_client_cleanup(bcli);
                    free(body);
                }
                free(b64);
            }
        }
        ESP_LOGI(TAG_HTTP, "Boot sent: epoch=0 keySource=static");
    }
    int poll_seq = 0;

    while (1) {
        if (g_proto_mode == PROTO_MODE_MQTT_ONLY) {
            vTaskDelay(pdMS_TO_TICKS(SENSOR_READ_INTERVAL_MS));
            continue;
        }

        /* ---- 读传感器 ---- */
        float temperature, humidity, light_lux;
        uint8_t pir;
        if (xSemaphoreTake(s_sys_mutex, pdMS_TO_TICKS(200)) == pdTRUE) {
            temperature = s_sys_data.temperature;
            humidity    = s_sys_data.humidity;
            light_lux   = s_sys_data.light_lux;
            pir         = s_sys_data.pir_detected;
            xSemaphoreGive(s_sys_mutex);
        } else {
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }

        /* ---- 加密传感器 JSON ---- */
        char json_buf[256];
        int json_len = snprintf(json_buf, sizeof(json_buf),
            "{\"proto\":\"http\",\"dev\":\"%s\",\"temp\":%.1f,\"hum\":%.1f,\"lux\":%.1f,\"pir\":%d}",
            s_device_id, temperature, humidity, light_lux, pir);
        uint8_t iv[AES_IV_LEN], ct[256], tag[AES_TAG_LEN];
        size_t ct_len = 0;
        esp_fill_random(iv, sizeof(iv));
        if (!crypto_aes_encrypt((uint8_t *)json_buf, json_len, iv, sizeof(iv),
                                ct, &ct_len, tag, sizeof(tag))) {
            vTaskDelay(pdMS_TO_TICKS(SENSOR_READ_INTERVAL_MS));
            continue;
        }
        uint8_t enc_pkt[300];
        memcpy(enc_pkt, iv, AES_IV_LEN);
        memcpy(enc_pkt + AES_IV_LEN, tag, AES_TAG_LEN);
        memcpy(enc_pkt + AES_IV_LEN + AES_TAG_LEN, ct, ct_len);
        int enc_len = AES_IV_LEN + AES_TAG_LEN + (int)ct_len;

        char b64[512];
        base64_encode(enc_pkt, enc_len, b64, sizeof(b64));

        char post_body[768];
        int body_len = snprintf(post_body, sizeof(post_body),
            "{\"deviceId\":\"%s\",\"topic\":\"%s\",\"payloadBase64\":\"%s\",\"crypto\":\"%s\"}",
            s_device_id, t_sensor, b64, crypto_get_mode() ? "sm4" : "aes");

        /* ---- HTTP POST 上报 ---- */
        esp_http_client_config_t cfg = {
            .url = sensor_url, .timeout_ms = 5000,
            .cert_pem = s_mqtt_ca_cert,
        };
        esp_http_client_handle_t cli = esp_http_client_init(&cfg);
        esp_http_client_set_method(cli, HTTP_METHOD_POST);
        esp_http_client_set_header(cli, "Content-Type", "application/json");
        esp_http_client_set_post_field(cli, post_body, body_len);
        esp_err_t err = esp_http_client_perform(cli);
        if (err == ESP_OK)
            ESP_LOGI(TAG_HTTP, "POST OK (%d)", esp_http_client_get_status_code(cli));
        else
            ESP_LOGW(TAG_HTTP, "POST fail %d", err);
        esp_http_client_cleanup(cli);

        /* ---- HTTP GET 轮询命令 ---- */
        poll_seq++;
        char poll_url[256];
        snprintf(poll_url, sizeof(poll_url),
                 "%s/api/http/command?deviceId=%s",
                 g_pairing_config.http_url, s_device_id);
        esp_http_client_config_t gcfg = {
            .url = poll_url,
            .timeout_ms = 3000,
            .cert_pem = s_mqtt_ca_cert,
        };
        esp_http_client_handle_t gcli = esp_http_client_init(&gcfg);
        esp_http_client_set_method(gcli, HTTP_METHOD_GET);
        esp_err_t gerr = esp_http_client_open(gcli, 0);
        if (gerr == ESP_OK) {
            int rlen = esp_http_client_fetch_headers(gcli);
            int status = esp_http_client_get_status_code(gcli);
            if (rlen < 0) rlen = 4096;
            uint8_t *rbuf = malloc(rlen + 1);
            int actual = 0;
            if (rbuf) {
                actual = esp_http_client_read(gcli, (char *)rbuf, rlen);
                if (actual < 0) actual = 0;
                rbuf[actual] = '\0';
            }
            ESP_LOGI(TAG_HTTP, "Poll#%d %dB status=%d", poll_seq, actual, status);

            if (rbuf && actual > 30 && rbuf[0] == '{') {
                /* 检查 hasCommand */
                if (!strstr((char *)rbuf, "\"hasCommand\":true")) {
                    free(rbuf); rbuf = NULL;
                    goto poll_done;
                }
                /* 校验 deviceId */
                {
                    char *did = strstr((char *)rbuf, "\"deviceId\":\"");
                    if (!did || strncmp(did + 12, s_device_id, strlen(s_device_id)) != 0) {
                        ESP_LOGW(TAG_HTTP, "Poll deviceId mismatch");
                        free(rbuf); rbuf = NULL;
                        goto poll_done;
                    }
                }
                /* 解析 JSON: 取 payloadBase64 */
                char *b64s = strstr((char *)rbuf, "\"payloadBase64\":\"");
                if (b64s) {
                    b64s += 17;
                    char *b64e = strchr(b64s, '"');
                    if (b64e) {
                        *b64e = '\0';
                        int b64len = strlen(b64s);
                        /* 补全base64 padding */
                        while (b64len % 4) { b64s[b64len] = '='; b64len++; }
                        uint8_t *dec = malloc(b64len);
                        int dlen = base64_decode(b64s, b64len, dec, b64len);
                        ESP_LOGI(TAG_HTTP, "b64(%d)→%dB IV=%02X%02X..TAG=%02X%02X..CT[0]=%02X",
                                 b64len, dlen, dec[0],dec[1],dec[12],dec[13],dec[28]);
                        /* ECDH 公钥 (65B uncompressed, 0x04开头) → 绕过GCM直接处理 */
                        if (dlen == 65 && dec[0] == 0x04) {
                            ESP_LOGI(TAG_HTTP, "HTTP收到ECDH公钥, 绕过GCM直接协商");
                            key_layer_negotiate(dec, dlen);
                            /* 协商成功后发 key ACK */
                            if (key_layer_get_epoch() > 0) {
                                char kack[256];
                                snprintf(kack, sizeof(kack),
                                    "{\"type\":\"device_hello\",\"deviceId\":\"%s\","
                                    "\"name\":\"Sensor Controller\",\"room\":\"\","
                                    "\"capabilities\":%s,\"transport\":\"http\","
                                    "\"crypto\":\"%s\",\"epoch\":%d}",
                                    s_device_id, DEVICE_CAPS,
                                    crypto_get_mode() ? "sm4" : "aes",
                                    key_layer_get_epoch());
                                send_http_ack_raw(kack);
                                ESP_LOGI(TAG_HTTP, "ECDH完成, device_hello ACK sent");
                            }
                        }
                        else if (dlen >= 29) {
                            /* [IV(12)][TAG(16)][CT] 解密 */
                            const uint8_t *ivp = dec, *tgp = dec + AES_IV_LEN;
                            const uint8_t *ctp = dec + AES_IV_LEN + AES_TAG_LEN;
                            size_t clen = dlen - AES_IV_LEN - AES_TAG_LEN;
                            uint8_t plain[256]; size_t plen = 0;
                            /* 和 MQTT 完全一样的解密入口 */
                            bool ok = crypto_decrypt_fallback(ctp, clen, ivp, AES_IV_LEN,
                                                               tgp, AES_TAG_LEN, plain, &plen);
                            if (ok) plen = clen;
                            if (ok) {
                                plain[plen] = '\0';
                                ESP_LOGI(TAG_HTTP, "解密OK: %s", plain);
                                process_cmd((char *)plain);
                            }
                            if (!ok) {
                                ESP_LOGW(TAG_HTTP, "解密FAIL clen=%d dlen=%d", clen, dlen);
                                /* 打印完整密文hex, 方便和大禹对齐 */
                                printf("  FAIL pkt[%d]: ", dlen);
                                for(int i=0;i<dlen&&i<64;i++)printf("%02X",dec[i]);
                                printf("\n");
                            }
                        }
                        free(dec);
                    }
                }
            }
            poll_done:
            if (rbuf) free(rbuf);
        } else {
            ESP_LOGW(TAG_HTTP, "Poll open fail %d", gerr);
        }
        esp_http_client_close(gcli);
        esp_http_client_cleanup(gcli);

        vTaskDelay(pdMS_TO_TICKS(SENSOR_READ_INTERVAL_MS));
    }
}
#endif /* PROTO_ENABLE_HTTP */
