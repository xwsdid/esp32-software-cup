/**
 * @file  mqtt_app.c
 * @brief MQTT 通信任务 — AC 状态上报 + 指令解析 + 密钥协商 + 多设备支持
 */
#include "mqtt_app.h"
#include "ble_bridge.h"

/* 前置声明 (定义在 main.c) */
extern void ac_apply_state(const ac_state_t *target);

/* ======================== Topic 构建 (运行时, 基于 s_device_id) ======================== */
static inline void topic_ac(char *b, int sz) { snprintf(b, sz, "device/%s/ac", s_device_id); }
static inline void topic_status(char *b, int sz) { snprintf(b, sz, "device/%s/status", s_device_id); }
static inline void topic_cmd(char *b, int sz) { snprintf(b, sz, "dayu/cmd/%s", s_device_id); }

/* ======================== device_hello 发送 ======================== */
static void mqtt_publish_encrypted(const char *json, int json_len, const char *topic, int qos);
static void send_device_hello(void)
{
    char hello[256];
    int hlen = snprintf(hello, sizeof(hello),
        "{\"type\":\"device_hello\",\"deviceId\":\"%s\","
        "\"name\":\"AC Controller\",\"room\":\"\","
        "\"capabilities\":%s,"
        "\"transport\":\"mqtt\",\"crypto\":\"%s\",\"epoch\":%d}",
        s_device_id, DEVICE_CAPS,
        crypto_get_mode() ? "sm4" : "aes", key_layer_get_epoch());

    char topic[64]; topic_status(topic, sizeof(topic));
    mqtt_publish_encrypted(hello, hlen, topic, 1);
    ESP_LOGI(TAG_MQTT, "device_hello sent: caps=%s", DEVICE_CAPS);
}

/* ======================== IR 学习状态 (MQTT task 中非阻塞执行) ======================== */
static int g_learn_pending = -1;
static bool g_learn_all = false;
static int g_learn_seq = 0;

/* ======================== 窗帘步进电机 (MQTT task 中执行) ======================== */
static int g_curtain_pending = -1;  /* -1=none, >=0=target val 0~100 */
static int g_curtain_seq = 0;

/* ======================== 加密 ACK 快捷发布 ======================== */
static void mqtt_publish_encrypted(const char *json, int json_len, const char *topic, int qos)
{
    uint8_t aiv[AES_IV_LEN], act[400], atg[AES_TAG_LEN];
    size_t acl = 0;
    esp_fill_random(aiv, sizeof(aiv));
    if (crypto_aes_encrypt((uint8_t *)json, json_len, aiv, sizeof(aiv),
                           act, &acl, atg, sizeof(atg))) {
        uint8_t apkt[512];
        memcpy(apkt, aiv, AES_IV_LEN);
        memcpy(apkt + AES_IV_LEN, atg, AES_TAG_LEN);
        memcpy(apkt + AES_IV_LEN + AES_TAG_LEN, act, acl);
        esp_mqtt_client_publish(s_mqtt_client, topic,
            (char *)apkt, AES_IV_LEN + AES_TAG_LEN + (int)acl, qos, 0);
    }
}

/* ======================== MQTT 事件回调 ======================== */

static bool mqtt_connected = false;

void mqtt_event_handler(void *arg, esp_event_base_t base,
                               int32_t event_id, void *event_data)
{
    esp_mqtt_event_handle_t ev = (esp_mqtt_event_handle_t)event_data;

    switch ((esp_mqtt_event_id_t)event_id) {
    case MQTT_EVENT_CONNECTED:
        mqtt_connected = true;
        ESP_LOGI(TAG_MQTT, "已连接到 Broker (%s)",
                 MQTT_USE_TLS() ? "TLS 加密" : "明文");

        /* 订阅本机命令 topic: dayu/cmd/{deviceId} */
        {
            char t[64]; topic_cmd(t, sizeof(t));
            esp_mqtt_client_subscribe(s_mqtt_client, t, 0);
            ESP_LOGI(TAG_MQTT, "已订阅: %s", t);
        }

        /* Boot 通知 + device_hello */
        send_device_hello();

#if KEY_EXCHANGE_ENABLE
        /* 订阅 + 发布密钥协商 topic: key/ecdh/pub/{deviceId} */
        {
            char key_topic[64];
            snprintf(key_topic, sizeof(key_topic), "%s/%s",
                     KEY_MQTT_TOPIC_PREFIX, s_device_id);
            esp_mqtt_client_subscribe(s_mqtt_client, key_topic, 0);
            ESP_LOGI(TAG_MQTT, "已订阅密钥协商 topic: %s", key_topic);

            uint8_t pubkey[KEY_PUBKEY_MAX_LEN];
            size_t  pubkey_len = 0;
            if (key_layer_get_pubkey(pubkey, &pubkey_len)) {
                esp_mqtt_client_publish(s_mqtt_client, key_topic,
                                        (char *)pubkey, pubkey_len, 0, 0);
                ESP_LOGI(TAG_KEY, "已发布本机 ECDH 公钥 (%d 字节)", pubkey_len);
            }
        }
#endif
        break;

    case MQTT_EVENT_DISCONNECTED:
        mqtt_connected = false;
        ESP_LOGW(TAG_MQTT, "与 Broker 断开连接, 将自动重连");
        break;

    case MQTT_EVENT_DATA:
    {
        /* 过滤: 检查是否为本机command topic */
        {
            char cmd_topic[64]; topic_cmd(cmd_topic, sizeof(cmd_topic));
            size_t ct_len = strlen(cmd_topic);
            if (ev->topic_len != ct_len ||
                memcmp(ev->topic, cmd_topic, ct_len) != 0) {
                /* 不是发给本机的命令, 检查是否密钥协商 */
                goto check_key_topic;
            }
            /* 是本机命令, 继续处理 */
            goto process_command;
        }

check_key_topic:
#if KEY_EXCHANGE_ENABLE
        /* ---- 密钥协商 topic ---- */
        {
            char key_topic[64];
            snprintf(key_topic, sizeof(key_topic), "%s/%s",
                     KEY_MQTT_TOPIC_PREFIX, s_device_id);
            size_t kt_len = strlen(key_topic);
        if (ev->topic_len == kt_len &&
            memcmp(ev->topic, key_topic, kt_len) == 0) {

            static uint8_t last_peer_key[KEY_PUBKEY_MAX_LEN];
            static size_t  last_peer_len = 0;
            uint8_t our_pubkey[KEY_PUBKEY_MAX_LEN];
            size_t  our_len = 0;
            if (key_layer_get_pubkey(our_pubkey, &our_len) &&
                ev->data_len == (int)our_len &&
                memcmp(ev->data, our_pubkey, our_len) == 0) {
                ESP_LOGD(TAG_KEY, "跳过自己的公钥");
                break;
            }
            if (ev->data_len == (int)last_peer_len &&
                memcmp(ev->data, last_peer_key, last_peer_len) == 0) {
                ESP_LOGD(TAG_KEY, "跳过重复的大禹公钥");
                break;
            }

            ESP_LOGI(TAG_KEY, "收到大禹公钥 (%d 字节), 开始协商...", ev->data_len);
            printf("  ESP32 公钥: ");
            for(int i=0;i<(int)our_len;i++)printf("%02X",our_pubkey[i]);
            printf("\n  大禹公钥: ");
            for(int i=0;i<ev->data_len;i++)printf("%02X",ev->data[i]);
            printf("\n");

            if (key_layer_negotiate((const uint8_t *)ev->data, ev->data_len)) {
                memcpy(last_peer_key, ev->data, ev->data_len);
                last_peer_len = ev->data_len;
                ESP_LOGI(TAG_KEY, "密钥协商成功! epoch=%d", key_layer_get_epoch());

                /* Key ACK */
                char kack[256];
                int klen = snprintf(kack, sizeof(kack),
                    "{\"type\":\"ack\",\"cmd\":\"key\",\"ok\":true,"
                    "\"deviceId\":\"%s\",\"epoch\":%d,"
                    "\"keySource\":\"dynamic\","
                    "\"crypto\":\"%s\",\"transport\":\"mqtt\"}",
                    s_device_id, key_layer_get_epoch(),
                    crypto_get_mode() ? "sm4" : "aes");
                char t[64]; topic_ac(t, sizeof(t));
                mqtt_publish_encrypted(kack, klen, t, 1);
                ESP_LOGI(TAG_KEY, "Key ACK epoch=%d 已发送", key_layer_get_epoch());

                /* ECDH完成后重新发送device_hello */
                send_device_hello();
            } else {
                ESP_LOGW(TAG_KEY, "密钥协商失败, 等待下次尝试");
            }
            break;
        }
        } /* end key_topic scope */
#endif
        /* 不是本机命令也非密钥, 忽略 */
        break;

process_command:
        if (g_proto_mode == PROTO_MODE_HTTP_ONLY) {
            break;
        }
        ESP_LOGI(TAG_MQTT, "收到大禹消息 topic=%.*s, %d 字节",
                 ev->topic_len, ev->topic, ev->data_len);

#if CRYPTO_ENABLE
        if (ev->data_len >= AES_IV_LEN + AES_TAG_LEN + 1) {
            const uint8_t *rx_iv      = (const uint8_t *)ev->data;
            const uint8_t *rx_tag     = (const uint8_t *)ev->data + AES_IV_LEN;
            const uint8_t *rx_cipher  = (const uint8_t *)ev->data + AES_IV_LEN + AES_TAG_LEN;
            size_t rx_cipher_len      = ev->data_len - AES_IV_LEN - AES_TAG_LEN;

            uint8_t rx_plain[256];
            size_t rx_plain_len = 0;

            if (crypto_decrypt_fallback(rx_cipher, rx_cipher_len,
                                         rx_iv, AES_IV_LEN,
                                         rx_tag, AES_TAG_LEN,
                                         rx_plain, &rx_plain_len)) {
                rx_plain[rx_plain_len] = '\0';
                ESP_LOGI(TAG_MQTT, "解密成功! 明文: %s", rx_plain);
                ESP_LOGI(TAG_MQTT, "[CMD] crypto=%s epoch=%d keySource=%s",
                         crypto_get_mode() ? "SM4" : "AES",
                         key_layer_get_epoch(),
                         key_layer_get_epoch() > 0 ? "dynamic" : "static");

                /* 过滤自己的回显: ACK / Boot / device_hello */
                if (strstr((char *)rx_plain, "\"type\":\"ack\"") != NULL ||
                    strstr((char *)rx_plain, "\"type\":\"boot\"") != NULL ||
                    strstr((char *)rx_plain, "\"type\":\"device_hello\"") != NULL) {
                    ESP_LOGD(TAG_MQTT, "跳过自己的消息");
                    break;
                }

                /* ---- 密钥重发公钥 ---- */
                if (strstr((char *)rx_plain, "\"cmd\":\"key\"") &&
                    strstr((char *)rx_plain, "\"action\":\"pub\"")) {
                    ESP_LOGI(TAG_KEY, "收到 key/pub 请求, 重新发布公钥");
                    uint8_t pubkey[KEY_PUBKEY_MAX_LEN];
                    size_t  pubkey_len = 0;
                    if (key_layer_get_pubkey(pubkey, &pubkey_len)) {
                        char key_topic[64];
                        snprintf(key_topic, sizeof(key_topic), "%s/%s",
                                 KEY_MQTT_TOPIC_PREFIX, s_device_id);
                        esp_mqtt_client_publish(s_mqtt_client, key_topic,
                            (char *)pubkey, pubkey_len, 1, 0);
                        char kack[128]; int sq = 0;
                        char *sp = strstr((char *)rx_plain, "\"seq\":");
                        if (sp) sq = atoi(sp + 6);
                        int klen = snprintf(kack, sizeof(kack),
                            "{\"type\":\"ack\",\"cmd\":\"key\",\"ok\":true,"
                            "\"action\":\"pub\",\"deviceId\":\"%s\",\"seq\":%d}",
                            s_device_id, sq);
                        char t[64]; topic_ac(t, sizeof(t));
                        mqtt_publish_encrypted(kack, klen, t, 1);
                    }
                }

                /* ---- 协议切换 ---- */
                if (strstr((char *)rx_plain, "\"cmd\":\"proto\"")) {
                    if (strstr((char *)rx_plain, "\"val\":\"http\""))
                        g_proto_mode = PROTO_MODE_HTTP_ONLY;
                    else
                        g_proto_mode = PROTO_MODE_MQTT_ONLY;
                    const char *pn = (g_proto_mode==PROTO_MODE_MQTT_ONLY)?"mqtt":"http";
                    ESP_LOGI(TAG_MQTT, "协议切换: %s", pn);

                    char ack[200];
                    int alen = snprintf(ack, sizeof(ack),
                        "{\"type\":\"ack\",\"cmd\":\"proto\",\"ok\":true,"
                        "\"val\":\"%s\",\"deviceId\":\"%s\"}", pn, s_device_id);
                    char t[64]; topic_ac(t, sizeof(t));
                    mqtt_publish_encrypted(ack, alen, t, 1);
                    ESP_LOGI(TAG_MQTT, "Proto ACK: %s", pn);

                    /* 协议切换后重新发device_hello */
                    send_device_hello();
                }

                /* ---- 加密算法切换 ---- */
                if (strstr((char *)rx_plain, "\"cmd\":\"crypto\"")) {
                    bool sm4 = (strstr((char *)rx_plain, "\"val\":\"sm4\"") != NULL);
                    if (sm4 || strstr((char *)rx_plain, "\"val\":\"aes\"")) {
                        crypto_set_mode(sm4);
                        ESP_LOGI(TAG_MQTT, "算法切换: %s", sm4 ? "SM4" : "AES");

                        char ack[200];
                        int ack_len = snprintf(ack, sizeof(ack),
                            "{\"type\":\"ack\",\"cmd\":\"crypto\",\"ok\":true,"
                            "\"val\":\"%s\",\"deviceId\":\"%s\"}",
                            sm4 ? "sm4" : "aes", s_device_id);
                        char t[64]; topic_ac(t, sizeof(t));
                        mqtt_publish_encrypted(ack, ack_len, t, 1);
                        send_device_hello();
                    }
                }

                /* ---- AC 控制指令 ---- */
                else if (strstr((char *)rx_plain, "\"cmd\":\"ac\"")) {
                    ac_state_t target;
                    memcpy(&target, &s_ac_state, sizeof(target));

                    char *pp = strstr((char *)rx_plain, "\"power\":");
                    if (pp) {
                        char *tp = strstr(pp, "true"), *fp = strstr(pp, "false");
                        if (tp && tp < pp + 20) target.power = 1;
                        else if (fp && fp < pp + 20) target.power = 0;
                    }
                    char *tp = strstr((char *)rx_plain, "\"temp\":");
                    if (tp) target.target_temp = (float)atof(tp + 7);
                    char *mp = strstr((char *)rx_plain, "\"mode\":\"");
                    if (mp) { mp += 8;
                        if (strncmp(mp,"cool",4)==0) target.mode=0;
                        else if (strncmp(mp,"heat",4)==0) target.mode=1;
                        else if (strncmp(mp,"fan",3)==0) target.mode=2;
                        else if (strncmp(mp,"dry",3)==0) target.mode=3; }
                    char *fp2 = strstr((char *)rx_plain, "\"fan\":\"");
                    if (fp2) { fp2 += 6;
                        if (strncmp(fp2,"auto",4)==0) target.fan_speed=0;
                        else if (strncmp(fp2,"low",3)==0) target.fan_speed=1;
                        else if (strncmp(fp2,"mid",3)==0) target.fan_speed=2;
                        else if (strncmp(fp2,"high",4)==0) target.fan_speed=3; }
                    char *sp = strstr((char *)rx_plain, "\"swing\":");
                    if (sp) {
                        char *ts = strstr(sp,"true"), *fs = strstr(sp,"false");
                        if (ts&&ts<sp+20) target.swing=1;
                        else if (fs&&fs<sp+20) target.swing=0; }
                    int seq = 0;
                    char *sq = strstr((char *)rx_plain, "\"seq\":");
                    if (sq) seq = atoi(sq + 6);

                    ESP_LOGI(TAG_MQTT, "AC 指令: power=%d temp=%.0f mode=%d fan=%d swing=%d",
                             target.power, target.target_temp, target.mode, target.fan_speed, target.swing);

                    if (xSemaphoreTake(s_ac_mutex, pdMS_TO_TICKS(500)) == pdTRUE) {
                        ac_apply_state(&target);
                        xSemaphoreGive(s_ac_mutex);
                    }

                    char ack[300];
                    int ack_len = snprintf(ack, sizeof(ack),
                        "{\"type\":\"ack\",\"cmd\":\"ac\",\"ok\":true,"
                        "\"power\":%s,\"temp\":%.0f,\"mode\":\"%s\","
                        "\"fan\":\"%s\",\"swing\":%s,\"seq\":%d,"
                        "\"deviceId\":\"%s\"}",
                        target.power ? "true" : "false", target.target_temp,
                        target.mode==0?"cool":target.mode==1?"heat":target.mode==2?"fan":"dry",
                        target.fan_speed==0?"auto":target.fan_speed==1?"low":
                        target.fan_speed==2?"mid":"high",
                        target.swing?"true":"false", seq, s_device_id);
                    char t[64]; topic_ac(t, sizeof(t));
                    mqtt_publish_encrypted(ack, ack_len, t, 1);
                    ESP_LOGI(TAG_MQTT, "AC ACK 已发送: ok=true seq=%d", seq);
                }

                /* ---- 报警解除 ---- */
                else if (strstr((char *)rx_plain, "\"cmd\":\"alarm\"")) {
                    int seq = 0;
                    char *sq = strstr((char *)rx_plain, "\"seq\":");
                    if (sq) seq = atoi(sq + 6);
                    alarm_clear();
                    char ack[200];
                    int alen = snprintf(ack, sizeof(ack),
                        "{\"type\":\"ack\",\"cmd\":\"alarm\","
                        "\"action\":\"off\",\"ok\":true,"
                        "\"seq\":%d,\"deviceId\":\"%s\","
                        "\"msg\":\"alarm cleared\"}", seq, s_device_id);
                    char t[64]; topic_ac(t, sizeof(t));
                    mqtt_publish_encrypted(ack, alen, t, 1);
                    ESP_LOGI(TAG_MQTT, "报警解除 ACK 已发送");
                }

                /* ---- 恢复出厂 (擦除配网) ---- */
                else if (strstr((char *)rx_plain, "\"cmd\":\"factory_reset\"")) {
                    ESP_LOGW(TAG_MQTT, "!!! 收到恢复出厂指令 !!!");
                    int seq = 0;
                    char *sq = strstr((char *)rx_plain, "\"seq\":");
                    if (sq) seq = atoi(sq + 6);
                    char ack[200]; int alen = snprintf(ack, sizeof(ack),
                        "{\"type\":\"ack\",\"cmd\":\"factory_reset\",\"ok\":true,"
                        "\"seq\":%d,\"deviceId\":\"%s\","
                        "\"msg\":\"erasing and reboot\"}", seq, s_device_id);
                    char t[64]; topic_ac(t, sizeof(t));
                    mqtt_publish_encrypted(ack, alen, t, 1);
                    vTaskDelay(pdMS_TO_TICKS(500));
                    pairing_factory_reset();  /* 擦除 NVS + 重启 */
                }

                /* ---- 窗帘控制 ---- */
                else if (strstr((char *)rx_plain, "\"cmd\":\"curtain\"")) {
                    int seq = 0;
                    char *sq = strstr((char *)rx_plain, "\"seq\":");
                    if (sq) seq = atoi(sq + 6);

                    char *vp = strstr((char *)rx_plain, "\"val\":");
                    if (vp) {
                        int val = atoi(vp + 6);
                        if (val < 0) val = 0;
                        if (val > 100) val = 100;
                        g_curtain_pending = val;
                        g_curtain_seq = seq;
                    } else {
                        char ack[200]; int alen = snprintf(ack, sizeof(ack),
                            "{\"type\":\"ack\",\"cmd\":\"curtain\",\"ok\":false,"
                            "\"msg\":\"missing val\",\"seq\":%d,"
                            "\"deviceId\":\"%s\"}", seq, s_device_id);
                        char t[64]; topic_ac(t, sizeof(t));
                        mqtt_publish_encrypted(ack, alen, t, 1);
                    }
                }

                /* ---- IR 指令 ---- */
                else if (strstr((char *)rx_plain, "\"cmd\":\"ir\"")) {
                    char *akp = strstr((char *)rx_plain, "\"action\":\"");
                    char *ikp = strstr((char *)rx_plain, "\"index\":");
                    int idx = ikp ? atoi(ikp + 8) : -1;
                    int seq = 0;
                    char *sq = strstr((char *)rx_plain, "\"seq\":");
                    if (sq) seq = atoi(sq + 6);

                    if (akp) {
                        char action[16] = {0};
                        strncpy(action, akp + 10, sizeof(action) - 1);
                        char *eq = strchr(action, '"'); if (eq) *eq = '\0';

                        char t[64]; topic_ac(t, sizeof(t));

                        if (strcmp(action, "learn") == 0 && idx >= 1 && idx <= 6) {
                            if (g_learn_pending >= 0) {
                                char ack[200];
                                int alen = snprintf(ack, sizeof(ack),
                                    "{\"type\":\"ack\",\"cmd\":\"ir\",\"action\":\"learn\","
                                    "\"ok\":false,\"msg\":\"busy\",\"seq\":%d,"
                                    "\"deviceId\":\"%s\"}", seq, s_device_id);
                                mqtt_publish_encrypted(ack, alen, t, 1);
                            } else {
                                g_learn_pending = idx;
                                g_learn_all = false;
                                g_learn_seq = seq;
                                char ack[200];
                                int alen = snprintf(ack, sizeof(ack),
                                    "{\"type\":\"ack\",\"cmd\":\"ir\",\"action\":\"learn\","
                                    "\"ok\":true,\"index\":%d,\"msg\":\"learning\","
                                    "\"keyName\":\"%s\",\"seq\":%d,"
                                    "\"deviceId\":\"%s\"}",
                                    idx, ac_key_names[idx], seq, s_device_id);
                                mqtt_publish_encrypted(ack, alen, t, 1);
                            }
                        }
                        else if (strcmp(action, "learn-all") == 0) {
                            if (g_learn_pending >= 0) {
                                char ack[200]; int alen = snprintf(ack, sizeof(ack),
                                    "{\"type\":\"ack\",\"cmd\":\"ir\",\"action\":\"learn-all\","
                                    "\"ok\":false,\"msg\":\"busy\",\"seq\":%d,"
                                    "\"deviceId\":\"%s\"}", seq, s_device_id);
                                mqtt_publish_encrypted(ack, alen, t, 1);
                            } else {
                                g_learn_pending = 1; g_learn_all = true; g_learn_seq = seq;
                                char ack[200]; int alen = snprintf(ack, sizeof(ack),
                                    "{\"type\":\"ack\",\"cmd\":\"ir\",\"action\":\"learn-all\","
                                    "\"ok\":true,\"msg\":\"learning 1~6, ~6min\","
                                    "\"seq\":%d,\"deviceId\":\"%s\"}", seq, s_device_id);
                                mqtt_publish_encrypted(ack, alen, t, 1);
                            }
                        }
                        else if (strcmp(action, "exit") == 0) {
                            g_learn_pending = -1; g_learn_all = false;
                            ir_exit_learn();
                            char ack[200]; int alen = snprintf(ack, sizeof(ack),
                                "{\"type\":\"ack\",\"cmd\":\"ir\",\"action\":\"exit\","
                                "\"ok\":true,\"seq\":%d,\"deviceId\":\"%s\"}", seq, s_device_id);
                            mqtt_publish_encrypted(ack, alen, t, 1);
                        }
                        else if (strcmp(action, "send") == 0 && idx >= 1 && idx <= 6) {
                            int ret = ir_send_stored_code((uint8_t)idx);
                            char ack[200]; int alen = snprintf(ack, sizeof(ack),
                                "{\"type\":\"ack\",\"cmd\":\"ir\",\"action\":\"send\","
                                "\"ok\":%s,\"index\":%d,\"keyName\":\"%s\","
                                "\"seq\":%d,\"deviceId\":\"%s\"}",
                                ret==0?"true":"false", idx, ac_key_names[idx], seq, s_device_id);
                            mqtt_publish_encrypted(ack, alen, t, 1);
                        }
                        else if (strcmp(action, "read") == 0 && idx >= 1 && idx <= 6) {
                            uint8_t code[512]; uint16_t clen = 0;
                            if (ir_read_code((uint8_t)idx, code, sizeof(code), &clen) == 0 && clen > 0) {
                                char hex[128], *hp = hex;
                                for (uint16_t i = 0; i < clen && i < 32; i++) hp += snprintf(hp, 3, "%02X", code[i]);
                                if (clen > 32) { *hp++ = '.'; *hp++ = '.'; *hp = '\0'; }
                                char ack[300]; int alen = snprintf(ack, sizeof(ack),
                                    "{\"type\":\"ack\",\"cmd\":\"ir\",\"action\":\"read\","
                                    "\"ok\":true,\"index\":%d,\"len\":%d,\"hex\":\"%s\","
                                    "\"seq\":%d,\"deviceId\":\"%s\"}", idx, clen, hex, seq, s_device_id);
                                mqtt_publish_encrypted(ack, alen, t, 1);
                            } else {
                                char ack[200]; int alen = snprintf(ack, sizeof(ack),
                                    "{\"type\":\"ack\",\"cmd\":\"ir\",\"action\":\"read\","
                                    "\"ok\":false,\"index\":%d,\"msg\":\"empty\","
                                    "\"seq\":%d,\"deviceId\":\"%s\"}", idx, seq, s_device_id);
                                mqtt_publish_encrypted(ack, alen, t, 1);
                            }
                        }
                        else if (strcmp(action, "format") == 0 || strcmp(action, "reset") == 0) {
                            int ret = strcmp(action,"format")==0 ? ir_format() : ir_reset();
                            char ack[200]; int alen = snprintf(ack, sizeof(ack),
                                "{\"type\":\"ack\",\"cmd\":\"ir\",\"action\":\"%s\","
                                "\"ok\":%s,\"seq\":%d,\"deviceId\":\"%s\"}",
                                action, ret==0?"true":"false", seq, s_device_id);
                            mqtt_publish_encrypted(ack, alen, t, 1);
                        }
                        else {
                            char ack[200]; int alen = snprintf(ack, sizeof(ack),
                                "{\"type\":\"ack\",\"cmd\":\"ir\",\"ok\":false,"
                                "\"msg\":\"unknown action\",\"seq\":%d,"
                                "\"deviceId\":\"%s\"}", seq, s_device_id);
                            mqtt_publish_encrypted(ack, alen, t, 1);
                        }
                    }
                }
            } else {
                ESP_LOGW(TAG_MQTT, "解密失败! 数据长度=%d", ev->data_len);
            }
        } else {
            ESP_LOGW(TAG_MQTT, "数据太短无法解密: %d 字节 (需>=%d)",
                     ev->data_len, AES_IV_LEN + AES_TAG_LEN + 1);
        }
#else
        ESP_LOGI(TAG_MQTT, "收到: %.*s", ev->data_len, ev->data);
#endif
        break;
    }

    case MQTT_EVENT_ERROR:
        ESP_LOGE(TAG_MQTT, "MQTT 错误");
        break;

    default:
        break;
    }
}

/* ======================== MQTT 任务 ======================== */

void mqtt_task(void *pvParameters)
{
    ESP_LOGI(TAG_MQTT, "MQTT 任务已启动");

    const char *broker_uri = g_pairing_config.broker_url;

    esp_mqtt_client_config_t mqtt_cfg = {
        .broker.address.uri = broker_uri,
        .session.keepalive = 30,
        .broker.verification.certificate =
            MQTT_USE_TLS() ? s_mqtt_ca_cert : NULL,
    };

    s_mqtt_client = esp_mqtt_client_init(&mqtt_cfg);
    if (s_mqtt_client == NULL) {
        ESP_LOGE(TAG_MQTT, "MQTT 客户端初始化失败");
        vTaskDelete(NULL);
        return;
    }

    esp_mqtt_client_register_event(s_mqtt_client, ESP_EVENT_ANY_ID,
                                   mqtt_event_handler, NULL);
    esp_mqtt_client_start(s_mqtt_client);

    TickType_t last_rotate_tick = xTaskGetTickCount();
    bool mqtt_idle = false;

    while (1) {
        alarm_read();
        /* BLE 传感器上报 (烟雾/水浸) */
        ble_bridge_report_sensor();

        if (g_proto_mode == PROTO_MODE_HTTP_ONLY) {
            if (!mqtt_idle) {
                ESP_LOGI(TAG_MQTT, "HTTP模式, MQTT 暂停");
                mqtt_idle = true;
            }
            vTaskDelay(pdMS_TO_TICKS(TASK_LOOP_INTERVAL_MS));
            continue;
        }
        if (mqtt_idle) {
            ESP_LOGI(TAG_MQTT, "MQTT模式, 恢复连接");
            mqtt_idle = false;
            esp_mqtt_client_reconnect(s_mqtt_client);
        }

#if KEY_EXCHANGE_ENABLE
        if (g_learn_pending < 0 &&
            xTaskGetTickCount() - last_rotate_tick >=
            pdMS_TO_TICKS(KEY_ROTATE_INTERVAL_SEC * 1000)) {
            ESP_LOGI(TAG_KEY, "密钥轮换: 开始重新协商...");
            uint8_t new_pubkey[KEY_PUBKEY_MAX_LEN];
            size_t  new_len = 0;
            if (key_layer_rotate(new_pubkey, &new_len)) {
                char key_topic[64];
                snprintf(key_topic, sizeof(key_topic), "%s/%s",
                         KEY_MQTT_TOPIC_PREFIX, s_device_id);
                esp_mqtt_client_publish(s_mqtt_client, key_topic,
                                        (char *)new_pubkey, new_len, 0, 0);
                ESP_LOGI(TAG_KEY, "密钥轮换: 新公钥已发布 (%d 字节)", new_len);
            }
            last_rotate_tick = xTaskGetTickCount();
        }
#endif

        /* IR 学习状态机 */
        if (g_learn_pending >= 1 && g_learn_pending <= 6) {
            int idx = g_learn_pending;
            ESP_LOGI(TAG_MQTT, "开始 IR learn idx=%d (%s)...", idx, ac_key_names[idx]);
            if (ir_enter_learn((uint8_t)idx) != 0) {
                ESP_LOGE(TAG_MQTT, "IR enter learn failed idx=%d", idx);
                char ack[200]; int alen = snprintf(ack, sizeof(ack),
                    "{\"type\":\"ack\",\"cmd\":\"ir\",\"action\":\"learn\","
                    "\"ok\":false,\"index\":%d,\"msg\":\"enter learn failed\","
                    "\"seq\":%d,\"deviceId\":\"%s\"}", idx, g_learn_seq, s_device_id);
                char t[64]; topic_ac(t, sizeof(t));
                mqtt_publish_encrypted(ack, alen, t, 1);
                g_learn_pending = -1;
            } else {
                ir_report_t report;
                int ret = ir_wait_learn_report(&report, 65000);
                if (ret == 0 && report.flag == IR_REPORT_LEARN_OK && report.status == 0) {
                    ESP_LOGI(TAG_MQTT, "IR learn idx=%d (%s) SUCCESS", idx, ac_key_names[idx]);
                    char ack[200]; int alen = snprintf(ack, sizeof(ack),
                        "{\"type\":\"ack\",\"cmd\":\"ir\",\"action\":\"learn\","
                        "\"ok\":true,\"index\":%d,\"keyName\":\"%s\","
                        "\"msg\":\"learned\",\"seq\":%d,\"deviceId\":\"%s\"}",
                        idx, ac_key_names[idx], g_learn_seq, s_device_id);
                    char t[64]; topic_ac(t, sizeof(t));
                    mqtt_publish_encrypted(ack, alen, t, 1);
                } else {
                    ir_exit_learn();
                    ESP_LOGW(TAG_MQTT, "IR learn idx=%d TIMEOUT/FAIL", idx);
                    char ack[200]; int alen = snprintf(ack, sizeof(ack),
                        "{\"type\":\"ack\",\"cmd\":\"ir\",\"action\":\"learn\","
                        "\"ok\":false,\"index\":%d,\"keyName\":\"%s\","
                        "\"msg\":\"timeout\",\"seq\":%d,\"deviceId\":\"%s\"}",
                        idx, ac_key_names[idx], g_learn_seq, s_device_id);
                    char t[64]; topic_ac(t, sizeof(t));
                    mqtt_publish_encrypted(ack, alen, t, 1);
                }
                if (g_learn_all && g_learn_pending >= 1 && g_learn_pending < 6) {
                    ESP_LOGI(TAG_MQTT, "3秒后开始下一个按键...");
                    vTaskDelay(pdMS_TO_TICKS(3000));
                    g_learn_pending++;
                } else {
                    g_learn_pending = -1; g_learn_all = false;
                    if (idx >= 6) ESP_LOGI(TAG_MQTT, "IR learn-all 全部完成 (1~6)");
                }
            }
        }

        /* 检测报警 (BLE 已连接时报警走 BLE 通道, 跳过 MQTT) */
        extern bool ble_is_connected(void);
        if (!ble_is_connected() && alarm_check_and_send()) {
            alarm_data_t alm;
            if (xSemaphoreTake(s_alarm_mutex, pdMS_TO_TICKS(50)) == pdTRUE) {
                memcpy(&alm, &s_alarm_data, sizeof(alm));
                xSemaphoreGive(s_alarm_mutex);
            } else { memset(&alm, 0, sizeof(alm)); }
            char alarm_json[300];
            int alen = snprintf(alarm_json, sizeof(alarm_json),
                "{\"type\":\"alarm\",\"dev\":\"%s\","
                "\"smoke\":{\"alarm\":%s,\"raw\":%d,\"voltage\":%.2f},"
                "\"water\":{\"alarm\":%s,\"raw\":%d,\"voltage\":%.2f},"
                "\"deviceId\":\"%s\"}",
                s_device_id,
                alm.smoke_alarm ? "true" : "false", alm.smoke_raw, alm.smoke_voltage,
                alm.water_alarm ? "true" : "false", alm.water_raw, alm.water_voltage,
                s_device_id);
            char t[64]; topic_ac(t, sizeof(t));
            mqtt_publish_encrypted(alarm_json, alen, t, 1);
        }

        /* 窗帘步进电机执行 */
        if (g_curtain_pending >= 0) {
            int target = g_curtain_pending;
            int seq = g_curtain_seq;
            g_curtain_pending = -1;

            stepper_set_target((uint8_t)target);
            uint8_t actual = stepper_get_position();

            /* ACK → device/{deviceId}/status */
            char ack[200]; int alen = snprintf(ack, sizeof(ack),
                "{\"type\":\"ack\",\"cmd\":\"curtain\",\"ok\":true,"
                "\"val\":%d,\"seq\":%d,\"deviceId\":\"%s\"}",
                actual, seq, s_device_id);
            char t[64]; topic_status(t, sizeof(t));
            mqtt_publish_encrypted(ack, alen, t, 1);

            /* 主动上报位置 → device/{deviceId}/status */
            char report[128];
            int rlen = snprintf(report, sizeof(report),
                "{\"deviceId\":\"%s\",\"curtainPercent\":%d}",
                s_device_id, actual);
            mqtt_publish_encrypted(report, rlen, t, 1);
        }

        /* 读 AC + 报警 */
        ac_state_t cur;
        if (xSemaphoreTake(s_ac_mutex, pdMS_TO_TICKS(200)) == pdTRUE) {
            memcpy(&cur, &s_ac_state, sizeof(cur));
            xSemaphoreGive(s_ac_mutex);
        } else { vTaskDelay(pdMS_TO_TICKS(100)); continue; }

        alarm_data_t alm;
        if (xSemaphoreTake(s_alarm_mutex, pdMS_TO_TICKS(50)) == pdTRUE) {
            memcpy(&alm, &s_alarm_data, sizeof(alm));
            xSemaphoreGive(s_alarm_mutex);
        } else { memset(&alm, 0, sizeof(alm)); }

        char json_buf[512];
        int json_len = snprintf(json_buf, sizeof(json_buf),
            "{\"proto\":\"mqtt\",\"dev\":\"%s\","
            "\"power\":%s,\"temp\":%.0f,\"mode\":\"%s\","
            "\"fan\":\"%s\",\"swing\":%s,"
            "\"smoke\":{\"raw\":%d,\"voltage\":%.2f,\"alarm\":%s},"
            "\"water\":{\"raw\":%d,\"voltage\":%.2f,\"alarm\":%s},"
            "\"deviceId\":\"%s\"}",
            s_device_id, cur.power ? "true" : "false", cur.target_temp,
            cur.mode==0?"cool":cur.mode==1?"heat":cur.mode==2?"fan":"dry",
            cur.fan_speed==0?"auto":cur.fan_speed==1?"low":cur.fan_speed==2?"mid":"high",
            cur.swing?"true":"false",
            alm.smoke_raw, alm.smoke_voltage, alm.smoke_alarm?"true":"false",
            alm.water_raw, alm.water_voltage, alm.water_alarm?"true":"false",
            s_device_id);

        uint8_t iv[AES_IV_LEN]; esp_fill_random(iv, sizeof(iv));
        uint8_t ciphertext[256]; size_t cipher_len = 0;
        uint8_t auth_tag[AES_TAG_LEN];

        if (crypto_aes_encrypt((uint8_t *)json_buf, json_len, iv, sizeof(iv),
                               ciphertext, &cipher_len, auth_tag, sizeof(auth_tag))) {
            uint8_t pub[350];
            memcpy(pub, iv, AES_IV_LEN);
            memcpy(pub + AES_IV_LEN, auth_tag, AES_TAG_LEN);
            memcpy(pub + AES_IV_LEN + AES_TAG_LEN, ciphertext, cipher_len);
            int plen = AES_IV_LEN + AES_TAG_LEN + cipher_len;
            if (s_mqtt_client && g_proto_mode != PROTO_MODE_HTTP_ONLY && mqtt_connected) {
                char t[64]; topic_ac(t, sizeof(t));
                int ret = esp_mqtt_client_publish(s_mqtt_client, t, (char *)pub, plen, 0, 0);
                if (ret < 0) ESP_LOGW(TAG_MQTT, "发布失败: %d", ret);
                else ESP_LOGI(TAG_MQTT, "已发布 [%s%s]: %d 字节",
                    MQTT_USE_TLS()?"TLS+":"", crypto_get_mode()?"SM4":"AES", plen);
            }
        }
        vTaskDelay(pdMS_TO_TICKS(TASK_LOOP_INTERVAL_MS));
    }
}
