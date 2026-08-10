#include "mqtt_app.h"
#include "sensors.h"
#include "actuator.h"
#include "door.h"

/* ======================== Topic 构建 (devId不变, 全局复用) ======================== */
char t_sensor[64], t_ack[64], t_status[64], t_cmd[64];
static void topics_init(void) {
    snprintf(t_sensor, sizeof(t_sensor), "device/%s/sensor", s_device_id);
    snprintf(t_ack,    sizeof(t_ack),    "device/%s/ack",    s_device_id);
    snprintf(t_status, sizeof(t_status), "device/%s/status", s_device_id);
    snprintf(t_cmd,    sizeof(t_cmd),    "dayu/cmd/%s",      s_device_id);
}

/* ======================== 加密发布 (带topic参数) ======================== */
static void mqtt_sensorlish_encrypted(const char *json, int json_len, const char *topic, int qos)
{
    uint8_t aiv[AES_IV_LEN], act[400], atg[AES_TAG_LEN];
    size_t acl = 0;
    esp_fill_random(aiv, sizeof(aiv));
    if (crypto_aes_encrypt((uint8_t *)json, json_len, aiv, sizeof(aiv), act, &acl, atg, sizeof(atg))) {
        uint8_t apkt[512];
        memcpy(apkt, aiv, AES_IV_LEN);
        memcpy(apkt + AES_IV_LEN, atg, AES_TAG_LEN);
        memcpy(apkt + AES_IV_LEN + AES_TAG_LEN, act, acl);
        esp_mqtt_client_publish(s_mqtt_client, topic, (char *)apkt, AES_IV_LEN + AES_TAG_LEN + (int)acl, qos, 0);
    }
}

/* ======================== device_hello ======================== */
static void send_device_hello(void)
{
    char hello[256];
    int hlen = snprintf(hello, sizeof(hello),
        "{\"type\":\"device_hello\",\"deviceId\":\"%s\",\"name\":\"Sensor Controller\",\"room\":\"\","
        "\"capabilities\":%s,\"transport\":\"mqtt\",\"crypto\":\"%s\",\"epoch\":%d}",
        s_device_id, DEVICE_CAPS, crypto_get_mode() ? "sm4" : "aes", key_layer_get_epoch());
    mqtt_sensorlish_encrypted(hello, hlen, t_status, 1);
    ESP_LOGI(TAG_MQTT, "device_hello sent");
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
        /* 订阅本机命令 topic */
        esp_mqtt_client_subscribe(s_mqtt_client, t_cmd, 0);
        ESP_LOGI(TAG_MQTT, "已订阅: %s", t_cmd);
        /* 发送device_hello */
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
#if KEY_EXCHANGE_ENABLE
        /* ---- 密钥协商 topic ---- */
        /* 检查是否为密钥协商 topic: key/ecdh/pub/{deviceId} */
        {
            char key_topic[64];
            snprintf(key_topic, sizeof(key_topic), "%s/%s",
                     KEY_MQTT_TOPIC_PREFIX, s_device_id);
            size_t kt_len = strlen(key_topic);
        if (ev->topic_len == kt_len &&
            memcmp(ev->topic, key_topic, kt_len) == 0) {

            /* 过滤自己发出的公钥 (不处理自己的公钥) */
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
            /* 过滤重复的大禹公钥 */
            if (ev->data_len == (int)last_peer_len &&
                memcmp(ev->data, last_peer_key, last_peer_len) == 0) {
                ESP_LOGD(TAG_KEY, "跳过重复的大禹公钥");
                break;
            }

            ESP_LOGI(TAG_KEY, "收到大禹公钥 (%d 字节), 开始协商...", ev->data_len);

            /* 打印双方公钥 hex (复用上面已获取的 our_pubkey) */
            printf("  ESP32 公钥: ");
            for(int i=0;i<(int)our_len;i++)printf("%02X",our_pubkey[i]);
            printf("\n  大禹公钥: ");
            for(int i=0;i<ev->data_len;i++)printf("%02X",ev->data[i]);
            printf("\n");

            if (key_layer_negotiate((const uint8_t *)ev->data, ev->data_len)) {
                /* 记录本次大禹公钥, 用于去重 */
                memcpy(last_peer_key, ev->data, ev->data_len);
                last_peer_len = ev->data_len;
                const key_material_t *keys = key_layer_get_keys();
                if (keys) {
                    int ep = key_layer_get_epoch();
                    ESP_LOGI(TAG_KEY, "密钥协商成功! epoch=%d", ep);

                    /* 发 ACK 告知大禹新密钥已就绪 */
                    char kack[128];
                    int klen = snprintf(kack, sizeof(kack),
                        "{\"type\":\"ack\",\"cmd\":\"key\",\"ok\":true,"
                        "\"deviceId\":\"%s\",\"epoch\":%d,"
                        "\"keySource\":\"dynamic\","
                        "\"crypto\":\"%s\",\"transport\":\"mqtt\"}",
                        s_device_id, ep,
                        crypto_get_mode() ? "sm4" : "aes");
                    uint8_t kiv[AES_IV_LEN], kct[256], ktg[AES_TAG_LEN];
                    size_t kcl = 0;
                    esp_fill_random(kiv, sizeof(kiv));
                    if (crypto_aes_encrypt((uint8_t *)kack, klen, kiv, sizeof(kiv),
                                           kct, &kcl, ktg, sizeof(ktg))) {
                        uint8_t kpkt[400];
                        memcpy(kpkt, kiv, AES_IV_LEN);
                        memcpy(kpkt + AES_IV_LEN, ktg, AES_TAG_LEN);
                        memcpy(kpkt + AES_IV_LEN + AES_TAG_LEN, kct, kcl);
                        esp_mqtt_client_publish(s_mqtt_client, t_sensor,
                            (char *)kpkt, AES_IV_LEN + AES_TAG_LEN + (int)kcl, 1, 0);
                        ESP_LOGI(TAG_KEY, "Key ACK epoch=%d 已发送", ep);
                    send_device_hello();
                    }
                }
            } else {
                ESP_LOGW(TAG_KEY, "密钥协商失败, 等待下次尝试");
            }
            break;
        }
        } /* end key_topic scope */
#endif

        /* ---- 只处理发到本机 cmd topic 的消息 ---- */
        {
            size_t ct_len = strlen(t_cmd);
            if (ev->topic_len != ct_len || memcmp(ev->topic, t_cmd, ct_len) != 0)
                break; /* 不是发给本机的命令, 忽略 */
        }

        /* ---- 接收大禹发来的数据 (HTTP模式跳过, 走HTTP轮询) ---- */
        if (g_proto_mode == PROTO_MODE_HTTP_ONLY) {
            break;
        }
        ESP_LOGI(TAG_MQTT, "收到大禹消息 topic=%.*s, %d 字节",
                 ev->topic_len, ev->topic, ev->data_len);

#if CRYPTO_ENABLE
        /* 解包: [IV(12B)][AUTH_TAG(16B)][CIPHERTEXT(NB)] */
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

                /* 过滤自己和兄弟设备: ACK/device_hello/boot */
                if (strstr((char *)rx_plain, "\"type\":\"ack\"") ||
                    strstr((char *)rx_plain, "\"type\":\"device_hello\"") ||
                    strstr((char *)rx_plain, "\"type\":\"boot\"")) {
                    ESP_LOGD(TAG_MQTT, "跳过自己的消息(type=ack/device_hello/boot)");
                    break;
                }

                /* ---- 解析大禹指令 ---- */

                /* 0a. 密钥重发公钥: {"cmd":"key","action":"pub",...} */
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
                        ESP_LOGI(TAG_KEY, "已重新发布公钥 (%d 字节)", pubkey_len);
                        /* ACK: 公钥已发布, 不切 dynamic */
                        char kack[128]; int sq = 0;
                        char *sp = strstr((char *)rx_plain, "\"seq\":");
                        if (sp) sq = atoi(sp + 6);
                        int klen = snprintf(kack, sizeof(kack),
                            "{\"type\":\"ack\",\"cmd\":\"key\",\"ok\":true,"
                            "\"action\":\"pub\",\"deviceId\":\"%s\",\"seq\":%d}",
                            s_device_id, sq);
                        uint8_t kiv[AES_IV_LEN], kct[256], ktg[AES_TAG_LEN];
                        size_t kcl = 0;
                        esp_fill_random(kiv, sizeof(kiv));
                        if (crypto_aes_encrypt((uint8_t *)kack, klen,
                                               kiv, sizeof(kiv),
                                               kct, &kcl, ktg, sizeof(ktg))) {
                            uint8_t kpkt[400];
                            memcpy(kpkt, kiv, AES_IV_LEN);
                            memcpy(kpkt + AES_IV_LEN, ktg, AES_TAG_LEN);
                            memcpy(kpkt + AES_IV_LEN + AES_TAG_LEN, kct, kcl);
                            esp_mqtt_client_publish(s_mqtt_client, t_sensor,
                                (char *)kpkt, AES_IV_LEN+AES_TAG_LEN+(int)kcl, 1, 0);
                        }
                    }
                }

                /* 0. 协议切换指令: {"cmd":"proto","val":"mqtt/http"} */
                if (strstr((char *)rx_plain, "\"cmd\":\"proto\"")) {
                    if (strstr((char *)rx_plain, "\"val\":\"http\""))
                        g_proto_mode = PROTO_MODE_HTTP_ONLY;
                    else
                        g_proto_mode = PROTO_MODE_MQTT_ONLY;
                    const char *pn = (g_proto_mode==PROTO_MODE_MQTT_ONLY)?"mqtt":"http";
                    ESP_LOGI(TAG_MQTT, "协议切换: %s", pn);

                    /* 回复 ACK */
                    char ack[128];
                    int alen = snprintf(ack, sizeof(ack),
                        "{\"type\":\"ack\",\"cmd\":\"proto\",\"val\":\"%s\",\"ok\":true,\"deviceId\":\"%s\"}", pn, s_device_id);
                    uint8_t aiv[AES_IV_LEN], act[256], atg[AES_TAG_LEN];
                    size_t acl = 0;
                    esp_fill_random(aiv, sizeof(aiv));
                    if (crypto_aes_encrypt((uint8_t *)ack, alen, aiv, sizeof(aiv),
                                           act, &acl, atg, sizeof(atg))) {
                        uint8_t apkt[400];
                        memcpy(apkt, aiv, AES_IV_LEN);
                        memcpy(apkt + AES_IV_LEN, atg, AES_TAG_LEN);
                        memcpy(apkt + AES_IV_LEN + AES_TAG_LEN, act, acl);
                        esp_mqtt_client_publish(s_mqtt_client, t_sensor,
                            (char *)apkt, AES_IV_LEN + AES_TAG_LEN + (int)acl, 1, 0);
                        ESP_LOGI(TAG_MQTT, "Proto ACK: %s", pn);
                    send_device_hello();
                    }
                }
                /* 1. 加密算法切换指令: {"cmd":"crypto","val":"aes"} */
                if (strstr((char *)rx_plain, "\"cmd\":\"crypto\"")) {
                    bool switch_to_sm4 = (strstr((char *)rx_plain, "\"val\":\"sm4\"") != NULL);
                    bool switch_to_aes = (strstr((char *)rx_plain, "\"val\":\"aes\"") != NULL);
                    if (switch_to_sm4 || switch_to_aes) {
                        bool new_mode = switch_to_sm4;
                        crypto_set_mode(new_mode);
                        ESP_LOGI(TAG_MQTT, "算法已切换为: %s",
                                 new_mode ? "SM4" : "AES");

                        /* 用新算法加密回复 */
                        char ack[128];
                        int ack_len = snprintf(ack, sizeof(ack),
                                               "{\"type\":\"ack\",\"cmd\":\"crypto\",\"ok\":true,"
                                               "\"val\":\"%s\",\"deviceId\":\"%s\"}",
                                               new_mode ? "SM4" : "AES", s_device_id);
                        uint8_t ack_iv[AES_IV_LEN], ack_ct[256], ack_tag[AES_TAG_LEN];
                        size_t ack_ct_len = 0;
                        esp_fill_random(ack_iv, sizeof(ack_iv));
                        if (crypto_aes_encrypt((uint8_t *)ack, ack_len,
                                               ack_iv, sizeof(ack_iv),
                                               ack_ct, &ack_ct_len,
                                               ack_tag, sizeof(ack_tag))) {
                            uint8_t ack_pkt[300];
                            memcpy(ack_pkt, ack_iv, AES_IV_LEN);
                            memcpy(ack_pkt + AES_IV_LEN, ack_tag, AES_TAG_LEN);
                            memcpy(ack_pkt + AES_IV_LEN + AES_TAG_LEN,
                                   ack_ct, ack_ct_len);
                            esp_mqtt_client_publish(s_mqtt_client, t_sensor,
                                                    (char *)ack_pkt,
                                                    AES_IV_LEN + AES_TAG_LEN + ack_ct_len,
                                                    1, 0);
                            ESP_LOGI(TAG_MQTT, "已回复切换确认 [%s]", new_mode ? "SM4" : "AES");
                        }
                    }
                }
                /* 2. LED 控制指令 (带控制锁) */
                else if (strstr((char *)rx_plain, "\"cmd\":\"led\"")) {
                    int val = -1, priority = 10, lock_ms = 5000, seq = 0;
                    /* 简单解析: 从 JSON 里提取字段 (不用完整 JSON parser) */
                    {
                        char *p = (char *)rx_plain;
                        char *vp = strstr(p, "\"val\":");
                        if (vp) val = atoi(vp + 6);
                        char *pp = strstr(p, "\"priority\":");
                        if (pp) priority = atoi(pp + 11);
                        char *lp = strstr(p, "\"lockMs\":");
                        if (lp) lock_ms = atoi(lp + 9);
                        char *sp = strstr(p, "\"seq\":");
                        if (sp) seq = atoi(sp + 6);
                    }

                    if (val == 0 || val == 1) {
                        /* 设置 LED */
                        gpio_set_level(LED_GPIO, val ? LED_ON_LEVEL : (1 - LED_ON_LEVEL));
                        ESP_LOGI(TAG_ACTUATOR, "大禹 LED 指令: %s (priority=%d, lock=%dms)",
                                 val ? "开" : "关", priority, lock_ms);

                        /* 更新系统数据 + 控制锁 */
                        if (xSemaphoreTake(s_sys_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
                            s_sys_data.led_cmd = (uint8_t)val;
                            s_sys_data.led_on  = (uint8_t)val;
                            /* 设置控制锁 */
                            strncpy(s_sys_data.led_lock.owner, "dayu", 15);
                            s_sys_data.led_lock.priority = priority;
                            s_sys_data.led_lock.lock_until_ms =
                                xTaskGetTickCount() + pdMS_TO_TICKS((uint32_t)lock_ms);
                            s_sys_data.led_lock.last_seq = seq;
                            xSemaphoreGive(s_sys_mutex);
                        }

                        /* 发送 ACK */
                        char ack[256];
                        int ack_len = snprintf(ack, sizeof(ack),
                            "{\"type\":\"ack\",\"cmd\":\"led\",\"val\":%d,"
                            "\"ok\":true,\"source\":\"esp32\","
                            "\"appliedSource\":\"dayu\",\"priority\":%d,"
                            "\"lockMs\":%d,\"seq\":%d,\"deviceId\":\"%s\"}",
                            val, priority, lock_ms, seq, s_device_id);
                        uint8_t ack_iv[AES_IV_LEN], ack_ct[300], ack_tag[AES_TAG_LEN];
                        size_t ack_ct_len = 0;
                        esp_fill_random(ack_iv, sizeof(ack_iv));
                        if (crypto_aes_encrypt((uint8_t *)ack, ack_len,
                                               ack_iv, sizeof(ack_iv),
                                               ack_ct, &ack_ct_len,
                                               ack_tag, sizeof(ack_tag))) {
                            uint8_t ack_pkt[400];
                            memcpy(ack_pkt, ack_iv, AES_IV_LEN);
                            memcpy(ack_pkt + AES_IV_LEN, ack_tag, AES_TAG_LEN);
                            memcpy(ack_pkt + AES_IV_LEN + AES_TAG_LEN,
                                   ack_ct, ack_ct_len);
                            esp_mqtt_client_publish(s_mqtt_client, t_sensor,
                                (char *)ack_pkt, AES_IV_LEN + AES_TAG_LEN + ack_ct_len, 1, 0);
                            ESP_LOGI(TAG_MQTT, "LED ACK 已发送: ok=true seq=%d", seq);
                        }
                    }
                }
                /* 3. 门锁控制指令 */
                else if (strstr((char *)rx_plain, "\"cmd\":\"door\"")) {
                    int d_val = -1, d_pri = 10, d_lock = 5000, d_seq = 0;
                    char *vp = strstr((char *)rx_plain, "\"val\":");
                    if (vp) d_val = atoi(vp + 6);
                    char *pp = strstr((char *)rx_plain, "\"priority\":");
                    if (pp) d_pri = atoi(pp + 11);
                    char *lp = strstr((char *)rx_plain, "\"lockMs\":");
                    if (lp) d_lock = atoi(lp + 9);
                    char *sp = strstr((char *)rx_plain, "\"seq\":");
                    if (sp) d_seq = atoi(sp + 6);

                    bool ok = false;
                    if (d_val == 1) {
                        ok = door_unlock(d_pri, (uint32_t)d_lock, d_seq);
                    } else if (d_val == 0) {
                        ok = door_lock(d_pri, d_seq);
                    }

                    bool locked = door_is_locked();

                    /* 构造 ACK */
                    char ack[256];
                    int ack_len = door_build_ack(ack, sizeof(ack), d_seq, ok, locked,
                        ok ? NULL : (d_val == -1 ? "val 参数无效" : "GPIO 操作失败"));

                    /* 加密并发送 ACK */
                    ESP_LOGI(TAG_ACTUATOR, "门锁 ACK: ok=%s locked=%s seq=%d",
                             ok ? "true" : "false", locked ? "true" : "false", d_seq);

                    uint8_t ack_iv[AES_IV_LEN], ack_ct[300], ack_tag[AES_TAG_LEN];
                    size_t ack_ct_len = 0;
                    esp_fill_random(ack_iv, sizeof(ack_iv));
                    if (crypto_aes_encrypt((uint8_t *)ack, ack_len,
                                           ack_iv, sizeof(ack_iv),
                                           ack_ct, &ack_ct_len,
                                           ack_tag, sizeof(ack_tag))) {
                        uint8_t ack_pkt[400];
                        memcpy(ack_pkt, ack_iv, AES_IV_LEN);
                        memcpy(ack_pkt + AES_IV_LEN, ack_tag, AES_TAG_LEN);
                        memcpy(ack_pkt + AES_IV_LEN + AES_TAG_LEN,
                               ack_ct, ack_ct_len);
                        esp_mqtt_client_publish(s_mqtt_client, t_sensor,
                            (char *)ack_pkt, AES_IV_LEN + AES_TAG_LEN + ack_ct_len, 1, 0);
                        ESP_LOGI(TAG_MQTT, "Door ACK 已发送: ok=%s seq=%d",
                                 ok ? "true" : "false", d_seq);
                    }
                }
            } else {
                ESP_LOGW(TAG_MQTT, "解密失败! 密钥或格式不匹配, 数据长度=%d", ev->data_len);
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

/**
 * @brief MQTT 通信任务 (与大禹智能终端对接)
 *
 * 支持两种模式:
 *   - 明文 TCP:  mqtt://<ip>:1883     (MQTT_USE_TLS=0)
 *   - 加密 TLS:  mqtts://<ip>:8883    (MQTT_USE_TLS=1)
 *
 * 数据流:
 *   ESP32 --[JSON payload]--> publish("esp32/sensor")  --> 大禹
 *   ESP32 <--[指令]---------- subscribe("dayu/cmd")    <-- 大禹
 */
void mqtt_task(void *pvParameters)
{
    ESP_LOGI(TAG_MQTT, "MQTT 任务已启动");
    topics_init();

    /* ---- 1. Broker URI (直接使用配网或 NVS 中的完整 URL) ---- */
    const char *broker_uri = g_pairing_config.broker_url;

    /* ---- 2. 配置 MQTT 客户端 ---- */
    esp_mqtt_client_config_t mqtt_cfg = {
        .broker.address.uri = broker_uri,
        .session.keepalive = 30,   /* 对齐大禹 30s 心跳 */
        .broker.verification.certificate =
            MQTT_USE_TLS() ? s_mqtt_ca_cert : NULL,
    };

    s_mqtt_client = esp_mqtt_client_init(&mqtt_cfg);
    if (s_mqtt_client == NULL
    ) {
        ESP_LOGE(TAG_MQTT, "MQTT 客户端初始化失败");
        vTaskDelete(NULL);
        return;
    }

    esp_mqtt_client_register_event(s_mqtt_client, ESP_EVENT_ANY_ID,
                                   mqtt_event_handler, NULL);
    esp_mqtt_client_start(s_mqtt_client);

    /* ---- 3. 订阅大禹下发的指令 topic ---- */
    /* 等连接成功后在事件回调里订阅, 这里只是启动 */

    /* ---- 4. 主循环: 定时发布传感器数据 + 密钥轮换 ---- */
    TickType_t last_rotate_tick = xTaskGetTickCount();
    bool mqtt_idle = false;
    while (1) {
        /* HTTP 模式: 断开 MQTT, 休眠等待切回 */
        if (g_proto_mode == PROTO_MODE_HTTP_ONLY) {
            if (!mqtt_idle) {
                ESP_LOGI(TAG_MQTT, "HTTP模式, MQTT 暂停");
                mqtt_idle = true;
            }
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }
        if (mqtt_idle) {
            ESP_LOGI(TAG_MQTT, "MQTT模式, 恢复连接");
            mqtt_idle = false;
            esp_mqtt_client_reconnect(s_mqtt_client);
        }

#if KEY_EXCHANGE_ENABLE
        /* 定时密钥轮换 (每30分钟重新ECDH协商) */
        if (xTaskGetTickCount() - last_rotate_tick >=
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

        float temperature, humidity, light_lux;
        uint8_t pir;

        /* BLE 已连接 → 传感器走 BLE, 跳过 MQTT 上报 */
        extern bool ble_is_connected(void);
        if (ble_is_connected()) {
            vTaskDelay(pdMS_TO_TICKS(500));
            continue;
        }

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

        /* ---- 构造 JSON payload (传感器 + LED + 门锁 + 锁状态) ---- */
        uint8_t led_state = 0, door_state = 0, door_locked = 0;
        int lock_ttl_ms = 0;
        char lock_owner[16] = "";
        int lock_priority = 0;
        if (xSemaphoreTake(s_sys_mutex, pdMS_TO_TICKS(50)) == pdTRUE) {
            led_state   = s_sys_data.led_on;
            door_state  = s_sys_data.door_open;
            door_locked = s_sys_data.door_locked;
            if (s_sys_data.led_lock.owner[0] != '\0') {
                int32_t remaining = (int32_t)(s_sys_data.led_lock.lock_until_ms
                    - xTaskGetTickCount());
                lock_ttl_ms = (remaining > 0) ? (int)(remaining * portTICK_PERIOD_MS) : 0;
                if (lock_ttl_ms > 0) {
                    strncpy(lock_owner, s_sys_data.led_lock.owner, 15);
                    lock_priority = s_sys_data.led_lock.priority;
                }
            }
            xSemaphoreGive(s_sys_mutex);
        }

        char json_buf[512];
        int json_len;
        if (lock_ttl_ms > 0) {
            json_len = snprintf(json_buf, sizeof(json_buf),
                "{\"proto\":\"mqtt\",\"dev\":\"%s\","
                "\"temp\":%.1f,\"hum\":%.1f,\"lux\":%.1f,\"pir\":%d,"
                "\"led\":%d,"
                "\"ledLock\":{\"owner\":\"%s\",\"priority\":%d,\"ttlMs\":%d},"
                "\"door\":%d,\"locked\":%d}",
                s_device_id, temperature, humidity, light_lux, pir,
                led_state, lock_owner, lock_priority, lock_ttl_ms,
                door_state, door_locked);
        } else {
            json_len = snprintf(json_buf, sizeof(json_buf),
                "{\"proto\":\"mqtt\",\"dev\":\"%s\","
                "\"temp\":%.1f,\"hum\":%.1f,\"lux\":%.1f,\"pir\":%d,"
                "\"led\":%d,\"door\":%d,\"locked\":%d}",
                s_device_id, temperature, humidity, light_lux, pir,
                led_state, door_state, door_locked);
        }

        int publish_len = 0;
        uint8_t publish_buf[300];  /* IV(12) + TAG(16) + cipher(<=256) */

#if CRYPTO_ENABLE
        /* ---- 数据层加密: AES-256-GCM ---- */
        uint8_t iv[AES_IV_LEN];
        esp_fill_random(iv, sizeof(iv));  /* 每次加密用随机 nonce */

        uint8_t ciphertext[256];
        size_t cipher_len = 0;
        uint8_t auth_tag[AES_TAG_LEN];

        if (crypto_aes_encrypt((uint8_t *)json_buf, json_len,
                               iv, sizeof(iv),
                               ciphertext, &cipher_len,
                               auth_tag, sizeof(auth_tag))) {
            /* 组包: [IV][AUTH_TAG][CIPHERTEXT] */
            memcpy(publish_buf,                    iv,         AES_IV_LEN);
            memcpy(publish_buf + AES_IV_LEN,       auth_tag,   AES_TAG_LEN);
            memcpy(publish_buf + AES_IV_LEN + AES_TAG_LEN, ciphertext, cipher_len);
            publish_len = AES_IV_LEN + AES_TAG_LEN + cipher_len;
            /* 调试: 打印加密key来源 */
            ESP_LOGI(TAG_MQTT, "SEND crypto=%s epoch=%d keySrc=%s",
                     crypto_get_mode() ? "SM4" : "AES",
                     key_layer_get_epoch(),
                     key_layer_get_epoch() > 0 ? "dynamic" : "static");
            ESP_LOGI(TAG_MQTT, "SEND iv=%02X%02X.. tag=%02X%02X.. ct=%02X%02X.. json=%s",
                     iv[0], iv[1], auth_tag[0], auth_tag[1],
                     ciphertext[0], ciphertext[1], json_buf);
        } else {
            ESP_LOGW(TAG_MQTT, "AES 加密失败, 跳过本次上报");
            vTaskDelay(pdMS_TO_TICKS(SENSOR_READ_INTERVAL_MS));
            continue;
        }
#else
        /* 明文模式: 直接发 JSON */
        memcpy(publish_buf, json_buf, json_len);
        publish_len = json_len;
#endif

        if (s_mqtt_client != NULL && g_proto_mode != PROTO_MODE_HTTP_ONLY &&
            mqtt_connected) {
            int ret = esp_mqtt_client_publish(s_mqtt_client, t_sensor,
                                              (char *)publish_buf, publish_len,
                                              0, 0);  /* QoS 0, 对齐大禹 */
            if (ret < 0) {
                ESP_LOGW(TAG_MQTT, "MQTT 发布失败: %d", ret);
            } else {
                ESP_LOGI(TAG_MQTT, "MQTT 已发布 [%s%s]: %d 字节",
                         MQTT_USE_TLS() ? "TLS+" : "",
                         CRYPTO_ENABLE ? (crypto_get_mode() ? "SM4" : "AES") : "明文", publish_len);
            }
        }

        vTaskDelay(pdMS_TO_TICKS(SENSOR_READ_INTERVAL_MS));
    }
}


