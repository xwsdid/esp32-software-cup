/**
 * @file  main.c
 * @brief ESP32 空调控制器主程序 — 初始化 + 任务创建
 */
#include "main_config.h"
#include "wifi_app.h"
#include "mqtt_app.h"
#include "http_app.h"
#include "alarm.h"
#include "stepper.h"
#include "ble_peripheral.h"
#include "ble_bridge.h"
#include "ble_crypto.h"
#include "esp_sntp.h"
#include <time.h>

/* ===== 全局变量定义 (extern 声明在 main_config.h) ===== */
SemaphoreHandle_t s_sys_mutex = NULL;
SemaphoreHandle_t s_ac_mutex = NULL;
ac_state_t s_ac_state = {0};
esp_mqtt_client_handle_t s_mqtt_client = NULL;
char s_broker_ip[32] = "192.168.3.5";
int s_broker_port = 1883;
int g_proto_mode = PROTO_MODE_MQTT_ONLY;
char s_device_id[32] = {0};

/* ======================== 设备ID (Base MAC) ======================== */
static void device_id_init(void)
{
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    snprintf(s_device_id, sizeof(s_device_id), "esp32-%02X%02X%02X%02X%02X%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    ESP_LOGI("SYS", "DEVICE_ID: %s", s_device_id);
}
/* ======================== 调试串口输出 ======================== */

static void dbg_uart_init(void)
{
    uart_config_t uart_config = {
        .baud_rate  = DBG_UART_BAUD_RATE,
        .data_bits  = UART_DATA_8_BITS,
        .parity     = UART_PARITY_DISABLE,
        .stop_bits  = UART_STOP_BITS_1,
        .flow_ctrl  = UART_HW_FLOWCTRL_DISABLE,
    };
    uart_param_config(DBG_UART_PORT, &uart_config);
    uart_driver_install(DBG_UART_PORT, 256, 0, 0, NULL, 0);
    ESP_LOGI("SYS", "UART%d OK", DBG_UART_PORT);
}

void dbg_uart_printf(const char *fmt, ...)
{
#if DEBUG_SENSOR_UART
    char buf[128];
    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    if (len > 0) {
        uart_write_bytes(DBG_UART_PORT, buf, len);
    }
#endif
}

/* ======================== AC 状态初始化 ======================== */

static void ac_state_init(void)
{
    s_ac_state.power       = 0;
    s_ac_state.target_temp = 26.0f;
    s_ac_state.mode        = 0;  /* 制冷 */
    s_ac_state.fan_speed   = 0;  /* 自动 */
    s_ac_state.swing       = 0;  /* 关 */
    s_ac_state.timestamp   = xTaskGetTickCount();
}

/**
 * @brief 发送单个红外按键 (带延迟)
 */
static void ac_send_key(ac_key_index_t key, int delay_ms)
{
    if (ir_send_stored_code((uint8_t)key) != 0) {
        ESP_LOGW(TAG_IR, "发送 %s 失败 (未学习?)", ac_key_names[key]);
    } else {
        ESP_LOGI(TAG_IR, "已发送: %s", ac_key_names[key]);
    }
    if (delay_ms > 0) {
        vTaskDelay(pdMS_TO_TICKS((uint32_t)delay_ms));
    }
}

/**
 * @brief 根据目标状态翻译并发送红外码
 *
 * 基于当前 s_ac_state 和目标状态计算差异, 发送对应按键。
 * 调用此函数前需持有 s_ac_mutex。
 *
 * @param target  目标空调状态
 */
void ac_apply_state(const ac_state_t *target)
{
    ac_state_t cur = s_ac_state;  /* 快照当前状态 */
    ESP_LOGI(TAG_IR, "AC apply: cur(power=%d,temp=%.0f,mode=%d) -> "
             "tgt(power=%d,temp=%.0f,mode=%d)",
             cur.power, cur.target_temp, cur.mode,
             target->power, target->target_temp, target->mode);

    /* ---- 开关机 (独立键: 0=关机, 6=开机) ---- */
    if (target->power == 1 && cur.power == 0) {
        /* 需要开机 */
        ac_send_key(AC_KEY_ON, 500);
        cur.power = 1;
    }
    if (target->power == 0 && cur.power == 1) {
        /* 需要关机 */
        ac_send_key(AC_KEY_OFF, 500);
        cur.power = 0;
        memcpy(&s_ac_state, &cur, sizeof(cur));
        s_ac_state.timestamp = xTaskGetTickCount();
        return;
    }

    /* 如果关机状态, 先开机再调参数 */
    if (!cur.power) {
        memcpy(&s_ac_state, &cur, sizeof(cur));
        return;
    }

    /* ---- 模式切换 (制冷/制热是独立键) ---- */
    if (target->mode != cur.mode) {
        if (target->mode == 0)      /* 制冷 */
            ac_send_key(AC_KEY_COOL, 500);
        else if (target->mode == 1) /* 制热 */
            ac_send_key(AC_KEY_HEAT, 500);
        /* mode=2(送风)/3(除湿) 未学习, 忽略 */
        cur.mode = target->mode;
    }

    /* ---- 温度调整 ---- */
    if (target->target_temp != cur.target_temp) {
        int diff = (int)(target->target_temp - cur.target_temp);
        ac_key_index_t key = (diff > 0) ? AC_KEY_TEMP_UP : AC_KEY_TEMP_DN;
        int steps = (diff > 0) ? diff : -diff;
        for (int i = 0; i < steps; i++) {
            ac_send_key(key, 300);
        }
        cur.target_temp = target->target_temp;
    }

    /* 保存新状态 */
    cur.timestamp = xTaskGetTickCount();
    memcpy(&s_ac_state, &cur, sizeof(cur));
}

/* ======================== SNTP 时间同步 ======================== */

static void sntp_sync(void)
{
    ESP_LOGI("SYS", "SNTP 时间同步中...");
    esp_sntp_setoperatingmode(SNTP_OPMODE_POLL);
    esp_sntp_setservername(0, "ntp.aliyun.com");
    esp_sntp_setservername(1, "pool.ntp.org");
    esp_sntp_init();

    int retry = 0;
    while (sntp_get_sync_status() == SNTP_SYNC_STATUS_RESET && retry < 150) {
        vTaskDelay(pdMS_TO_TICKS(200));
        retry++;
    }

    if (sntp_get_sync_status() == SNTP_SYNC_STATUS_COMPLETED) {
        time_t now;
        time(&now);
        struct tm ti;
        localtime_r(&now, &ti);
        ESP_LOGI("SYS", "SNTP OK: %04d-%02d-%02d %02d:%02d:%02d UTC",
                 ti.tm_year + 1900, ti.tm_mon + 1, ti.tm_mday,
                 ti.tm_hour, ti.tm_min, ti.tm_sec);
    } else {
        ESP_LOGW("SYS", "SNTP sync timeout (retry=%d), TLS may fail", retry);
    }
}

/* ======================== 主函数 ======================== */

void app_main(void)
{
    /* 0. 设备唯一ID (基于Base MAC, 最早) */
    device_id_init();

    /* 0b. 串口配网 (NVS加载 + 配网窗口监听大禹) */
    pairing_init();
    /* 配网后同步 deviceId (NVS 或 配网写入的值) */
    strncpy(s_device_id, g_pairing_config.device_id, sizeof(s_device_id) - 1);

    /* 0c. 串口 debug */
    dbg_uart_init();

    /* 0c. 默认MQTT+SM4, 后续可切换 */
    g_proto_mode = PROTO_MODE_MQTT_ONLY;
    crypto_set_mode(true);  /* true=SM4 */

    /* 1. 互斥锁 */
    s_sys_mutex = xSemaphoreCreateMutex();
    s_ac_mutex  = xSemaphoreCreateMutex();

    /* 2. 空调状态初始化 */
    ac_state_init();

    /* 3. 红外模块初始化 */
    ESP_LOGI("SYS", "--- 红外模块 ---");
    if (ir_init(IR_TX_PIN, IR_RX_PIN, IR_BAUD_RATE)) {
        ESP_LOGI("SYS", "红外模块 OK TX=%d RX=%d Baud=%d", IR_TX_PIN, IR_RX_PIN, IR_BAUD_RATE);
        /* 验证模块通信 */
        uint8_t addr = 0xFF;
        if (ir_get_addr(&addr) == 0) {
            ESP_LOGI("SYS", "模块地址=%02X, 通信正常", addr);
        }
        /* 检查哪些按键已学习 */
        int learned = 0, total = 0;
        for (int i = 1; i <= 6; i++) {
            total++;
            uint8_t code[32]; uint16_t clen = 0;
            if (ir_read_code((uint8_t)i, code, sizeof(code), &clen) == 0 && clen > 0)
                learned++;
        }
        if (learned < total) {
            ESP_LOGW("SYS", "红外编码: %d/%d 已学习, 请通过 MQTT 发送 learn 指令学习遥控器", learned, total);
            ESP_LOGW("SYS", "例: {\"cmd\":\"ir\",\"action\":\"learn\",\"index\":0}");
            ESP_LOGW("SYS", "或: {\"cmd\":\"ir\",\"action\":\"learn-all\"}");
        } else {
            ESP_LOGI("SYS", "红外编码: 全部 %d 个已学习, 可以控制空调", learned);
        }
    } else {
        ESP_LOGE("SYS", "红外模块初始化失败! 检查接线");
    }

    /* 3b. 传感器 ADC 初始化 */
    alarm_init();

    /* 3c. 窗帘步进电机初始化 */
    stepper_init();

    /* ---- 窗帘自测 (调试时改为 #if 1) ---- */
#if 0
    ESP_LOGI("SYS", "=== 窗帘自测开始 ===");
    vTaskDelay(pdMS_TO_TICKS(1000));
    ESP_LOGI("SYS", "→ 开窗帘到 100%%");
    stepper_set_target(100);
    vTaskDelay(pdMS_TO_TICKS(2000));
    ESP_LOGI("SYS", "→ 关窗帘到 0%%");
    stepper_set_target(0);
    ESP_LOGI("SYS", "=== 窗帘自测完成 (pos=%d%%) ===", stepper_get_position());
#endif

    /* 4. WiFi */
    ESP_LOGI("SYS", "--- WiFi ---");
    wifi_init_sta();

    /* 5. 时间同步 (TLS证书校验依赖正确时间) */
    ESP_LOGI("SYS", "--- SNTP ---");
    sntp_sync();

    /* 6. 安全 */
#if KEY_EXCHANGE_ENABLE
    ESP_LOGI("SYS", "--- 安全 ---");
    if (key_layer_init()) {
        ESP_LOGI("SYS", "ECDH+HKDF OK");
    } else {
        ESP_LOGW("SYS", "ECDH+HKDF FAIL");
    }
    key_layer_reset_boot();
#endif

    /* 6. 任务 */
    ESP_LOGI("SYS", "--- 任务 ---");
    ESP_LOGI("SYS", "WiFi SSID : %s", g_pairing_config.wifi_ssid);
    ESP_LOGI("SYS", "协议传输  : %s", g_pairing_config.transport);
    ESP_LOGI("SYS", "MQTT      : %s (%s, TLS:%s)",
             g_pairing_config.broker_url,
             PROTO_ENABLE_MQTT ? "ON" : "OFF",
             MQTT_USE_TLS() ? "ON" : "OFF");
    ESP_LOGI("SYS", "HTTP      : %s (%s, TLS:%s)",
             g_pairing_config.http_url,
             PROTO_ENABLE_HTTP ? "ON" : "OFF",
             strncmp(g_pairing_config.http_url, "https", 5) == 0 ? "ON" : "OFF");
    ESP_LOGI("SYS", "数据加密  : %s",
             CRYPTO_ENABLE ? (crypto_get_mode() ? "SM4-GCM" : "AES-256-GCM") : "OFF");

    xTaskCreate(mqtt_task,      "mqtt",      MQTT_TASK_STACK_SIZE,
                NULL, MQTT_TASK_PRIORITY, NULL);
#if PROTO_ENABLE_HTTP
    xTaskCreate(http_task,      "http",      HTTP_TASK_STACK_SIZE,
                NULL, HTTP_TASK_PRIORITY, NULL);
#endif

    /* BLE Peripheral (start after everything else is ready) */
    ble_peripheral_init();
    ble_crypto_init(s_device_id);
    ble_bridge_init(s_device_id);

    ESP_LOGI("SYS", "========== 启动完成 ==========");
}
