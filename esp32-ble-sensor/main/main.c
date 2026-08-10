/**
 * @file  main.c
 * @brief ESP32 主程序 — 初始化 + 任务创建
 */
#include "main_config.h"
#include "sensors.h"
#include "wifi_app.h"
#include "mqtt_app.h"
#include "http_app.h"
#include "actuator.h"
#include "door.h"
#include "ble_peripheral.h"
#include "ble_bridge.h"
#include "ble_crypto.h"


/* ===== 全局变量定义 (extern 声明在 main_config.h) ===== */
SemaphoreHandle_t s_sys_mutex = NULL;
system_data_t s_sys_data = {0};
i2c_master_bus_handle_t s_i2c_bus = NULL;
i2c_master_dev_handle_t s_gy30_dev = NULL;
esp_mqtt_client_handle_t s_mqtt_client = NULL;
char s_broker_ip[32] = "192.168.3.5";
int s_broker_port = 1883;
int g_proto_mode = PROTO_MODE_MQTT_ONLY;  /* 默认仅MQTT */
char s_device_id[32] = {0};

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

/* ======================== 系统初始化汇总 ======================== */

static void system_init(void)
{
    /* 互斥锁 (必须在任何会使用 s_sys_mutex 的模块之前创建) */
    s_sys_mutex = xSemaphoreCreateMutex();

    /* 硬件外设 */
    pir_gpio_init();
    gy30_i2c_init();
    led_gpio_init();
    sht31_uart_init();
    door_init();

    ESP_LOGI("SYS", "========== ESP32 启动 ==========");
}

/* ======================== 主函数 ======================== */

void app_main(void)
{
    /* 0. 设备唯一ID (MAC生成 → 配网可能覆盖) */
    device_id_init();

    /* 0b. 串口配网 */
    pairing_init();
    /* 配网后同步 deviceId (NVS 或 配网写入的值) */
    strncpy(s_device_id, g_pairing_config.device_id, sizeof(s_device_id) - 1);

    /* 0c. 串口 debug (UART0 重配为 debug 输出) */
    dbg_uart_init();

    /* 0c. 根据配网配置设置初始协议模式和加密模式 */
    /* 重启默认 MQTT + SM4, 后续大禹可切 */
    g_proto_mode = PROTO_MODE_MQTT_ONLY;
    crypto_set_mode(true);  /* true=SM4 */

    /* 1. 硬件初始化 */
    system_init();

    /* 2. WiFi */
    ESP_LOGI("SYS", "--- WiFi ---");
    wifi_init_sta();

    /* 3. 安全 */
#if KEY_EXCHANGE_ENABLE
    ESP_LOGI("SYS", "--- 安全 ---");
    if (key_layer_init()) {
        ESP_LOGI("SYS", "ECDH+HKDF OK");
    } else {
        ESP_LOGW("SYS", "ECDH+HKDF FAIL");
    }
    /* Reset 后统一回退静态密钥, epoch=0, 等大禹重新 ECDH */
    key_layer_reset_boot();
#endif

    /* 4. 任务 */
    ESP_LOGI("SYS", "--- 任务 ---");
    ESP_LOGI("SYS", "SSID:%s 加密:%s TLS:%s MQTT:%s HTTP:%s",
             g_pairing_config.wifi_ssid,
             CRYPTO_ENABLE ? (crypto_get_mode() ? "SM4" : "AES") : "OFF",
             MQTT_USE_TLS() ? "ON" : "OFF",
             PROTO_ENABLE_MQTT ? "ON" : "OFF",
             PROTO_ENABLE_HTTP ? "ON" : "OFF");

    xTaskCreate(sensor_task,    "sensor",    SENSOR_TASK_STACK_SIZE,
                NULL, SENSOR_TASK_PRIORITY, NULL);
    xTaskCreate(actuator_task,  "actuator",  ACTUATOR_TASK_STACK_SIZE,
                NULL, ACTUATOR_TASK_PRIORITY, NULL);
    xTaskCreate(mqtt_task,      "mqtt",      MQTT_TASK_STACK_SIZE,
                NULL, MQTT_TASK_PRIORITY, NULL);
#if PROTO_ENABLE_HTTP
    xTaskCreate(http_task,      "http",      HTTP_TASK_STACK_SIZE,
                NULL, HTTP_TASK_PRIORITY, NULL);
#endif

    /* ---- 大禹测试向量验证 ---- */
    {
        extern void sm4_gcm_encrypt(const uint8_t*,const uint8_t*,size_t,const uint8_t*,uint8_t*,uint8_t*);
        extern bool sm4_gcm_decrypt(const uint8_t*,const uint8_t*,size_t,const uint8_t*,const uint8_t*,uint8_t*);
        uint8_t dk[16] = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
                           0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10};
        uint8_t div[12] = {0x24,0xa6,0x53,0xf7,0x22,0xbb,0x96,0x0e,0xbe,0x2a,0x0c,0xfb};
        const char *dpt = "{\"cmd\":\"ac\",\"brand\":\"格力\",\"temp\":24,\"power\":true}";
        int dpt_len = strlen(dpt);
        uint8_t dct[64], dtag[16], dresult[64];
        sm4_gcm_encrypt(dk, (uint8_t*)dpt, dpt_len, div, dct, dtag);
        printf("\n=== DAYU VECTOR TEST ===\n");
        printf("  PT=%d: %s\n", dpt_len, dpt);
        printf("  Dayu TAG: 30e6ac6c8077948ac619ee3fbe888664\n");
        printf("  Our  TAG: "); for(int i=0;i<16;i++) printf("%02x",dtag[i]); printf("\n");
        printf("  Dayu CT:  a9e59c32fab1c1d373eb32c60a1de0e7b2e079f8...\n");
        printf("  Our  CT:  "); for(int i=0;i<dpt_len;i++) printf("%02x",dct[i]); printf("\n");
        bool d_ok = sm4_gcm_decrypt(dk, dct, dpt_len, div, dtag, dresult);
        printf("  Self decrypt: %s\n", d_ok?"PASS":"FAIL");
        if (d_ok) { dresult[dpt_len]=0; printf("  Result: %s\n", dresult); }
        /* 用大禹的完整包解密 */
        uint8_t d_full[] = {
            0x24,0xa6,0x53,0xf7,0x22,0xbb,0x96,0x0e,0xbe,0x2a,0x0c,0xfb,
            0x30,0xe6,0xac,0x6c,0x80,0x77,0x94,0x8a,0xc6,0x19,0xee,0x3f,0xbe,0x88,0x86,0x64,
            0xa9,0xe5,0x9c,0x32,0xfa,0xb1,0xc1,0xd3,0x73,0xeb,0x32,0xc6,0x0a,0x1d,0xe0,0xe7,
            0xb2,0xe0,0x79,0xf8,0xe4,0xb9,0x30,0x6a,0xb2,0xdd,0x65,0x2c,0x95,0x19,0xce,0x9c,
            0xb0,0x83,0xb6,0xef,0xef,0x69,0x20,0xfe,0x49,0x82,0x39,0xec,0x44,0xf5,0x26,0xcf,
            0xfd,0x8b,0x48,0xe3
        };
        uint8_t d_plain[80];
        bool d2 = sm4_gcm_decrypt(dk, d_full+28, dpt_len, d_full, d_full+12, d_plain);
        printf("  Dayu pkt decrypt: %s\n", d2?"PASS":"FAIL");
        if (d2) { d_plain[dpt_len]=0; printf("  Result: %s\n", d_plain); }
        printf("=== END VECTOR ===\n\n");
    }

    ESP_LOGI("SYS", "========== 启动完成 ==========");

    /* BLE Peripheral — start after all other initialisation is done */
    ble_peripheral_init();
    ble_crypto_init(s_device_id);

    /* BLE 日常通信桥接: 注册 business_cmd 回调 → 开灯控制 */
    ble_bridge_init(s_device_id);
}
