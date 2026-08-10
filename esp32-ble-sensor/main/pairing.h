/**
 * @file  pairing.h
 * @brief 串口配网模块 — 大禹帧协议定义 + 配置结构体 + API
 *
 * 帧格式 (大禹约定):
 *   AA 55 | ver(1B) | type(1B) | seq(1B) | len(2B BE) | payload(var) | CRC16(2B MODBUS)
 *
 * CRC16 覆盖范围: ver + type + seq + len(2B) + payload
 */
#ifndef PAIRING_H
#define PAIRING_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ======================== 帧协议常量 ======================== */
#define PAIR_FRAME_SYNC1        0xAA
#define PAIR_FRAME_SYNC2        0x55
#define PAIR_FRAME_VER          0x01
#define PAIR_FRAME_MAX_PAYLOAD  512

/* ======================== 命令类型 ======================== */

/* 大禹 -> ESP32 */
#define PAIR_TYPE_ENTER_CONFIG  0x10  /* 请求进入配网 */
#define PAIR_TYPE_CONFIG_SET    0x20  /* 发送配置 JSON    */
#define PAIR_TYPE_CONFIG_SAVE   0x30  /* 要求保存配置      */
#define PAIR_TYPE_CONFIG_TEST   0x40  /* 测试 WiFi/MQTT   */
#define PAIR_TYPE_REBOOT        0x50  /* 重启设备          */

/* ESP32 -> 大禹 */
#define PAIR_TYPE_CONFIG_MODE_ACK   0x11  /* 已进入配网模式  */
#define PAIR_TYPE_CONFIG_ACK        0x21  /* 已收到配置      */
#define PAIR_TYPE_CONFIG_SAVED      0x31  /* 保存完成        */
#define PAIR_TYPE_CONFIG_TEST_RESULT 0x41 /* 测试结果        */
#define PAIR_TYPE_ERROR             0x7F  /* 错误            */

/* ======================== 配网窗口参数 ======================== */
#define PAIRING_UART_PORT       UART_NUM_0
#define PAIRING_UART_BAUD       115200
#define PAIRING_WINDOW_MS       4000    /* 上电配网窗口 (ms) */
#define PAIRING_POLL_INTERVAL_MS 10     /* 串口轮询间隔      */

/* ======================== NVS 命名空间 & 键 ======================== */
#define PAIR_NVS_NAMESPACE     "pairing"
#define PAIR_NVS_KEY_SSID      "ssid"
#define PAIR_NVS_KEY_PASS      "pass"
#define PAIR_NVS_KEY_BROKER    "broker"
#define PAIR_NVS_KEY_HTTP      "http"
#define PAIR_NVS_KEY_DEVID     "devid"
#define PAIR_NVS_KEY_CRYPTO    "crypto"
#define PAIR_NVS_KEY_TRANSPORT "transport"
#define PAIR_NVS_KEY_PAIRED    "paired"   /* uint8: 1=已配网 */

/* ======================== 配置结构体 ======================== */

/**
 * @brief 配网后运行时配置 (替代硬编码 #define)
 */
typedef struct {
    char    wifi_ssid[33];      /* WiFi SSID (UTF-8, max 32 + NUL)      */
    char    wifi_pass[65];      /* WiFi 密码 (max 64 + NUL)             */
    char    broker_url[128];    /* MQTT broker URL 完整字符串,          */
                                /*   例: mqtts://192.168.3.5:8883       */
    char    http_url[128];      /* HTTP bridge URL,                     */
                                /*   例: https://192.168.3.5:3444/...   */
    char    device_id[32];      /* 设备标识, 例: esp32                  */
    bool    crypto_sm4;         /* true=SM4, false=AES                  */
    char    transport[8];       /* "mqtt" 或 "http"                     */
    bool    paired;             /* NVS 中是否有有效配置                  */
} pairing_config_t;

/* ======================== 全局配置实例 ======================== */
extern pairing_config_t g_pairing_config;

/* ======================== API ======================== */

/**
 * @brief 串口配网初始化 (在 app_main 最早期调用)
 *
 * 流程:
 *   1. 初始化 NVS, 尝试加载已有配置
 *   2. 初始化 UART0, 进入配网监听窗口
 *      - 有 NVS 配置: 等待 PAIRING_WINDOW_MS ms
 *      - 无 NVS 配置: 无限等待直到配网成功
 *   3. 窗口内收到 0x10 → 进入配网模式 (状态机)
 *   4. 配网模式中:
 *      - 0x20: 解析 JSON → 存 RAM → 回 0x21
 *      - 0x30: 写 NVS → 回 0x31
 *      - 0x40: 测试连接 (预留)
 *      - 0x50: 写 NVS → esp_restart()
 *   5. 窗口超时且有配置 → 返回, 进入正常启动流程
 */
void pairing_init(void);

/**
 * @brief 从 NVS 加载配网配置到 g_pairing_config
 * @return true 加载成功且有效, false 无有效配置
 */
bool pairing_load_nvs(void);

/**
 * @brief 判断 Broker URL 是否为 TLS
 */
bool pairing_broker_is_tls(void);

#ifdef __cplusplus
}
#endif

#endif /* PAIRING_H */
