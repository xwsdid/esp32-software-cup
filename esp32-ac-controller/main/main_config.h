/**
 * @file  main_config.h
 * @brief 全局配置、类型定义、共享变量声明
 */
#ifndef MAIN_CONFIG_H
#define MAIN_CONFIG_H

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_err.h"
#include "driver/gpio.h"
#include "driver/uart.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include "mqtt_client.h"
#include "esp_http_client.h"
#include "crypto_layer.h"
#include "key_layer.h"
#include "pairing.h"
#include "ir_learning.h"
#include "alarm.h"
#include "stepper.h"
#include "esp_random.h"
#include "esp_mac.h"

/* ======================== 设备唯一标识 ======================== */
extern char s_device_id[32];                    /* 基于Base MAC: esp32-XXXXXXXXXXXX */
#define DEVICE_ID_MAC()     s_device_id          /* 唯一设备ID */

/* ======================== 能力声明 ======================== */
#define DEVICE_CAPS          "[\"ac\",\"ir_learning\",\"alarm\",\"curtain\"]"

/* ======================== WiFi 配置 ======================== */
/* SSID/Password 运行时来自 g_pairing_config (NVS 或 配网或 默认值) */
#define WIFI_SSID()         (g_pairing_config.wifi_ssid)
#define WIFI_PASS()         (g_pairing_config.wifi_pass)
#define WIFI_MAX_RETRY      5

/* MQTT Broker — 运行时来自配网配置 */
extern char s_broker_ip[32];
extern int s_broker_port;
#define MQTT_BROKER_IP      s_broker_ip
#define MQTT_BROKER_PORT    s_broker_port

/* 传输层加密: 运行时根据 broker URL scheme 判断 (mqtts:// = TLS) */
#define MQTT_USE_TLS()      pairing_broker_is_tls()
#define MQTT_BROKER_PORT_TLS 8884

/* Topic 运行时构建: 使用 snprintf(buf, size, fmt, s_device_id) */
#define MQTT_TOPIC_SUB_FMT       "dayu/cmd/%s"
#define MQTT_TOPIC_SENSOR_FMT    "device/%s/sensor"
#define MQTT_TOPIC_STATUS_FMT    "device/%s/status"
#define MQTT_TOPIC_AC_FMT        "device/%s/ac"
#define KEY_MQTT_TOPIC_PREFIX    "key/ecdh/pub"

/* ======================== 多协议支持 ======================== */
#define DEVICE_ID()         DEVICE_ID_MAC()
#define PROTO_ENABLE_MQTT   1
#define PROTO_ENABLE_HTTP   1
#define PROTO_ENABLE_COAP   0

extern int g_proto_mode;
#define PROTO_MODE_MQTT_ONLY 1
#define PROTO_MODE_HTTP_ONLY 2

/* 密钥协商开关 */
#define KEY_EXCHANGE_ENABLE 1

/* HTTP 配置 — 运行时来自 g_pairing_config */
#define HTTP_TARGET_URL()   (g_pairing_config.http_url)

/* 数据层加密开关 */
#define CRYPTO_ENABLE       1

/* 大禹 Broker CA 证书 */
static const char s_mqtt_ca_cert[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIID6TCCAtGgAwIBAgIUBYWSCdPlmmPfr7XmfOH0eET797MwDQYJKoZIhvcNAQEL\n"
    "BQAwfDELMAkGA1UEBhMCQ04xDjAMBgNVBAgMBUxvY2FsMQ4wDAYDVQQHDAVMb2Nh\n"
    "bDEWMBQGA1UECgwNTXkgU21hcnQgSG9tZTEWMBQGA1UECwwNTG9jYWwgTVFUVCBD\n"
    "QTEdMBsGA1UEAwwUTXlTbWFydEhvbWUgTG9jYWwgQ0EwHhcNMjYwNjI4MDQzMDQ1\n"
    "WhcNMzYwNjI1MDQzMDQ1WjB8MQswCQYDVQQGEwJDTjEOMAwGA1UECAwFTG9jYWwx\n"
    "DjAMBgNVBAcMBUxvY2FsMRYwFAYDVQQKDA1NeSBTbWFydCBIb21lMRYwFAYDVQQL\n"
    "DA1Mb2NhbCBNUVRUIENBMR0wGwYDVQQDDBRNeVNtYXJ0SG9tZSBMb2NhbCBDQTCC\n"
    "ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALkrYrYaxMr1VSu3InLBVNxQ\n"
    "mpdSClL1vWziCiofTrt3iLFx+rXHscBi9FgwQxxOZ4j8paHsPW4bM8cAHnAdajHp\n"
    "BMNxAwTQ8O3BbOgg0Oabo3LoQW2Nb0Nl36Yz6ZlkkhlTbmedUWks+d/MJ6zw/KaC\n"
    "El1jSX6Icjqow0F6cIvEd1o4ubIC/1iykKrTQr/q+wb+fjT5FRTIktA9YIO0kvxe\n"
    "QQZ+cs3Kawo6cb5owoxYyVtDyzZWCu9ZotoogZbdF6RIOwnbJMQY9MvpJ9qIjXjM\n"
    "puCNrURm+GHcK/C92qWpb3Kvpaj4kMLdnr1DvrMI24uZxG7ie+W9oL8seyLj11UC\n"
    "AwEAAaNjMGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0O\n"
    "BBYEFHnBXb67+wWRwhw62+4UDPnHKY/sMB8GA1UdIwQYMBaAFHnBXb67+wWRwhw6\n"
    "2+4UDPnHKY/sMA0GCSqGSIb3DQEBCwUAA4IBAQCPxRRdUn9op87iZ7Qdknj881Lf\n"
    "KOFpNjRkWkhlliUA3addkdHvzaKIRltIGPT/KR5S/g6jlLcUjyZvhiXXCzpi9+gl\n"
    "moWjjwUpDWApLy4WOkBs1gzcevZVzJls4fJ/fuiCZT1VeWk4DgzoGE5KnkDmwNwO\n"
    "d0yTcn6H3VmmmgSDqPm8XihQwpV2pZI1v4xSnWABR0ApG5435abrkRm7J2zDRiy+\n"
    "PRSvPo3NeG/+lwgfWQbNALacROlq8ykqHX9jdAgXrco3CSXand5nNDM0ExrLEuhz\n"
    "m2Ar+heto6sMG5FPgmhGm5kyspxxyNLSxCuHOSQDx80i8czfaVZEk4DfqFDv\n"
    "-----END CERTIFICATE-----\n";

/* ======================== 调试控制位 ======================== */
#define DEBUG_SENSOR_UART   1

/* ======================== 红外模块硬件引脚 ======================== */
#define IR_TX_PIN           16       /* ESP32 TX → 红外模块 J1 RX */
#define IR_RX_PIN           17       /* ESP32 RX → 红外模块 J1 TX */
#define IR_BAUD_RATE        115200

/* 调试串口输出配置 (板载烧录串口 UART0) */
#define DBG_UART_PORT       UART_NUM_0
#define DBG_UART_BAUD_RATE  115200

/* ======================== 空调按键索引 (与红外模块学习槽位对应) ======================== */
/* 学习顺序: 1=开机 2=关机 3=温度+ 4=温度- 5=制冷 6=制热 (0保留) */
typedef enum {
    AC_KEY_NONE     = 0,    /* 保留 */
    AC_KEY_ON       = 1,    /* 开机 */
    AC_KEY_OFF      = 2,    /* 关机 */
    AC_KEY_TEMP_UP  = 3,    /* 温度+ */
    AC_KEY_TEMP_DN  = 4,    /* 温度- */
    AC_KEY_COOL     = 5,    /* 制冷模式 */
    AC_KEY_HEAT     = 6,    /* 制热模式 */
} ac_key_index_t;

static const char *ac_key_names[] __attribute__((unused)) = {
    "---", "开机", "关机", "温度+", "温度-", "制冷", "制热"
};

/* ======================== 空调状态跟踪 ======================== */
typedef struct {
    uint8_t  power;         /* 0=关, 1=开 */
    float    target_temp;   /* 目标温度 °C (通常16~30) */
    uint8_t  mode;          /* 0=制冷, 1=制热, 2=送风, 3=除湿 */
    uint8_t  fan_speed;     /* 0=自动, 1=低, 2=中, 3=高 */
    uint8_t  swing;         /* 0=关, 1=开 */
    uint32_t timestamp;     /* 最近一次更新时间 (tick) */
} ac_state_t;

/* 全局空调状态 & 互斥锁 */
extern ac_state_t s_ac_state;
extern SemaphoreHandle_t s_ac_mutex;

/* MQTT 客户端句柄 */
extern esp_mqtt_client_handle_t s_mqtt_client;

/* 系统互斥锁 (兼容旧模块) */
extern SemaphoreHandle_t s_sys_mutex;

/* ======================== 任务配置 ======================== */
#define MQTT_TASK_STACK_SIZE      10240
#define MQTT_TASK_PRIORITY        4
#if PROTO_ENABLE_HTTP
#define HTTP_TASK_STACK_SIZE      12288
#define HTTP_TASK_PRIORITY        3
#endif
#define TASK_LOOP_INTERVAL_MS     1000   /* 主循环间隔 (ms) */

/* ======================== LOG TAG ======================== */
__attribute__((unused)) static const char *TAG_IR      = "IR";
__attribute__((unused)) static const char *TAG_WIFI    = "WIFI";
__attribute__((unused)) static const char *TAG_MQTT    = "MQTT";
#if PROTO_ENABLE_HTTP
__attribute__((unused)) static const char *TAG_HTTP    = "HTTP";
#endif
__attribute__((unused)) static const char *TAG_KEY     = "KEY";

void dbg_uart_printf(const char *fmt, ...);

#endif
