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
#include "driver/i2c_master.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include "mqtt_client.h"
#include "esp_http_client.h"
#include "crypto_layer.h"
#include "key_layer.h"
#include "pairing.h"
#include "esp_random.h"
#include "esp_mac.h"

/* ======================== 设备唯一标识 ======================== */
extern char s_device_id[32];
#define DEVICE_ID_MAC()     s_device_id

/* ======================== 能力声明 ======================== */
#define DEVICE_CAPS          "[\"sensor\",\"door\",\"light\"]"

/* ======================== WiFi 配置 ======================== */
/* SSID/Password 运行时来自 g_pairing_config (NVS 或 配网或 默认值) */
#define WIFI_SSID()         (g_pairing_config.wifi_ssid)
#define WIFI_PASS()         (g_pairing_config.wifi_pass)
#define WIFI_MAX_RETRY      5

/* MQTT Broker — beacon 自动发现优先, 下面为 fallback */
extern char s_broker_ip[32];   /* 大禹 Broker IP */
extern int s_broker_port;
#define MQTT_BROKER_IP      s_broker_ip           /* 指向动态变量 */
#define MQTT_BROKER_PORT    s_broker_port

/* 传输层加密: 运行时根据 broker URL scheme 判断 (mqtts:// = TLS) */
#define MQTT_USE_TLS()      pairing_broker_is_tls()
#define MQTT_BROKER_PORT_TLS 8884

/* Topic 运行时构建: 使用 snprintf(buf, size, fmt, s_device_id) */
#define MQTT_TOPIC_SUB_FMT       "dayu/cmd/%s"
#define MQTT_TOPIC_SENSOR_FMT    "device/%s/sensor"
#define MQTT_TOPIC_STATUS_FMT    "device/%s/status"
#define MQTT_TOPIC_AC_FMT        "device/%s/ac"
#define KEY_MQTT_TOPIC_PREFIX    "key/ecdh/pub"   /* 发布到 /{deviceId} */

/* ======================== 多协议支持 ======================== */
#define DEVICE_ID()         DEVICE_ID_MAC()
#define PROTO_ENABLE_MQTT   1                    /* MQTT 协议 */
#define PROTO_ENABLE_HTTP   1                    /* HTTP 协议 (broker bridge) */
#define PROTO_ENABLE_COAP   0                    /* CoAP 协议(预留) */

/* 运行时协议选择: 1=MQTT, 2=HTTP (大禹指令切换, 默认MQTT) */
extern int g_proto_mode;
#define PROTO_MODE_MQTT_ONLY 1
#define PROTO_MODE_HTTP_ONLY 2

/* 密钥协商开关: 0=关闭(测试连通), 1=启用(ECDH+HKDF动态密钥) */
#define KEY_EXCHANGE_ENABLE 1

/* HTTP 配置 — 运行时来自 g_pairing_config (NVS 或 配网或 默认值) */
#define HTTP_TARGET_URL()   (g_pairing_config.http_url)

/* 数据层加密开关: 0=明文JSON, 1=AES-256-GCM加密 */
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
#define DEBUG_SENSOR_UART   1    /* 传感器串口输出 (1=开启, 0=关闭) */
#define SHT31_DEBUG_LOG     0    /* SHT31 解析调试日志 (1=开启, 0=关闭) */

/* ======================== 硬件引脚配置 ======================== */

/* PIR SR602 人体红外传感器引脚 (数字量) */
#define PIR_SENSOR_GPIO       GPIO_NUM_13     /* PIR 信号输入引脚 */

/* GY-30 BH1750 光照传感器 I2C 引脚 */
#define GY30_I2C_SDA_PIN      GPIO_NUM_12    /* I2C SDA */
#define GY30_I2C_SCL_PIN      GPIO_NUM_11    /* I2C SCL */
#define GY30_I2C_FREQ_HZ      100000         /* I2C 时钟频率 100kHz */
#define GY30_SENSOR_ADDR      0x23           /* BH1750 I2C 地址 */

/* SHT31 温湿度传感器 UART 引脚 */
#define SHT31_UART_PORT       UART_NUM_1     /* UART1 */
#define SHT31_UART_RX_PIN     GPIO_NUM_4     /* UART RX (接收 SHT31 上报数据) */
#define SHT31_UART_TX_PIN     GPIO_NUM_5     /* UART TX */
#define SHT31_UART_BAUD_RATE  9600           /* SHT31 串口波特率 */

/* LED 控制引脚 */
#define LED_GPIO              GPIO_NUM_21     /* LED 引脚 */
#define LED_ON_LEVEL          1              /* LED 点亮电平: 1=高电平, 0=低电平 */

/* 光照度阈值: 低于此值且有人时点亮 LED */
#define LIGHT_THRESHOLD_LUX   200.0f

/* 调试串口输出配置 (使用板载烧录串口 UART0) */
#define DBG_UART_PORT         UART_NUM_0     /* UART0=板载烧录串口 */
#define DBG_UART_BAUD_RATE    115200         /* 波特率 */

/* ======================== 任务配置 ======================== */
#define SENSOR_TASK_STACK_SIZE    4096
#define SENSOR_TASK_PRIORITY      5
#define ACTUATOR_TASK_STACK_SIZE  2048
#define ACTUATOR_TASK_PRIORITY    4
#define MQTT_TASK_STACK_SIZE      6144
#define MQTT_TASK_PRIORITY        4
#if PROTO_ENABLE_HTTP
#define HTTP_TASK_STACK_SIZE      12288
#define HTTP_TASK_PRIORITY        3
#endif
#define SENSOR_READ_INTERVAL_MS   1000        /* 传感器读取间隔 (ms) */

__attribute__((unused)) static const char *TAG_SR602    = "SR602";
__attribute__((unused)) static const char *TAG_GY30     = "GY30";
__attribute__((unused)) static const char *TAG_SHT31    = "SHT31";
__attribute__((unused)) static const char *TAG_ACTUATOR = "ACTUATOR";
__attribute__((unused)) static const char *TAG_WIFI     = "WIFI";
__attribute__((unused)) static const char *TAG_MQTT     = "MQTT";
#if PROTO_ENABLE_HTTP
__attribute__((unused)) static const char *TAG_HTTP     = "HTTP";
#endif
__attribute__((unused)) static const char *TAG_KEY      = "KEY";


/* MQTT 客户端句柄 */
extern esp_mqtt_client_handle_t s_mqtt_client;

/* ======================== 系统统一数据结构 ======================== */

/**
 * @brief LED 控制锁 (大禹远程控制时锁定, 禁止本地自动逻辑覆盖)
 */
typedef struct {
    char     owner[16];       /* 锁持有者: "dayu" 或 "" (无锁) */
    int      priority;        /* 优先级, 越高越优先 */
    uint32_t lock_until_ms;   /* 锁过期时间 (FreeRTOS tick, ms) */
    int      last_seq;        /* 最后一次指令序号 */
} led_lock_t;

/**
 * @brief 系统传感器/执行器数据 (所有任务共享)
 */
typedef struct {
    uint8_t  pir_detected;       /* 1=检测到人, 0=无人 */
    float    light_lux;          /* 光照度 (lux) */
    float    temperature;        /* 温度 (°C) */
    float    humidity;           /* 湿度 (%RH) */
    uint8_t  led_cmd;            /* LED 控制指令: 1=应点亮, 0=应熄灭 */
    uint8_t  led_on;             /* LED 实际状态: 1=亮, 0=灭 */
    led_lock_t led_lock;         /* LED 控制锁 */
    uint8_t  door_open;          /* 门锁状态: 1=开, 0=关 */
    uint8_t  door_locked;        /* 门锁是否锁定: 1=锁定 */
    led_lock_t door_lock;        /* 门锁控制锁 */
    uint32_t timestamp;          /* 最近一次更新时间 (tick) */
} system_data_t;

/* 全局系统数据 & 互斥锁 */
extern system_data_t s_sys_data;
extern SemaphoreHandle_t s_sys_mutex;

/* I2C 句柄 */
extern i2c_master_bus_handle_t s_i2c_bus;
extern i2c_master_dev_handle_t s_gy30_dev;

void dbg_uart_printf(const char *fmt, ...);



#endif
