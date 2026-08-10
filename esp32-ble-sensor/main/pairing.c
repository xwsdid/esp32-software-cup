/**
 * @file  pairing.c
 * @brief 串口配网实现 — 大禹帧协议 CRC16 + 帧解析/构建 + 状态机 + NVS 读写
 */
#include "pairing.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/uart.h"
#include "driver/usb_serial_jtag.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_mac.h"
#include "nvs_flash.h"
#include "nvs.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static const char *TAG_PAIR = "PAIR";

/* ======================== 全局配置实例 ======================== */
pairing_config_t g_pairing_config = {0};

/* ======================== CRC16 MODBUS ======================== */

/**
 * @brief CRC16 MODBUS (poly=0x8005, init=0xFFFF, reflected)
 */
static uint16_t crc16_modbus(const uint8_t *data, size_t len)
{
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            if (crc & 0x0001)
                crc = (crc >> 1) ^ 0xA001;
            else
                crc >>= 1;
        }
    }
    return crc;
}

/* ======================== 帧构建 ======================== */

/**
 * @brief 构建大禹帧协议数据包
 * @param buf          输出缓冲区
 * @param buf_size     缓冲区大小
 * @param type         命令类型
 * @param seq          序列号
 * @param payload      载荷数据 (可为 NULL)
 * @param payload_len  载荷长度 (0 表示无载荷)
 * @return 帧总字节数, 或 -1 缓冲区不够
 */
static int pairing_build_frame(uint8_t *buf, size_t buf_size,
                               uint8_t type, uint8_t seq,
                               const uint8_t *payload, uint16_t payload_len)
{
    size_t total = 2 + 1 + 1 + 1 + 2 + payload_len + 2;  /* 9 + payload */
    if (total > buf_size) return -1;

    buf[0] = PAIR_FRAME_SYNC1;          /* AA */
    buf[1] = PAIR_FRAME_SYNC2;          /* 55 */
    buf[2] = PAIR_FRAME_VER;            /* ver  */
    buf[3] = type;                      /* type */
    buf[4] = seq;                       /* seq  */
    buf[5] = (uint8_t)((payload_len >> 8) & 0xFF); /* len high (大端) */
    buf[6] = (uint8_t)(payload_len & 0xFF);        /* len low             */
    if (payload_len > 0 && payload != NULL) {
        memcpy(buf + 7, payload, payload_len);
    }

    /* CRC16 覆盖 ver .. payload (不含 AA 55) */
    uint16_t crc = crc16_modbus(buf + 2, 5 + payload_len);
    buf[7 + payload_len] = (uint8_t)(crc & 0xFF);
    buf[8 + payload_len] = (uint8_t)((crc >> 8) & 0xFF);

    return (int)total;
}

/**
 * @brief 发送帧 (无载荷)
 */
static void pairing_send_frame(uint8_t type, uint8_t seq)
{
    uint8_t buf[16];  /* 9 字节最小帧 */
    int len = pairing_build_frame(buf, sizeof(buf), type, seq, NULL, 0);
    if (len > 0) {
        uart_write_bytes(PAIRING_UART_PORT, buf, len);
        usb_serial_jtag_write_bytes(buf, len, portMAX_DELAY);
    }
}

/**
 * @brief 发送 JSON 载荷帧
 */
static void pairing_send_json(uint8_t type, uint8_t seq, const char *json)
{
    uint8_t buf[PAIR_FRAME_MAX_PAYLOAD + 16];
    int len = pairing_build_frame(buf, sizeof(buf), type, seq,
                                  (const uint8_t *)json, (uint16_t)strlen(json));
    if (len > 0) {
        uart_write_bytes(PAIRING_UART_PORT, buf, len);
        usb_serial_jtag_write_bytes(buf, len, portMAX_DELAY);
    }
}

/**
 * @brief 发送错误帧
 */
static void pairing_send_error(uint8_t seq, const char *msg)
{
    pairing_send_json(PAIR_TYPE_ERROR, seq, msg);
}

/* ======================== 帧接收 ======================== */

typedef enum {
    RX_SYNC1,
    RX_SYNC2,
    RX_HEADER,
    RX_PAYLOAD,
    RX_CRC,
} rx_state_t;

typedef struct {
    rx_state_t  state;
    uint8_t     header[5];       /* ver, type, seq, len_lo, len_hi */
    uint8_t     header_pos;
    uint16_t    expected_len;
    uint8_t     pay_buf[PAIR_FRAME_MAX_PAYLOAD];
    uint16_t    pay_pos;
    uint8_t     crc_buf[2];
    uint8_t     crc_pos;
    uint8_t     frame_ver, frame_type, frame_seq;
} frame_reader_t;

static void fr_reset(frame_reader_t *fr)
{
    memset(fr, 0, sizeof(*fr));
    fr->state = RX_SYNC1;
}

/**
 * @brief 馈入一个字节, 尝试解析帧
 * @return  0 = 继续等待
 *          1 = 完整帧接收成功 (type/seq/payload 已填充)
 *         -1 = CRC 校验失败
 */
static int fr_feed(frame_reader_t *fr, uint8_t b,
                   uint8_t *type_out, uint8_t *seq_out,
                   uint8_t *payload, uint16_t *payload_len)
{
    switch (fr->state) {
    case RX_SYNC1:
        if (b == PAIR_FRAME_SYNC1) fr->state = RX_SYNC2;
        break;

    case RX_SYNC2:
        if (b == PAIR_FRAME_SYNC2) {
            fr->state      = RX_HEADER;
            fr->header_pos = 0;
        } else if (b != PAIR_FRAME_SYNC1) {
            fr->state = RX_SYNC1;  /* 非法, 重新找 AA */
        }
        /* b == AA: 留在 RX_SYNC2 (兼容 AA AA 55) */
        break;

    case RX_HEADER:
        fr->header[fr->header_pos++] = b;
        if (fr->header_pos >= 5) {
            fr->frame_ver  = fr->header[0];
            fr->frame_type = fr->header[1];
            fr->frame_seq  = fr->header[2];
            fr->expected_len = ((uint16_t)fr->header[3] << 8)
                             | (uint16_t)fr->header[4];  /* 大端 */

            if (fr->expected_len > PAIR_FRAME_MAX_PAYLOAD) {
                fr_reset(fr);  /* 非法长度, 丢弃 */
                return 0;
            }
            if (fr->expected_len == 0) {
                fr->state   = RX_CRC;
                fr->crc_pos = 0;
            } else {
                fr->state   = RX_PAYLOAD;
                fr->pay_pos = 0;
            }
        }
        break;

    case RX_PAYLOAD:
        fr->pay_buf[fr->pay_pos++] = b;
        if (fr->pay_pos >= fr->expected_len) {
            fr->state   = RX_CRC;
            fr->crc_pos = 0;
        }
        break;

    case RX_CRC:
        fr->crc_buf[fr->crc_pos++] = b;
        if (fr->crc_pos >= 2) {
            /* 计算 CRC: ver + type + seq + len(2B) + payload */
            uint8_t crc_input[PAIR_FRAME_MAX_PAYLOAD + 5];
            crc_input[0] = fr->frame_ver;
            crc_input[1] = fr->frame_type;
            crc_input[2] = fr->frame_seq;
            crc_input[3] = fr->header[3];
            crc_input[4] = fr->header[4];
            if (fr->expected_len > 0) {
                memcpy(crc_input + 5, fr->pay_buf, fr->expected_len);
            }
            uint16_t calc = crc16_modbus(crc_input, 5 + fr->expected_len);
            uint16_t rx   = (uint16_t)fr->crc_buf[0]
                          | ((uint16_t)fr->crc_buf[1] << 8);

            /* 先保存帧数据到输出缓冲区, 再 reset (reset 会 memset 清零所有字段!) */
            if (fr->expected_len > 0) {
                memcpy(payload, fr->pay_buf, fr->expected_len);
            }
            uint8_t  saved_type    = fr->frame_type;
            uint8_t  saved_seq     = fr->frame_seq;
            uint16_t saved_pay_len = fr->expected_len;

            fr_reset(fr);  /* 准备下一个帧 */

            if (calc == rx) {
                *type_out    = saved_type;
                *seq_out     = saved_seq;
                *payload_len = saved_pay_len;
                return 1;   /* 成功 */
            }
            ESP_LOGW(TAG_PAIR, "CRC err: calc=0x%04X rx=0x%04X", calc, rx);
            return -1;  /* CRC 错误 */
        }
        break;
    }
    return 0;  /* 继续等待 */
}

/* ======================== JSON 字段提取 (strstr, 不依赖 cJSON) ======================== */

/**
 * @brief 从简易 JSON 中提取字符串字段
 * @param json    JSON 字符串
 * @param key     字段名 (例如 "ssid")
 * @param out     输出缓冲区
 * @param out_size 输出缓冲区大小
 * @return true 找到字段, false 未找到
 */
static bool json_get_str(const char *json, const char *key,
                         char *out, size_t out_size)
{
    /* 构造搜索模式 "key":" (兼容冒号后有空格) */
    char pattern[64];
    int plen = snprintf(pattern, sizeof(pattern), "\"%s\":", key);

    const char *start = strstr(json, pattern);
    if (!start) return false;
    start += plen;

    /* 跳过冒号后的空白字符 */
    while (*start == ' ' || *start == '\t') start++;

    if (*start != '"') return false;  /* 期望值以引号开始 */
    start++;  /* 跳过开头引号 */

    const char *end = strchr(start, '"');
    if (!end) return false;

    size_t len = (size_t)(end - start);
    if (len >= out_size) len = out_size - 1;
    memcpy(out, start, len);
    out[len] = '\0';
    return true;
}

/**
 * @brief 解析 CONFIG_SET(0x20) 的 JSON payload
 */
static bool pairing_parse_config_json(const uint8_t *payload, uint16_t len,
                                      pairing_config_t *cfg)
{
    char json[PAIR_FRAME_MAX_PAYLOAD + 1];
    size_t copy_len = len < sizeof(json) - 1 ? len : sizeof(json) - 1;
    memcpy(json, payload, copy_len);
    json[copy_len] = '\0';

    /* 不打印完整 JSON 到 USB (会冲掉后面的 ACK 帧), 只打印摘要 */
    json_get_str(json, "ssid",       cfg->wifi_ssid,  sizeof(cfg->wifi_ssid));
    json_get_str(json, "password",   cfg->wifi_pass,  sizeof(cfg->wifi_pass));
    json_get_str(json, "brokerUrl",  cfg->broker_url, sizeof(cfg->broker_url));
    json_get_str(json, "httpBridge", cfg->http_url,   sizeof(cfg->http_url));
    json_get_str(json, "deviceId",   cfg->device_id,  sizeof(cfg->device_id));

    /* deviceId="auto" → 用 Base MAC 生成唯一 ID: esp32-XXXXXXXXXXXX */
    if (strcmp(cfg->device_id, "auto") == 0 || cfg->device_id[0] == '\0') {
        uint8_t mac[6];
        esp_read_mac(mac, ESP_MAC_WIFI_STA);
        snprintf(cfg->device_id, sizeof(cfg->device_id),
                 "esp32-%02X%02X%02X%02X%02X%02X",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        ESP_LOGI(TAG_PAIR, "deviceId auto → %s", cfg->device_id);
    }

    char crypto_buf[8] = {0};
    if (json_get_str(json, "crypto", crypto_buf, sizeof(crypto_buf))) {
        cfg->crypto_sm4 = (strcmp(crypto_buf, "sm4") == 0);
    }

    char trans_buf[8] = {0};
    if (json_get_str(json, "transport", trans_buf, sizeof(trans_buf))) {
        strncpy(cfg->transport, trans_buf, sizeof(cfg->transport) - 1);
    } else {
        strncpy(cfg->transport, "mqtt", sizeof(cfg->transport) - 1);
    }

    /* 有效性检查 */
    if (cfg->wifi_ssid[0] == '\0') {
        ESP_LOGE(TAG_PAIR, "JSON missing: ssid");
        return false;
    }
    if (cfg->wifi_pass[0] == '\0') {
        ESP_LOGE(TAG_PAIR, "JSON missing: password");
        return false;
    }
    if (cfg->broker_url[0] == '\0') {
        ESP_LOGE(TAG_PAIR, "JSON missing: brokerUrl");
        return false;
    }

    ESP_LOGI(TAG_PAIR, "JSON OK, broker=%s", cfg->broker_url);
    /* 注意: 不打印 WiFi 明文密码 */
    return true;
}

/* ======================== NVS 读写 ======================== */

bool pairing_load_nvs(void)
{
    nvs_handle_t handle;
    esp_err_t err = nvs_open(PAIR_NVS_NAMESPACE, NVS_READONLY, &handle);
    if (err != ESP_OK) {
        ESP_LOGI(TAG_PAIR, "NVS 无配网数据 (首次启动)");
        return false;
    }

    uint8_t paired_flag = 0;
    err = nvs_get_u8(handle, PAIR_NVS_KEY_PAIRED, &paired_flag);
    if (err != ESP_OK || paired_flag != 1) {
        nvs_close(handle);
        return false;
    }

    size_t len;

    len = sizeof(g_pairing_config.wifi_ssid);
    nvs_get_str(handle, PAIR_NVS_KEY_SSID, g_pairing_config.wifi_ssid, &len);

    len = sizeof(g_pairing_config.wifi_pass);
    nvs_get_str(handle, PAIR_NVS_KEY_PASS, g_pairing_config.wifi_pass, &len);

    len = sizeof(g_pairing_config.broker_url);
    nvs_get_str(handle, PAIR_NVS_KEY_BROKER, g_pairing_config.broker_url, &len);

    len = sizeof(g_pairing_config.http_url);
    err = nvs_get_str(handle, PAIR_NVS_KEY_HTTP, g_pairing_config.http_url, &len);
    if (err != ESP_OK) g_pairing_config.http_url[0] = '\0';

    len = sizeof(g_pairing_config.device_id);
    err = nvs_get_str(handle, PAIR_NVS_KEY_DEVID, g_pairing_config.device_id, &len);
    if (err != ESP_OK) strcpy(g_pairing_config.device_id, "esp32");

    char crypto_buf[8] = {0};
    len = sizeof(crypto_buf);
    if (nvs_get_str(handle, PAIR_NVS_KEY_CRYPTO, crypto_buf, &len) == ESP_OK) {
        g_pairing_config.crypto_sm4 = (strcmp(crypto_buf, "sm4") == 0);
    }

    char trans_buf[8] = {0};
    len = sizeof(trans_buf);
    if (nvs_get_str(handle, PAIR_NVS_KEY_TRANSPORT, trans_buf, &len) == ESP_OK) {
        strncpy(g_pairing_config.transport, trans_buf,
                sizeof(g_pairing_config.transport) - 1);
    } else {
        strncpy(g_pairing_config.transport, "mqtt",
                sizeof(g_pairing_config.transport) - 1);
    }

    g_pairing_config.paired = true;
    nvs_close(handle);

    ESP_LOGI(TAG_PAIR, "NVS 配网配置已加载 (SSID=%s, broker=%s)",
             g_pairing_config.wifi_ssid, g_pairing_config.broker_url);
    return true;
}

static bool pairing_save_nvs(const pairing_config_t *cfg)
{
    nvs_handle_t handle;
    esp_err_t err = nvs_open(PAIR_NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG_PAIR, "NVS 打开失败: %d", err);
        return false;
    }

    nvs_set_str(handle, PAIR_NVS_KEY_SSID,   cfg->wifi_ssid);
    nvs_set_str(handle, PAIR_NVS_KEY_PASS,   cfg->wifi_pass);
    nvs_set_str(handle, PAIR_NVS_KEY_BROKER, cfg->broker_url);
    if (cfg->http_url[0] != '\0') {
        nvs_set_str(handle, PAIR_NVS_KEY_HTTP, cfg->http_url);
    }
    nvs_set_str(handle, PAIR_NVS_KEY_DEVID,   cfg->device_id);
    nvs_set_str(handle, PAIR_NVS_KEY_CRYPTO,
                cfg->crypto_sm4 ? "sm4" : "aes");
    nvs_set_str(handle, PAIR_NVS_KEY_TRANSPORT, cfg->transport);
    nvs_set_u8(handle,  PAIR_NVS_KEY_PAIRED, 1);

    err = nvs_commit(handle);
    nvs_close(handle);

    if (err != ESP_OK) {
        ESP_LOGE(TAG_PAIR, "NVS 写入失败: %d", err);
        return false;
    }

    ESP_LOGI(TAG_PAIR, "配网配置已写入 NVS");
    return true;
}

/* ======================== Broker TLS 判断 ======================== */

bool pairing_broker_is_tls(void)
{
    return (strncmp(g_pairing_config.broker_url, "mqtts", 5) == 0);
}

/* ======================== 默认配置填充 ======================== */

/**
 * @brief 用硬编码默认值填充配置 (NVS 无数据时的 fallback)
 */
static void pairing_fill_defaults(pairing_config_t *cfg)
{
    strcpy(cfg->wifi_ssid,  "HUAWEI-1GRK2Z");
    strcpy(cfg->wifi_pass,  "a9123456");
    strcpy(cfg->broker_url, "mqtt://192.168.3.103:1883");
    strcpy(cfg->http_url,   "http://192.168.3.103:3000");
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    snprintf(cfg->device_id, sizeof(cfg->device_id),
             "esp32-%02X%02X%02X%02X%02X%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    cfg->crypto_sm4 = true;
    strcpy(cfg->transport, "mqtt");
    cfg->paired = false;
}

/* ======================== 配网状态机 ======================== */

typedef enum {
    PM_IDLE,
    PM_CONFIG_MODE,    /* 已进入配网, 等待大禹下发配置 */
    PM_CONFIG_RCVD,    /* 已收到 CONFIG_SET, 等待 CONFIG_SAVE 或 REBOOT */
    PM_SAVED,          /* 已保存, 等待 REBOOT */
} pm_state_t;

/**
 * @brief 配网主函数 — 在 app_main 最早调用
 */
void pairing_init(void)
{
    /* ---- 1. 初始化 NVS ---- */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }

    /* ---- 2. 尝试加载已有配置 ---- */
    bool has_config = pairing_load_nvs();
    if (!has_config) {
        pairing_fill_defaults(&g_pairing_config);
    }

    /* ---- 3. 初始化 UART0 ---- */
    uart_config_t uart_cfg = {
        .baud_rate  = PAIRING_UART_BAUD,
        .data_bits  = UART_DATA_8_BITS,
        .parity     = UART_PARITY_DISABLE,
        .stop_bits  = UART_STOP_BITS_1,
        .flow_ctrl  = UART_HW_FLOWCTRL_DISABLE,
    };
    uart_param_config(PAIRING_UART_PORT, &uart_cfg);
    uart_driver_install(PAIRING_UART_PORT, 1024, 0, 0, NULL, 0);

    /* 初始化 USB Serial/JTAG 驱动 (Type-C USB口) */
    usb_serial_jtag_driver_config_t usj_cfg = USB_SERIAL_JTAG_DRIVER_CONFIG_DEFAULT();
    usb_serial_jtag_driver_install(&usj_cfg);

    /* 清空残留数据 */
    uint8_t flush[64];
    uart_read_bytes(PAIRING_UART_PORT, flush, sizeof(flush), pdMS_TO_TICKS(50));

    /* ---- 4. 配网窗口 ---- */
    /* 有配置: 等 PAIRING_WINDOW_MS   无配置: 无限等 */
    uint32_t window_ms = has_config ? PAIRING_WINDOW_MS : 0xFFFFFFFF;
    TickType_t t_start = xTaskGetTickCount();

    ESP_LOGI(TAG_PAIR, "==== 配网窗口 %lums (已有配置=%d) ====",
             window_ms, has_config);

    frame_reader_t fr;
    fr_reset(&fr);
    uint8_t  rx_payload[PAIR_FRAME_MAX_PAYLOAD];
    uint16_t rx_payload_len = 0;
    uint8_t  rx_type = 0, rx_seq = 0;

    /* 调试: 收集 UART 字节 */
    uint8_t dbg_buf[128];
    int     dbg_pos = 0;
    TickType_t dbg_last_dump = xTaskGetTickCount();
    TickType_t dbg_last_ready = 0;

    pm_state_t pm = PM_IDLE;
    pairing_config_t tmp_cfg;  /* 临时配置 (RAM), 确认后才写 NVS */
    bool tmp_cfg_valid = false;

    while (1) {
        /* 只在 PM_IDLE 发心跳, 配网模式后停掉避免干扰 0x21 */
        if (pm == PM_IDLE &&
            xTaskGetTickCount() - dbg_last_ready >= pdMS_TO_TICKS(1000)) {
            const char *ready = "ESP32_UART_READY\r\n";
            uart_write_bytes(PAIRING_UART_PORT, ready, strlen(ready));
            pairing_send_frame(PAIR_TYPE_CONFIG_MODE_ACK, 1);
            {
                const uint8_t ack[] = {
                    0xAA,0x55, 0x01,0x11, 0x01, 0x00,0x00, 0x4D,0x3C
                };
                usb_serial_jtag_write_bytes(ack, sizeof(ack), portMAX_DELAY);
            }
            ESP_LOGI(TAG_PAIR, "→ SPAM 0x11 (TEST)");
            dbg_last_ready = xTaskGetTickCount();
        }

        /* ---- 窗口超时检查 ---- */
        if (has_config) {
            uint32_t elapsed = (uint32_t)(
                (xTaskGetTickCount() - t_start) * portTICK_PERIOD_MS);
            if (elapsed >= window_ms) {
                ESP_LOGI(TAG_PAIR, "配网窗口超时 → 正常启动");
                break;
            }
        }

        /* ---- 读取串口 (UART0 + USB Serial/JTAG 双口监听) ---- */
        uint8_t b;
        int n;
        /* 先试 UART0 (COM口), 再试 USB Serial/JTAG (Type-C口) */
        n = uart_read_bytes(PAIRING_UART_PORT, &b, 1,
                            pdMS_TO_TICKS(1));
        if (n <= 0)
            n = usb_serial_jtag_read_bytes(&b, 1, 1);
        if (n <= 0) {
            if (dbg_pos > 0 &&
                xTaskGetTickCount() - dbg_last_dump >= pdMS_TO_TICKS(500)) {
                char hex[256];
                int off = snprintf(hex, sizeof(hex), "UART_RX n=%d:", dbg_pos);
                for (int i = 0; i < dbg_pos && off < (int)sizeof(hex) - 4; i++)
                    off += snprintf(hex + off, sizeof(hex) - off,
                                    " %02X", dbg_buf[i]);
                uart_write_bytes(PAIRING_UART_PORT, hex, off);
                uart_write_bytes(PAIRING_UART_PORT, "\r\n", 2);
                dbg_pos = 0;
                dbg_last_dump = xTaskGetTickCount();
            }
            continue;
        }

        /* 记录收到的字节 */
        if (dbg_pos < (int)sizeof(dbg_buf) - 1)
            dbg_buf[dbg_pos++] = b;

        /* 硬编码 ACK: 滑窗匹配 ENTER_CONFIG 直接回 */
        {
            static uint8_t ring[9];
            static int ring_pos = 0;
            static const uint8_t enter_cfg[9] = {
                0xAA,0x55, 0x01,0x10, 0x01, 0x00,0x00, 0x4C,0xC0
            };
            ring[ring_pos] = b;
            ring_pos = (ring_pos + 1) % 9;
            bool match = true;
            for (int i = 0; i < 9; i++) {
                if (ring[(ring_pos + i) % 9] != enter_cfg[i])
                    { match = false; break; }
            }
            if (match) {
                const uint8_t ack[] = {
                    0xAA,0x55, 0x01,0x11, 0x01, 0x00,0x00, 0x4D,0x3C
                };
                uart_write_bytes(PAIRING_UART_PORT, ack, sizeof(ack));
                ESP_LOGI(TAG_PAIR, "ECHO ACK sent");
            }
        }

        int rc = fr_feed(&fr, b, &rx_type, &rx_seq,
                          rx_payload, &rx_payload_len);
        if (rc != 1) {
            if (rc == -1) {
                /* CRC 错误: 发错误帧 */
                if (pm != PM_IDLE) {
                    pairing_send_error(rx_seq, "CRC error");
                }
            }
            continue;
        }

        /* ---- 有效帧到达 ---- */
        ESP_LOGI(TAG_PAIR, "收到帧 type=0x%02X seq=%d len=%d",
                 rx_type, rx_seq, rx_payload_len);

        switch (rx_type) {

        case PAIR_TYPE_ENTER_CONFIG:   /* 0x10 */
            if (pm == PM_IDLE) {
                pm = PM_CONFIG_MODE;
                ESP_LOGI(TAG_PAIR, "进入配网模式");
            }
            pairing_send_frame(PAIR_TYPE_CONFIG_MODE_ACK, rx_seq);
            ESP_LOGI(TAG_PAIR, "→ 0x11 (ENTER_ACK)");
            break;

        case PAIR_TYPE_CONFIG_SET:     /* 0x20 */
            /* 不检查 pm 状态 — 崩溃重启后大禹可能直接发 0x20 */
            if (!pm) pm = PM_CONFIG_MODE;
            if (pairing_parse_config_json(rx_payload, rx_payload_len,
                                           &tmp_cfg)) {
                tmp_cfg_valid = true;
                pm = PM_CONFIG_RCVD;
                /* 先发 ACK，再打日志，连发3次确保大禹捕获 */
                {
                    uint8_t ack_buf[16];
                    int ack_len = pairing_build_frame(ack_buf, sizeof(ack_buf),
                                        PAIR_TYPE_CONFIG_ACK, rx_seq, NULL, 0);
                    if (ack_len > 0) {
                        /* 打印 0x21 hex 给大禹对照 */
                        {
                            char hx[32]; int off = 0;
                            for (int i = 0; i < ack_len && off < 30; i++)
                                off += snprintf(hx + off, sizeof(hx) - off, "%02X ", ack_buf[i]);
                            ESP_LOGI(TAG_PAIR, "TX 0x21 HEX: %s", hx);
                        }
                        /* 连发多次到 Type-C, 确认送达 */
                        for (int rep = 0; rep < 3; rep++) {
                            int wr = usb_serial_jtag_write_bytes(ack_buf, ack_len, pdMS_TO_TICKS(100));
                            if (wr <= 0)
                                ESP_LOGW(TAG_PAIR, "0x21 USB write ret=%d rep=%d", wr, rep);
                        }
                        /* 也发 UART0 */
                        uart_write_bytes(PAIRING_UART_PORT, ack_buf, ack_len);
                    }
                }
                /* 最后再打日志 */
                ESP_LOGI(TAG_PAIR, "→ 0x21 (CONFIG_ACK) seq=%d", rx_seq);
                ESP_LOGI(TAG_PAIR, "→ 0x21 (CONFIG_ACK)");
            } else {
                char err[80];
                snprintf(err, sizeof(err),
                         "JSON fail len=%d head=%.20s",
                         rx_payload_len,
                         rx_payload_len > 0 ? (const char *)rx_payload : "");
                pairing_send_error(rx_seq, err);
            }
            break;

        case PAIR_TYPE_CONFIG_SAVE:    /* 0x30 */
            if (tmp_cfg_valid) {
                if (pairing_save_nvs(&tmp_cfg)) {
                    /* 更新全局配置 */
                    memcpy(&g_pairing_config, &tmp_cfg, sizeof(tmp_cfg));
                    g_pairing_config.paired = true;
                    pm = PM_SAVED;
                    pairing_send_frame(PAIR_TYPE_CONFIG_SAVED, rx_seq);
                    ESP_LOGI(TAG_PAIR, "→ 0x31 (CONFIG_SAVED)");
                } else {
                    pairing_send_error(rx_seq, "NVS write failed");
                }
            } else {
                pairing_send_error(rx_seq, "No config to save");
            }
            break;

        case PAIR_TYPE_CONFIG_TEST:    /* 0x40 (预留) */
            pairing_send_json(PAIR_TYPE_CONFIG_TEST_RESULT, rx_seq,
                              "{\"ok\":false,\"msg\":\"not implemented\"}");
            break;

        case PAIR_TYPE_REBOOT:         /* 0x50 */
            ESP_LOGI(TAG_PAIR, "收到 REBOOT → 5 秒后重启");
            pairing_send_frame(PAIR_TYPE_CONFIG_SAVED, rx_seq);

            /* 如果有未保存的临时配置, 先存 */
            if (tmp_cfg_valid && pm < PM_SAVED) {
                pairing_save_nvs(&tmp_cfg);
            }

            /* 给大禹 5 秒接收 ACK, 然后重启 */
            vTaskDelay(pdMS_TO_TICKS(3000));
            ESP_LOGI(TAG_PAIR, "正在重启...");
            esp_restart();
            /* unreachable */
            break;

        default:
        {
            char err[64];
            snprintf(err, sizeof(err), "Unknown type 0x%02X pm=%d", rx_type, pm);
            ESP_LOGW(TAG_PAIR, "%s", err);
            pairing_send_error(rx_seq, err);
            break;
        }
        }
    }

    /* ---- 5. 退出配网窗口 ---- */
    /* 删除 UART 驱动, 让 dbg_uart_init() 重新安装 (如需要) */
    uart_driver_delete(PAIRING_UART_PORT);

    /* 确保使用正确的配置: NVS 加载的 或 默认值 */
    ESP_LOGI(TAG_PAIR, "配网完成, SSID=%s broker=%s",
             g_pairing_config.wifi_ssid, g_pairing_config.broker_url);
}
