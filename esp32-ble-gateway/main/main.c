/**
 * @file   main.c
 * @brief  ESP32-S3 USB Gateway — Stage 2: BLE Central for Dayu 210
 *
 * 帧协议: AA 55 | ver(0x01) | type | seq | len(2B BE) | payload(JSON) | CRC16(2B LE)
 *
 * USB 通道: ESP32-S3 USB Serial/JTAG (CDC-ACM Serial data)
 *   - Bulk OUT (0x01): 接收大禹请求
 *   - Bulk IN  (0x81): 返回网关 ACK / BLE 事件
 *
 * 命令/事件类型:
 *   - 0x60 → 0x61: USB 链路测试 (Stage 1)
 *   - 0x62 → 0x63: BLE 命令/事件 (Stage 2)
 *
 * BLE 角色: Central (NimBLE)
 *   - 扫描 → 发现 Peripheral → 自动连接 → GATT 读 device_hello → 上报大禹
 */

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "driver/uart.h"
#include "driver/usb_serial_jtag.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_timer.h"
#include "esp_system.h"
#include "sdkconfig.h"

/* NimBLE */
#include "host/ble_hs.h"
#include "host/ble_gap.h"
#include "host/ble_gatt.h"
#include "host/util/util.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "services/gap/ble_svc_gap.h"
#include "os/os_mbuf.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static const char *TAG = "GW";
#define GATEWAY_VERSION "v2.8-c08e1f7"

static QueueHandle_t g_evt_queue = NULL;  /* BLE 事件 → 主循环 发送队列 */
typedef struct { char *data; int len; } evt_item_t;
static SemaphoreHandle_t g_usb_tx_mutex = NULL;

/* ======================== 帧协议常量 ======================== */
#define FRAME_SYNC1         0xAA
#define FRAME_SYNC2         0x55
#define FRAME_VER           0x01
#define FRAME_MAX_PAYLOAD   1024

#define TYPE_GATEWAY_TEST        0x60  /* 大禹 → ESP32: USB 测试请求      */
#define TYPE_GATEWAY_ACK         0x61  /* ESP32 → 大禹: USB 测试 ACK      */
#define TYPE_GATEWAY_BLE_CMD     0x62  /* 大禹 → ESP32: BLE 命令          */
#define TYPE_GATEWAY_BLE_EVT     0x63  /* ESP32 → 大禹: BLE 事件          */

/* ======================== CRC16 MODBUS ======================== */
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
static int build_frame(uint8_t *buf, size_t buf_size,
                       uint8_t type, uint8_t seq,
                       const uint8_t *payload, uint16_t payload_len)
{
    size_t total = 9 + payload_len;
    if (total > buf_size) return -1;
    buf[0] = FRAME_SYNC1;
    buf[1] = FRAME_SYNC2;
    buf[2] = FRAME_VER;
    buf[3] = type;
    buf[4] = seq;
    buf[5] = (uint8_t)((payload_len >> 8) & 0xFF);
    buf[6] = (uint8_t)(payload_len & 0xFF);
    if (payload_len > 0 && payload != NULL)
        memcpy(buf + 7, payload, payload_len);
    uint16_t crc = crc16_modbus(buf + 2, 5 + payload_len);
    buf[7 + payload_len] = (uint8_t)(crc & 0xFF);
    buf[8 + payload_len] = (uint8_t)((crc >> 8) & 0xFF);
    return (int)total;
}

/* ======================== USB 帧发送 ======================== */
static void usb_send_frame_simple(uint8_t type, uint8_t seq,
                                  const uint8_t *payload, uint16_t payload_len)
{
    if (g_usb_tx_mutex && xSemaphoreTake(g_usb_tx_mutex, pdMS_TO_TICKS(5000)) != pdTRUE) {
        ESP_LOGE(TAG, "USB TX mutex timeout type=0x%02X seq=%d", type, seq);
        return;
    }
    uint8_t buf[FRAME_MAX_PAYLOAD + 16];
    int frame_len = build_frame(buf, sizeof(buf), type, seq, payload, payload_len);
    if (frame_len <= 0) {
        ESP_LOGE(TAG, "USB BUILD FAIL");
        if (g_usb_tx_mutex) xSemaphoreGive(g_usb_tx_mutex);
        return;
    }
    /* 分片写入: usb_serial_jtag_write_bytes 对大帧不稳定, 64B chunks */
    int total = 0;
    for (int off = 0; off < frame_len; ) {
        int chunk = frame_len - off;
        if (chunk > 64) chunk = 64;
        int wr = usb_serial_jtag_write_bytes(buf + off, chunk, pdMS_TO_TICKS(2000));
        if (wr <= 0) {
            ESP_LOGE(TAG, "USB TX FAIL type=0x%02X seq=%d len=%d at %d/%d: %d",
                     type, seq, frame_len, off, frame_len, wr);
            if (g_usb_tx_mutex) xSemaphoreGive(g_usb_tx_mutex);
            return;
        }
        off += wr; total += wr;
    }
    if (total != frame_len) {
        ESP_LOGE(TAG, "USB TX partial type=0x%02X seq=%d: %d/%d", type, seq, total, frame_len);
        if (g_usb_tx_mutex) xSemaphoreGive(g_usb_tx_mutex);
        return;
    }
    esp_err_t tx = usb_serial_jtag_wait_tx_done(pdMS_TO_TICKS(3000));
    if (tx != ESP_OK) ESP_LOGW(TAG, "USB FLUSH TIMEOUT type=0x%02X seq=%d", type, seq);
    ESP_LOGI(TAG, "USB TX OK type=0x%02X seq=%d len=%d", type, seq, frame_len);
    if (g_usb_tx_mutex) xSemaphoreGive(g_usb_tx_mutex);
    vTaskDelay(pdMS_TO_TICKS(100));  /* 帧间隔: 大禹需要时间解析每帧 */
}

static void usb_send_json(uint8_t type, uint8_t seq, const char *json)
{
    usb_send_frame_simple(type, seq, (const uint8_t *)json, (uint16_t)strlen(json));
}

/* ======================== 帧接收状态机 ======================== */
typedef enum { RX_SYNC1, RX_SYNC2, RX_HEADER, RX_PAYLOAD, RX_CRC } rx_state_t;
typedef struct {
    rx_state_t state; uint8_t header[5], header_pos; uint16_t expected_len;
    uint8_t pay_buf[FRAME_MAX_PAYLOAD]; uint16_t pay_pos;
    uint8_t crc_buf[2], crc_pos; uint8_t frame_ver, frame_type, frame_seq;
} frame_reader_t;

static void fr_reset(frame_reader_t *fr) { memset(fr, 0, sizeof(*fr)); fr->state = RX_SYNC1; }

static int fr_feed(frame_reader_t *fr, uint8_t b,
                   uint8_t *type_out, uint8_t *seq_out,
                   uint8_t *payload, uint16_t *payload_len)
{
    switch (fr->state) {
    case RX_SYNC1: if (b == FRAME_SYNC1) fr->state = RX_SYNC2; break;
    case RX_SYNC2:
        if (b == FRAME_SYNC2) { fr->state = RX_HEADER; fr->header_pos = 0; }
        else if (b != FRAME_SYNC1) { fr->state = RX_SYNC1; }
        break;
    case RX_HEADER:
        fr->header[fr->header_pos++] = b;
        if (fr->header_pos >= 5) {
            fr->frame_ver = fr->header[0]; fr->frame_type = fr->header[1];
            fr->frame_seq = fr->header[2];
            fr->expected_len = ((uint16_t)fr->header[3] << 8) | fr->header[4];
            if (fr->expected_len > FRAME_MAX_PAYLOAD) { fr_reset(fr); return 0; }
            fr->state = (fr->expected_len == 0) ? RX_CRC : RX_PAYLOAD;
            fr->pay_pos = 0; fr->crc_pos = 0;
        } break;
    case RX_PAYLOAD:
        fr->pay_buf[fr->pay_pos++] = b;
        if (fr->pay_pos >= fr->expected_len) { fr->state = RX_CRC; fr->crc_pos = 0; } break;
    case RX_CRC:
        fr->crc_buf[fr->crc_pos++] = b;
        if (fr->crc_pos >= 2) {
            uint8_t ci[FRAME_MAX_PAYLOAD + 5];
            ci[0] = fr->frame_ver; ci[1] = fr->frame_type; ci[2] = fr->frame_seq;
            ci[3] = fr->header[3]; ci[4] = fr->header[4];
            if (fr->expected_len > 0) memcpy(ci + 5, fr->pay_buf, fr->expected_len);
            uint16_t calc = crc16_modbus(ci, 5 + fr->expected_len);
            uint16_t rx = (uint16_t)fr->crc_buf[0] | ((uint16_t)fr->crc_buf[1] << 8);
            if (fr->expected_len > 0) memcpy(payload, fr->pay_buf, fr->expected_len);
            uint8_t st = fr->frame_type, sq = fr->frame_seq;
            uint16_t spl = fr->expected_len;
            fr_reset(fr);
            if (calc == rx) { *type_out = st; *seq_out = sq; *payload_len = spl; return 1; }
            ESP_LOGW(TAG, "CRC err: calc=0x%04X rx=0x%04X", calc, rx);
            return -1;
        } break;
    }
    return 0;
}

/* ======================== JSON 字段提取 ======================== */
static bool json_get_str(const char *json, const char *key, char *out, size_t out_size)
{
    char pattern[64]; int plen = snprintf(pattern, sizeof(pattern), "\"%s\":", key);
    const char *start = strstr(json, pattern); if (!start) return false;
    start += plen; while (*start == ' ' || *start == '\t') start++;
    if (*start != '"') return false;
    start++;
    const char *end = strchr(start, '"'); if (!end) return false;
    size_t len = (size_t)(end - start);
    if (len >= out_size) len = out_size - 1;
    memcpy(out, start, len); out[len] = '\0'; return true;
}

static bool json_get_bool(const char *json, const char *key, bool *out)
{
    char buf[16]; if (!json_get_str(json, key, buf, sizeof(buf))) return false;
    *out = (strcmp(buf, "true") == 0); return true;
}

static bool json_get_int(const char *json, const char *key, int *out)
{
    char pattern[64]; int plen = snprintf(pattern, sizeof(pattern), "\"%s\":", key);
    const char *start = strstr(json, pattern); if (!start) return false;
    start += plen; while (*start == ' ' || *start == '\t') start++;
    *out = (int)strtol(start, NULL, 10); return true;
}

/* ======================== 0x60 测试请求处理 ======================== */
static void handle_test_request(uint8_t seq, const uint8_t *payload, uint16_t payload_len)
{
    char json[FRAME_MAX_PAYLOAD + 1];
    size_t cl = payload_len < sizeof(json) - 1 ? payload_len : sizeof(json) - 1;
    memcpy(json, payload, cl); json[cl] = '\0';
    ESP_LOGI(TAG, "RX 0x60 seq=%d payload=%s", seq, json);

    char t[64] = {0}, m[128] = {0};
    if (!json_get_str(json, "type", t, sizeof(t)))
        { usb_send_json(TYPE_GATEWAY_ACK, seq, "{\"type\":\"gateway_test_ack\",\"ok\":false,\"message\":\"missing_type\",\"seq\":0}"); return; }
    if (strcmp(t, "gateway_test") != 0)
        { usb_send_json(TYPE_GATEWAY_ACK, seq, "{\"type\":\"gateway_test_ack\",\"ok\":false,\"message\":\"bad_type\",\"seq\":0}"); return; }
    if (!json_get_str(json, "message", m, sizeof(m)))
        { usb_send_json(TYPE_GATEWAY_ACK, seq, "{\"type\":\"gateway_test_ack\",\"ok\":false,\"message\":\"missing_message\",\"seq\":0}"); return; }
    if (strcmp(m, "dayu-usb-test") != 0)
        { usb_send_json(TYPE_GATEWAY_ACK, seq, "{\"type\":\"gateway_test_ack\",\"ok\":false,\"message\":\"bad_message\",\"seq\":0}"); return; }

    char ack[300];
    snprintf(ack, sizeof(ack), "{\"type\":\"gateway_test_ack\",\"ok\":true,\"message\":\"esp32-s3-gateway-ready\",\"seq\":%d,\"firmwareVersion\":\"%s\"}", seq, GATEWAY_VERSION);
    usb_send_json(TYPE_GATEWAY_ACK, seq, ack);
    ESP_LOGI(TAG, "0x61 ACK seq=%d OK", seq);
}

/* ================================================================== */
/*                         BLE Central                                 */
/* ================================================================== */

/* BLE GATT UUIDs (NimBLE 内部格式, MSB-first) */
/* Service:    7A6A0001-6B2D-4F01-9C6A-7E8B1A2C0001 */
/* device_hello: 7A6A0002-...  business_cmd: 7A6A0003-...  device_event: 7A6A0004-... */
/* BLE_UUID128_INIT 要求小端字节序 */
static const ble_uuid128_t GATT_SVC_UUID   = BLE_UUID128_INIT(0x01,0x00,0x2C,0x1A, 0x8B,0x7E,0x6A,0x9C, 0x01,0x4F,0x2D,0x6B, 0x01,0x00,0x6A,0x7A);
static const ble_uuid128_t CHAR_HELLO_UUID = BLE_UUID128_INIT(0x02,0x00,0x2C,0x1A, 0x8B,0x7E,0x6A,0x9C, 0x01,0x4F,0x2D,0x6B, 0x01,0x00,0x6A,0x7A);
static const ble_uuid128_t CHAR_CMD_UUID   __attribute__((unused)) = BLE_UUID128_INIT(0x03,0x00,0x2C,0x1A, 0x8B,0x7E,0x6A,0x9C, 0x01,0x4F,0x2D,0x6B, 0x01,0x00,0x6A,0x7A);
static const ble_uuid128_t CHAR_EVENT_UUID __attribute__((unused)) = BLE_UUID128_INIT(0x04,0x00,0x2C,0x1A, 0x8B,0x7E,0x6A,0x9C, 0x01,0x4F,0x2D,0x6B, 0x01,0x00,0x6A,0x7A);

/* Service UUID 的广播字节序 — NimBLE 把内部格式直接放入 AD, 不转换 */
/* 小端字节序 — 空中格式与 BLE_UUID128_INIT 一致 */
static const uint8_t SVC_UUID_WIRE[16] = {
    0x01, 0x00, 0x2C, 0x1A, 0x8B, 0x7E, 0x6A, 0x9C,
    0x01, 0x4F, 0x2D, 0x6B, 0x01, 0x00, 0x6A, 0x7A
};

/* 禹家设备列表 (仅广播了禹家 Service UUID 的设备) */
#define MAX_DEVICES 8
typedef struct {
    uint8_t  addr[6];   uint8_t  addr_type;
    char     name[32];  int8_t   rssi;
    uint16_t conn_handle;
    uint16_t business_cmd_handle;  /* 写入 business_cmd 用的 handle */
    bool     hello_read;
    bool     notify_ready;
    int      retry_count;     /* GATT 超时重试计数, 超过 3 次放弃 */
    int64_t  reconnect_at;    /* 断连后自动重连时间戳 (0=无需重连) */
    char     device_id[32]; char capabilities[128]; char room[16];
} device_entry_t;

static device_entry_t g_devices[MAX_DEVICES];
static int g_device_count = 0;
static int g_scan_seq = 0;
static bool g_scanning = false;
static bool g_auto_connect = false;
static uint8_t g_own_addr_type = 0;

/* 顺序连接状态机 */
static bool g_scan_done = false;       /* 扫描时间已到 */
static int  g_pending_idx = -1;        /* 正在处理第几个设备 (-1=无) */
static int  g_hello_done = 0;          /* 已完成 hello 读取的设备数 */
static bool g_busy = false;            /* BLE 操作进行中, 拒绝重叠命令 */
static int64_t g_busy_since = 0;       /* 开始忙的时间戳 (用于超时) */

/* ---- 广播数据中是否包含禹家 Service UUID ---- */
static bool has_our_service_uuid(const uint8_t *data, int len)
{
    for (int i = 0; i < len; ) {
        uint8_t fl = data[i];
        if (fl == 0 || i + fl >= len) break;
        uint8_t ft = data[i + 1];
        /* AD Type 0x06/0x07 = Incomplete/Complete List of 128-bit Service UUIDs */
        if ((ft == 0x06 || ft == 0x07) && fl >= 17) {
            for (int j = 2; j + 16 <= fl + 1; j += 16) {
                if (memcmp(data + i + j, SVC_UUID_WIRE, 16) == 0) return true;
            }
        }
        i += fl + 1;
    }
    return false;
}

static void try_connect_next(void);
static void nvs_save_devices(void);
static bool g_reconnect_mode = false;

static void schedule_device_reconnect(int idx, const char *reason)
{
    if (idx < 0 || idx >= g_device_count) return;
    device_entry_t *device = &g_devices[idx];
    device->conn_handle = 0xFFFF;
    device->business_cmd_handle = 0;
    device->hello_read = false;
    device->notify_ready = false;
    device->retry_count++;
    int delay_s = 2 + (device->retry_count - 1) * 2;
    if (delay_s > 10) delay_s = 10;
    device->reconnect_at = esp_timer_get_time() + (int64_t)delay_s * 1000000;
    ESP_LOGW(TAG, "Device[%d] reconnect scheduled in %ds attempt=%d reason=%s",
             idx, delay_s, device->retry_count, reason ? reason : "unknown");
}

/* BLE 事件发送 — 不阻塞 (在 NimBLE 回调上下文中, 不能长时间等待) */
static void ble_send_event_json(const char *json)
{
    uint8_t buf[FRAME_MAX_PAYLOAD + 16];
    int frame_len = build_frame(buf, sizeof(buf), TYPE_GATEWAY_BLE_EVT,
                                (uint8_t)g_scan_seq,
                                (const uint8_t *)json, (uint16_t)strlen(json));
    /* 队列项保存 data+len, 不依赖 strdup (Notify 数据可能不含 \0) */
    int jlen = (int)strlen(json);
    if (jlen <= 0) return;
    char *copy = malloc(jlen + 1);
    if (!copy) { ESP_LOGE(TAG, "BLE EVT OOM"); return; }
    memcpy(copy, json, jlen); copy[jlen] = '\0';
    evt_item_t item = { .data = copy, .len = jlen };
    if (xQueueSend(g_evt_queue, &item, pdMS_TO_TICKS(500)) != pdTRUE) {
        ESP_LOGW(TAG, "BLE EVT queue full, drop len=%d", jlen);
        free(copy);
    } else {
        /* 识别消息类型用于诊断 */
        char tbuf[32] = {0};
        if (strstr(json, "\"type\":\"ble_key_exchange\"")) snprintf(tbuf, sizeof(tbuf), "ble_key_exchange");
        else if (strstr(json, "\"type\":\"ble_secure\"")) snprintf(tbuf, sizeof(tbuf), "ble_secure");
        else if (strstr(json, "\"type\":\"ble_message\"")) snprintf(tbuf, sizeof(tbuf), "ble_message");
        else if (strstr(json, "\"type\":\"device_hello\"")) snprintf(tbuf, sizeof(tbuf), "device_hello");
        else if (strstr(json, "\"type\":\"ble_device\"")) snprintf(tbuf, sizeof(tbuf), "ble_device");
        else if (strstr(json, "\"type\":\"ble_device_state\"")) snprintf(tbuf, sizeof(tbuf), "ble_device_state");
        else snprintf(tbuf, sizeof(tbuf), "other");
        ESP_LOGI(TAG, "BLE EVT enqueued type=%s len=%d", tbuf[0] ? tbuf : "?", jlen);
    }
}

static void usb_event_tx_task(void *arg)
{
    evt_item_t item;
    while (1) {
        if (xQueueReceive(g_evt_queue, &item, portMAX_DELAY) == pdTRUE) {
            usb_send_json(TYPE_GATEWAY_BLE_EVT, (uint8_t)g_scan_seq, item.data);
            ESP_LOGI(TAG, "BLE EVT: %s", item.data);
            free(item.data);
        }
    }
}

/* 在设备列表中添加/查找 */
static int find_device_by_addr(const uint8_t *addr)
{
    for (int i = 0; i < g_device_count; i++)
        if (memcmp(g_devices[i].addr, addr, 6) == 0) return i;
    return -1;
}

static int add_device(const uint8_t *addr, uint8_t addr_type, const char *name, int8_t rssi)
{
    if (g_device_count >= MAX_DEVICES) return -1;
    int idx = find_device_by_addr(addr);
    if (idx >= 0) { g_devices[idx].rssi = rssi; return idx; }
    idx = g_device_count++;
    memcpy(g_devices[idx].addr, addr, 6);
    g_devices[idx].addr_type = addr_type;
    strncpy(g_devices[idx].name, name, sizeof(g_devices[idx].name) - 1);
    g_devices[idx].rssi = rssi;
    g_devices[idx].conn_handle = 0xFFFF;
    g_devices[idx].hello_read = false;
    g_devices[idx].notify_ready = false;
    g_devices[idx].device_id[0] = '\0';
    g_devices[idx].capabilities[0] = '\0';
    g_devices[idx].room[0] = '\0';
    return idx;
}

/* ---- GATT 读取回调 (级联) ---- */

struct hello_read_ctx {
    uint16_t conn_handle;
    uint16_t hello_handle;
    uint16_t event_handle;
    uint16_t cmd_handle;
    uint16_t service_start_handle;
    uint16_t service_end_handle;
    uint8_t addr[6];
    bool service_found;
};

struct subscribe_ctx { int idx; uint16_t conn_handle; };

static void report_device_ready(int idx)
{
    if (idx < 0 || idx >= g_device_count) return;
    char addr_str[18];
    snprintf(addr_str, sizeof(addr_str), "%02X:%02X:%02X:%02X:%02X:%02X",
             g_devices[idx].addr[5], g_devices[idx].addr[4], g_devices[idx].addr[3],
             g_devices[idx].addr[2], g_devices[idx].addr[1], g_devices[idx].addr[0]);

    char hello[600];
    snprintf(hello, sizeof(hello),
        "{\"type\":\"device_hello\",\"seq\":%d,\"deviceId\":\"%s\",\"name\":\"%s\","
        "\"room\":\"%s\",\"address\":\"%s\",\"rssi\":%d,\"connected\":true,"
        "\"capabilities\":%s,\"transport\":\"ble\",\"crypto\":\"sm4\",\"epoch\":0}",
        g_scan_seq, g_devices[idx].device_id, g_devices[idx].name, g_devices[idx].room,
        addr_str, g_devices[idx].rssi,
        g_devices[idx].capabilities[0] ? g_devices[idx].capabilities : "[]");
    ble_send_event_json(hello);

    char state[300];
    snprintf(state, sizeof(state),
        "{\"type\":\"ble_device_state\",\"seq\":%d,\"deviceId\":\"%s\","
        "\"address\":\"%s\",\"connected\":true}",
        g_scan_seq, g_devices[idx].device_id, addr_str);
    ble_send_event_json(state);

    char ready[320];
    snprintf(ready, sizeof(ready),
        "{\"type\":\"ble_ready\",\"seq\":%d,\"deviceId\":\"%s\","
        "\"address\":\"%s\",\"connected\":true,\"notifyReady\":true}",
        g_scan_seq, g_devices[idx].device_id, addr_str);
    ble_send_event_json(ready);
}

static void finish_device_setup(int idx, bool ready)
{
    if (idx >= 0 && idx < g_device_count) {
        g_devices[idx].notify_ready = ready;
        if (ready) {
            g_hello_done++;
            report_device_ready(idx);
            ESP_LOGI(TAG, "BLE ready: idx=%d device=%s", idx, g_devices[idx].device_id);
        } else {
            ESP_LOGW(TAG, "BLE notify setup failed: idx=%d", idx);
            g_devices[idx].business_cmd_handle = 0;
            g_devices[idx].hello_read = false;
            if (g_devices[idx].conn_handle != 0xFFFF) {
                ble_gap_terminate(g_devices[idx].conn_handle, BLE_ERR_REM_USER_CONN_TERM);
            }
        }
    }
    if (g_pending_idx >= 0) g_pending_idx++;
    try_connect_next();
}

static int ble_subscribe_cb(uint16_t conn_handle, const struct ble_gatt_error *error,
                            struct ble_gatt_attr *attr, void *arg)
{
    struct subscribe_ctx *ctx = (struct subscribe_ctx *)arg;
    bool ok = error && error->status == 0;
    int idx = ctx ? ctx->idx : -1;
    ESP_LOGI(TAG, "Subscribe complete: conn=%d idx=%d status=%d",
             conn_handle, idx, error ? error->status : -1);
    free(ctx);
    finish_device_setup(idx, ok);
    return 0;
}

static int ble_hello_read_cb(uint16_t conn_handle, const struct ble_gatt_error *error,
                             struct ble_gatt_attr *attr, void *arg)
{
    struct hello_read_ctx *ctx = (struct hello_read_ctx *)arg;
    int idx = find_device_by_addr(ctx->addr);
    if (error->status != 0 || attr == NULL) {
        ESP_LOGW(TAG, "GATT read err: conn=%d status=%d", conn_handle, error->status);
        free(ctx);
        finish_device_setup(idx, false);
        /* watchdog 兜底超时, 不在这里 disconnect */
        return 0;
    }

    /* mbuf 可能是链式结构 (大数据跨多个包), 必须用 ble_hs_mbuf_to_flat 展平 */
    uint16_t total_len = OS_MBUF_PKTLEN(attr->om);
    char json[512];
    uint16_t out_len = 0;
    int rc = ble_hs_mbuf_to_flat(attr->om, json, sizeof(json) - 1, &out_len);
    if (rc != 0 || out_len == 0) {
        ESP_LOGW(TAG, "mbuf_to_flat failed: rc=%d", rc);
        free(ctx);
        finish_device_setup(idx, false);
        return 0;
    }
    json[out_len] = '\0';
    ESP_LOGI(TAG, "device_hello read: conn=%d total=%u data=%s", conn_handle, total_len, json);

    /* 解析 device_hello JSON */
    char did[32] = {0}, nm[32] = {0}, caps[128] = {0}, rm[16] = {0};
    json_get_str(json, "deviceId", did, sizeof(did));
    json_get_str(json, "name", nm, sizeof(nm));
    json_get_str(json, "room", rm, sizeof(rm));

    /* capabilities 是数组 [\"...\",\"...\"], json_get_str 只能解析字符串,
     * 需要手动提取 [...] 之间的内容 */
    const char *ca = strstr(json, "\"capabilities\":");
    if (ca) {
        ca = strchr(ca, '[');
        const char *ce = ca ? strchr(ca, ']') : NULL;
        if (ca && ce && (size_t)(ce - ca) < sizeof(caps)) {
            size_t cl = (size_t)(ce - ca) + 1;
            memcpy(caps, ca, cl); caps[cl] = '\0';
        }
    }
    json_get_str(json, "room", rm, sizeof(rm));

    if (idx < 0 || did[0] == '\0') {
        ESP_LOGW(TAG, "device_hello missing stable deviceId");
        free(ctx);
        finish_device_setup(idx, false);
        return 0;
    }

    if (idx >= 0) {
        g_devices[idx].hello_read = true;
        g_devices[idx].notify_ready = false;
        g_devices[idx].business_cmd_handle = ctx->cmd_handle;
        snprintf(g_devices[idx].device_id, sizeof(g_devices[idx].device_id), "%s", did);
        snprintf(g_devices[idx].name, sizeof(g_devices[idx].name), "%s", nm[0] ? nm : "unknown");
        snprintf(g_devices[idx].room, sizeof(g_devices[idx].room), "%s", rm);
        snprintf(g_devices[idx].capabilities, sizeof(g_devices[idx].capabilities), "%s", caps);
        nvs_save_devices();  /* 首次读到 hello 时持久化到 NVS */
    }

    uint16_t event_handle = ctx->event_handle;
    free(ctx);

    /* Only report ready after the peripheral confirms the CCCD write. */
    if (event_handle != 0) {
        uint16_t cccd_handle = event_handle + 1;
        uint16_t cccd_val = 0x0001;
        struct subscribe_ctx *sub_ctx = calloc(1, sizeof(*sub_ctx));
        if (!sub_ctx) {
            finish_device_setup(idx, false);
            return 0;
        }
        sub_ctx->idx = idx;
        sub_ctx->conn_handle = conn_handle;
        int sub_rc = ble_gattc_write_flat(conn_handle, cccd_handle,
                                           &cccd_val, sizeof(cccd_val), ble_subscribe_cb, sub_ctx);
        if (sub_rc != 0) {
            ESP_LOGW(TAG, "Subscribe device_event failed: rc=%d", sub_rc);
            free(sub_ctx);
            finish_device_setup(idx, false);
        } else {
            ESP_LOGI(TAG, "Subscribe requested on conn=%d; waiting completion", conn_handle);
        }
    } else {
        finish_device_setup(idx, false);
    }

    return 0;
}

/* 特征发现回调 → 找到 device_hello, 发起 Read */
static int ble_chr_disc_cb(uint16_t conn_handle, const struct ble_gatt_error *error,
                           const struct ble_gatt_chr *chr, void *arg)
{
    struct hello_read_ctx *ctx = (struct hello_read_ctx *)arg;
    if (error->status == BLE_HS_EDONE) {
        if (ctx->hello_handle == 0 || ctx->event_handle == 0 || ctx->cmd_handle == 0) {
            int idx = find_device_by_addr(ctx->addr);
            ESP_LOGW(TAG, "GATT characteristics incomplete: hello=%d event=%d cmd=%d",
                     ctx->hello_handle, ctx->event_handle, ctx->cmd_handle);
            free(ctx);
            finish_device_setup(idx, false);
            return 0;
        }
        int rc = ble_gattc_read(conn_handle, ctx->hello_handle, ble_hello_read_cb, ctx);
        if (rc != 0) {
            int idx = find_device_by_addr(ctx->addr);
            ESP_LOGW(TAG, "device_hello read start failed: rc=%d", rc);
            free(ctx);
            finish_device_setup(idx, false);
        }
        return 0;
    }
    if (error->status != 0 || chr == NULL) {
        int idx = find_device_by_addr(ctx->addr);
        ESP_LOGW(TAG, "CHR DISC ERR: conn=%d status=%d", conn_handle, error->status);
        free(ctx);
        finish_device_setup(idx, false);
        return 0;
    }
    if (memcmp(&chr->uuid, &CHAR_HELLO_UUID, sizeof(ble_uuid128_t)) == 0) {
        ESP_LOGI(TAG, "Found device_hello char, handle=%d", chr->val_handle);
        ctx->hello_handle = chr->val_handle;
        return 0;
    }
    if (memcmp(&chr->uuid, &CHAR_EVENT_UUID, sizeof(ble_uuid128_t)) == 0) {
        ctx->event_handle = chr->val_handle;
        ESP_LOGI(TAG, "Found device_event char, handle=%d", chr->val_handle);
        return 0;
    }
    if (memcmp(&chr->uuid, &CHAR_CMD_UUID, sizeof(ble_uuid128_t)) == 0) {
        ctx->cmd_handle = chr->val_handle;
        ESP_LOGI(TAG, "Found business_cmd char, handle=%d", chr->val_handle);
        return 0;
    }
    return 0;
}

/* 服务发现回调 → 找到 Gateway Service, 发起特征发现 */
static int ble_svc_disc_cb(uint16_t conn_handle, const struct ble_gatt_error *error,
                           const struct ble_gatt_svc *svc, void *arg)
{
    struct hello_read_ctx *ctx = (struct hello_read_ctx *)arg;

    if (error->status == BLE_HS_EDONE) {
        if (ctx->service_found) {
            int rc = ble_gattc_disc_all_chrs(conn_handle,
                                             ctx->service_start_handle,
                                             ctx->service_end_handle,
                                             ble_chr_disc_cb, ctx);
            if (rc != 0) {
                int idx = find_device_by_addr(ctx->addr);
                ESP_LOGW(TAG, "Characteristic discovery start failed: rc=%d", rc);
                free(ctx);
                finish_device_setup(idx, false);
            }
        } else {
            int idx = find_device_by_addr(ctx->addr);
            ESP_LOGW(TAG, "Gateway Service not found: conn=%d", conn_handle);
            free(ctx);
            finish_device_setup(idx, false);
        }
        return 0;
    }
    if (error->status != 0 || svc == NULL) {
        int idx = find_device_by_addr(ctx->addr);
        ESP_LOGW(TAG, "SVC DISC ERR: conn=%d status=%d", conn_handle, error->status);
        free(ctx);
        finish_device_setup(idx, false);
        return 0;
    }
    /* 打印每个发现的 service UUID 前 8 字节用于诊断 */
    ESP_LOGI(TAG, "SVC DISC: conn=%d uuid_type=%d uuid_start=%02X%02X%02X%02X%02X%02X%02X%02X",
             conn_handle, ((const uint8_t*)&svc->uuid)[0],
             ((const uint8_t*)&svc->uuid)[1], ((const uint8_t*)&svc->uuid)[2],
             ((const uint8_t*)&svc->uuid)[3], ((const uint8_t*)&svc->uuid)[4],
             ((const uint8_t*)&svc->uuid)[5], ((const uint8_t*)&svc->uuid)[6],
             ((const uint8_t*)&svc->uuid)[7]);
    if (memcmp(&svc->uuid, &GATT_SVC_UUID, sizeof(ble_uuid128_t)) == 0) {
        ctx->service_found = true;
        ctx->service_start_handle = svc->start_handle;
        ctx->service_end_handle = svc->end_handle;
        ESP_LOGI(TAG, "Found Gateway Service, conn=%d start=%d end=%d",
                 conn_handle, svc->start_handle, svc->end_handle);
    }
    return 0;
}

static void start_service_discovery(struct hello_read_ctx *ctx)
{
    int idx = find_device_by_addr(ctx->addr);
    int rc = ble_gattc_disc_svc_by_uuid(ctx->conn_handle, &GATT_SVC_UUID.u,
                                        ble_svc_disc_cb, ctx);
    if (rc != 0) {
        ESP_LOGW(TAG, "Service discovery start failed: rc=%d idx=%d", rc, idx);
        free(ctx);
        finish_device_setup(idx, false);
    }
}

static int ble_mtu_cb(uint16_t conn_handle, const struct ble_gatt_error *error,
                      uint16_t mtu, void *arg)
{
    struct hello_read_ctx *ctx = (struct hello_read_ctx *)arg;
    ESP_LOGI(TAG, "MTU exchange complete: conn=%d mtu=%d status=%d",
             conn_handle, mtu, error ? error->status : -1);
    start_service_discovery(ctx);
    return 0;
}

/* ---- NimBLE GAP 事件回调 ---- */
static int ble_gap_event_cb(struct ble_gap_event *event, void *arg)
{
    switch (event->type) {

    case BLE_GAP_EVENT_DISC: {
        /* 发现设备 — 仅报告广播了禹家 Service UUID 的设备 */
        struct ble_gap_disc_desc *d = &event->disc;

        /* 诊断: 打印所有原始 AD 字段 */
        char addr_str[18];
        snprintf(addr_str, sizeof(addr_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                 d->addr.val[5], d->addr.val[4], d->addr.val[3],
                 d->addr.val[2], d->addr.val[1], d->addr.val[0]);

        const uint8_t *ad = d->data; int ad_len = d->length_data;
        for (int i = 0; i < ad_len; ) {
            uint8_t fl = ad[i]; if (fl == 0 || i + fl >= ad_len) break;
            uint8_t ft = ad[i + 1];
            /* 打印 AD type + hex dump */
            char hex[64] = {0}; int hpos = 0;
            for (int k = 0; k < fl - 1 && hpos < (int)sizeof(hex) - 3; k++)
                hpos += snprintf(hex + hpos, sizeof(hex) - hpos, "%02X", ad[i + 2 + k]);
            ESP_LOGI(TAG, "AD: addr=%s ADtype=0x%02X len=%d data=%s", addr_str, ft, fl - 1, hex);

            if ((ft == 0x06 || ft == 0x07) && fl >= 17) {
                /* 128-bit UUID — 打印匹配结果 */
                for (int j = 2; j + 16 <= fl + 1; j += 16) {
                    bool match = (memcmp(ad + i + j, SVC_UUID_WIRE, 16) == 0);
                    char uhex[40] = {0};
                    for (int k = 0; k < 16; k++) snprintf(uhex + k*2, 3, "%02X", ad[i + j + k]);
                    ESP_LOGI(TAG, "UUID128: %s match=%d", uhex, match);
                }
            }
            i += fl + 1;
        }

        bool matched = has_our_service_uuid(d->data, d->length_data);
        ESP_LOGI(TAG, "SCAN: %s rssi=%d uuid_match=%d", addr_str, d->rssi, matched);

        if (!matched) break;

        /* 提取设备名称 */
        char name[32] = {0};
        for (int i = 0; i < ad_len; ) {
            uint8_t fl = ad[i]; if (fl == 0 || i + fl >= ad_len) break;
            uint8_t ft = ad[i + 1];
            if ((ft == 0x09 || ft == 0x08) && fl >= 2) {
                int nl = fl - 1; if (nl > 31) nl = 31;
                memcpy(name, ad + i + 2, nl); name[nl] = '\0'; break;
            }
            i += fl + 1;
        }

        /* 去重添加 */
        int idx = find_device_by_addr(d->addr.val);
        if (idx < 0) idx = add_device(d->addr.val, d->addr.type, name, d->rssi);
        else { g_devices[idx].rssi = d->rssi; break; } /* 已上报过, 跳过 */

        ESP_LOGI(TAG, "MATCH: %s rssi=%d name=%s", addr_str, d->rssi, name);

        /* 上报 ble_device (仅禹家设备) */
        char evt[400];
        snprintf(evt, sizeof(evt),
            "{\"type\":\"ble_device\",\"seq\":%d,\"deviceId\":\"%s\",\"name\":\"%s\","
            "\"address\":\"%s\",\"rssi\":%d,\"connected\":false,\"capabilities\":[]}",
            g_scan_seq, addr_str, name[0] ? name : "unknown", addr_str, d->rssi);
        ble_send_event_json(evt);
        break;
    }

    case BLE_GAP_EVENT_DISC_COMPLETE: {
        ESP_LOGI(TAG, "Scan done: found=%d ours", g_device_count);
        g_scanning = false;
        g_scan_done = true;

        /* 扫描完立刻保存设备地址到 NVS (不等 hello 读完, WiFi 抢射频时 GATT 可能超时) */
        nvs_save_devices();

        if (!g_auto_connect || g_device_count == 0) {
            /* 无自动连接 或 没找到设备 → 直接结束 */
            char evt[200];
            snprintf(evt, sizeof(evt),
                "{\"type\":\"ble_scan_finished\",\"seq\":%d,\"ok\":true,\"count\":%d,\"reason\":\"completed\"}",
                g_scan_seq, g_device_count);
            ble_send_event_json(evt);
            g_busy = false;
            break;
        }

        /* 开始顺序连接 */
        g_hello_done = 0;
        g_pending_idx = 0;
        try_connect_next();
        break;
    }

    case BLE_GAP_EVENT_CONNECT: {
        if (event->connect.status != 0) {
            ESP_LOGW(TAG, "Connect failed: status=%d idx=%d",
                     event->connect.status, g_pending_idx);
            if (g_pending_idx >= 0) {
                schedule_device_reconnect(g_pending_idx, "gap_connect_failed");
                g_pending_idx++;
            }
            try_connect_next();
            break;
        }

        uint16_t ch = event->connect.conn_handle;
        struct ble_gap_conn_desc desc;
        if (ble_gap_conn_find(ch, &desc) != 0) break;

        /* 在设备列表中标记连接 */
        for (int i = 0; i < g_device_count; i++) {
            if (memcmp(g_devices[i].addr, desc.peer_ota_addr.val, 6) == 0) {
                g_devices[i].conn_handle = ch;
                g_devices[i].notify_ready = false;
                g_devices[i].retry_count = 0;
                g_devices[i].reconnect_at = 0;
                ESP_LOGI(TAG, "Connected: idx=%d name=%s handle=%d", i,
                         g_devices[i].name, ch);

                struct hello_read_ctx *ctx = calloc(1, sizeof(*ctx));
                if (ctx) {
                    ctx->conn_handle = ch;
                    memcpy(ctx->addr, g_devices[i].addr, 6);
                    int mtu_rc = ble_gattc_exchange_mtu(ch, ble_mtu_cb, ctx);
                    if (mtu_rc != 0) {
                        ESP_LOGW(TAG, "MTU exchange start failed: rc=%d; continuing discovery", mtu_rc);
                        start_service_discovery(ctx);
                    }
                } else {
                    finish_device_setup(i, false);
                }
                break;
            }
        }
        break;
    }

    case BLE_GAP_EVENT_NOTIFY_RX: {
        uint16_t ntfy_handle = event->notify_rx.attr_handle;
        struct os_mbuf *om = event->notify_rx.om;
        if (om) {
            uint16_t total_len = OS_MBUF_PKTLEN(om);
            uint8_t *raw = malloc(total_len + 1);
            if (raw) {
                uint16_t copied = 0;
                ble_hs_mbuf_to_flat(om, raw, total_len, &copied);
                static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                char b64_out[1024]; int bp = 0;
                for (int i = 0; i < (int)copied; i += 3) {
                    uint32_t v = (uint32_t)raw[i] << 16;
                    if (i + 1 < (int)copied) v |= (uint32_t)raw[i + 1] << 8;
                    if (i + 2 < (int)copied) v |= (uint32_t)raw[i + 2];
                    if (bp + 4 >= (int)sizeof(b64_out)) break;
                    b64_out[bp++] = b64[(v >> 18) & 0x3F];
                    b64_out[bp++] = b64[(v >> 12) & 0x3F];
                    b64_out[bp++] = (i + 1 < (int)copied) ? b64[(v >> 6) & 0x3F] : '=';
                    b64_out[bp++] = (i + 2 < (int)copied) ? b64[v & 0x3F] : '=';
                }
                b64_out[bp] = '\0';
                char did_str[32] = {0};
                for (int i = 0; i < g_device_count; i++) {
                    if (g_devices[i].conn_handle == event->notify_rx.conn_handle) {
                        snprintf(did_str, sizeof(did_str), "%s", g_devices[i].device_id);
                        break;
                    }
                }
                char evt[1280];
                snprintf(evt, sizeof(evt),
                    "{\"type\":\"ble_message\",\"seq\":%d,\"deviceId\":\"%s\","
                    "\"topic\":\"device/%s/status\",\"crypto\":\"none\","
                    "\"bytes\":%d,\"payloadBase64\":\"%s\"}",
                    g_scan_seq, did_str, did_str, (int)copied, b64_out);
                ESP_LOGI(TAG, "Notify hndl=%d total=%d copied=%d b64_len=%d evt_len=%d",
                         ntfy_handle, (int)total_len, (int)copied, bp, (int)strlen(evt));
                ble_send_event_json(evt);
                free(raw);
            }
        }
        return 0;
    }

    case BLE_GAP_EVENT_DISCONNECT: {
        ESP_LOGI(TAG, "Disconnected: handle=%d reason=%d",
                 event->disconnect.conn.conn_handle, event->disconnect.reason);
        for (int i = 0; i < g_device_count; i++) {
            if (g_devices[i].conn_handle == event->disconnect.conn.conn_handle) {
                g_devices[i].conn_handle = 0xFFFF;
                g_devices[i].business_cmd_handle = 0;
                g_devices[i].hello_read = false;
                g_devices[i].notify_ready = false;
                /* 上报离线 + 标记自动重连 */
                char addr_str[18];
                snprintf(addr_str, sizeof(addr_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                         g_devices[i].addr[5], g_devices[i].addr[4], g_devices[i].addr[3],
                         g_devices[i].addr[2], g_devices[i].addr[1], g_devices[i].addr[0]);
                char st[200];
                snprintf(st, sizeof(st),
                    "{\"type\":\"ble_device_state\",\"seq\":%d,\"deviceId\":\"%s\","
                    "\"address\":\"%s\",\"connected\":false}",
                    g_scan_seq, g_devices[i].device_id[0] ? g_devices[i].device_id : addr_str, addr_str);
                ble_send_event_json(st);
                schedule_device_reconnect(i, "disconnected");
                break;
            }
        }
        break;
    }

    default: break;
    }
    return 0;
}

/* ---- 顺序连接: 从 g_pending_idx 开始连接下一个设备 ---- */
static int count_ready_devices(void)
{
    int count = 0;
    for (int i = 0; i < g_device_count; i++) {
        if (!g_devices[i].notify_ready || g_devices[i].business_cmd_handle == 0 ||
            g_devices[i].conn_handle == 0xFFFF) {
            continue;
        }
        struct ble_gap_conn_desc desc;
        if (ble_gap_conn_find(g_devices[i].conn_handle, &desc) == 0) count++;
    }
    return count;
}

static void try_connect_next(void)
{
    while (g_pending_idx >= 0 && g_pending_idx < g_device_count) {
        int i = g_pending_idx;
        /* 已连接 → 跳过。仅在断开(conn_handle=0xFFFF)时重新连接 */
        if (g_devices[i].conn_handle != 0xFFFF) {
            /* 连接还在, 确认是否真的有效 */
            struct ble_gap_conn_desc desc;
            if (ble_gap_conn_find(g_devices[i].conn_handle, &desc) == 0) {
                if (!g_devices[i].notify_ready || g_devices[i].business_cmd_handle == 0) {
                    struct hello_read_ctx *ctx = calloc(1, sizeof(*ctx));
                    if (!ctx) {
                        ESP_LOGE(TAG, "GATT setup context allocation failed: idx=%d", i);
                        g_pending_idx++;
                        continue;
                    }
                    ctx->conn_handle = g_devices[i].conn_handle;
                    memcpy(ctx->addr, g_devices[i].addr, 6);
                    ESP_LOGI(TAG, "Refreshing GATT setup for connected device idx=%d", i);
                    int rc = ble_gattc_disc_svc_by_uuid(g_devices[i].conn_handle,
                                                        &GATT_SVC_UUID.u,
                                                        ble_svc_disc_cb, ctx);
                    if (rc == 0) return;
                    ESP_LOGW(TAG, "GATT setup refresh failed: rc=%d idx=%d", rc, i);
                    free(ctx);
                    g_pending_idx++;
                    continue;
                }
                g_hello_done++;
                report_device_ready(i);
                g_pending_idx++;
                continue;
            }
            /* 连接已失效 */
            g_devices[i].conn_handle = 0xFFFF;
        }
        /* conn_handle == 0xFFFF → 需要连接 */

        ble_addr_t addr; memcpy(addr.val, g_devices[i].addr, 6);
        addr.type = g_devices[i].addr_type;
        ESP_LOGI(TAG, "Connecting to idx=%d name=%s...", i, g_devices[i].name);
        int rc = ble_gap_connect(g_own_addr_type, &addr, 5000, NULL,
                                 ble_gap_event_cb, NULL);
        if (rc == 0) return;  /* 异步等待 connect 结果 */
        ESP_LOGW(TAG, "ble_gap_connect failed: rc=%d idx=%d", rc, i);
        schedule_device_reconnect(i, "connect_start_failed");
        g_pending_idx++;
    }

    /* 所有设备处理完毕 → 发完成事件 */
    if (g_scan_done || g_reconnect_mode) {
        int ready_count = count_ready_devices();
        bool reconnect_completion = g_reconnect_mode;
        if (reconnect_completion) {
            char evt[200];
            snprintf(evt, sizeof(evt),
                "{\"type\":\"ble_reconnect_finished\",\"seq\":%d,\"ok\":true,\"count\":%d,\"reason\":\"completed\"}",
                g_scan_seq, ready_count);
            ble_send_event_json(evt);
            g_reconnect_mode = false;
        } else {
            char evt[200];
            snprintf(evt, sizeof(evt),
                "{\"type\":\"ble_scan_finished\",\"seq\":%d,\"ok\":true,\"count\":%d,\"reason\":\"completed\"}",
                g_scan_seq, ready_count);
            ble_send_event_json(evt);
        }
        ESP_LOGI(TAG, "All done: %d/%d devices ready (%s)", ready_count, g_device_count,
                 reconnect_completion ? "reconnect" : "scan");
        g_pending_idx = -1;
        g_busy = false;
    }
}

/* ---- NimBLE 同步回调 (host 就绪后调用) ---- */
static void ble_on_sync(void)
{
    ESP_LOGI(TAG, "BLE host synced, ready");
    /* 使用自动推断的地址类型 (ESP32-S3 的烧录 MAC) */
    int rc = ble_hs_id_infer_auto(0, &g_own_addr_type);
    if (rc == 0) {
        ESP_LOGI(TAG, "BLE addr type: %d", g_own_addr_type);
    } else {
        ESP_LOGE(TAG, "ble_hs_id_infer_auto failed: %d", rc);
        g_own_addr_type = BLE_OWN_ADDR_PUBLIC;
    }
}

/* ---- NimBLE Host Task ---- */
static void ble_host_task(void *param)
{
    ESP_LOGI(TAG, "BLE host task started");
    nimble_port_run();
}

/* ---- BLE Central 初始化 ---- */
static void ble_central_init(void)
{
    /* 初始化 NimBLE */
    nimble_port_init();

    /* 配置 host */
    ble_hs_cfg.reset_cb = NULL;
    ble_hs_cfg.sync_cb = ble_on_sync;
    ble_hs_cfg.store_status_cb = ble_store_util_status_rr;

    /* MTU 交换: 默认 23B, device_hello JSON ~170B, 必须提高 */
    ble_att_set_preferred_mtu(256);

    /* 启动 NimBLE host task (FreeRTOS) */
    nimble_port_freertos_init(ble_host_task);

    ESP_LOGI(TAG, "BLE Central: NimBLE initialized");
}

/* ---- BLE 扫描 ---- */
static void ble_scan_start(int duration_ms, int max_devices, bool auto_connect)
{
    if (g_scanning) {
        ESP_LOGW(TAG, "Already scanning");
        return;
    }
    ESP_LOGI(TAG, "BLE scan: duration=%dms max=%d auto=%d",
             duration_ms, max_devices, auto_connect);

    /* 跨扫描累积设备: 保留已有连接, 重置扫描相关状态 */
    for (int i = 0; i < g_device_count; i++) {
        g_devices[i].retry_count = 0;
    }
    g_hello_done = 0;
    g_pending_idx = -1;
    g_scan_done = false;

    /* 设备重报已在 handle_ble_command 中用 usb_send_json 完成, 这里不重复 */

    g_scanning = true;
    g_auto_connect = auto_connect;
    g_reconnect_mode = false;

    struct ble_gap_disc_params params = {
        .itvl = BLE_GAP_SCAN_FAST_INTERVAL_MIN,
        .window = BLE_GAP_SCAN_FAST_WINDOW,
        .filter_policy = 0,
        .limited = 0,
        .passive = 0,    /* active scan */
        .filter_duplicates = 1,
    };

    int rc = ble_gap_disc(g_own_addr_type, duration_ms, &params,
                          ble_gap_event_cb, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gap_disc failed: %d", rc);
        g_scanning = false;
    }
}

/* ======================== NVS 设备持久化 ======================== */
#define NVS_NAMESPACE  "ble_gw"
#define NVS_KEY_COUNT  "dev_cnt"

static void nvs_save_devices(void)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) != ESP_OK) return;
    nvs_set_u8(h, NVS_KEY_COUNT, (uint8_t)g_device_count);
    for (int i = 0; i < g_device_count; i++) {
        char k[16];
        snprintf(k, sizeof(k), "a%d", i); nvs_set_blob(h, k, g_devices[i].addr, 6);
        snprintf(k, sizeof(k), "t%d", i); nvs_set_u8(h, k, g_devices[i].addr_type);
        snprintf(k, sizeof(k), "i%d", i); nvs_set_str(h, k, g_devices[i].device_id);
        snprintf(k, sizeof(k), "n%d", i); nvs_set_str(h, k, g_devices[i].name);
        snprintf(k, sizeof(k), "c%d", i); nvs_set_str(h, k, g_devices[i].capabilities);
        snprintf(k, sizeof(k), "r%d", i); nvs_set_str(h, k, g_devices[i].room);
    }
    nvs_commit(h); nvs_close(h);
    ESP_LOGI(TAG, "NVS: saved %d devices", g_device_count);
}

static int nvs_load_devices(void)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &h) != ESP_OK) { ESP_LOGI(TAG, "NVS: no saved devices"); return 0; }
    uint8_t cnt = 0; nvs_get_u8(h, NVS_KEY_COUNT, &cnt);
    if (cnt > MAX_DEVICES) cnt = MAX_DEVICES;
    g_device_count = 0;
    for (int i = 0; i < cnt; i++) {
        size_t len; char k[16];
        memset(&g_devices[i], 0, sizeof(g_devices[i]));
        g_devices[i].conn_handle = 0xFFFF;
        snprintf(k, sizeof(k), "a%d", i); len = 6; nvs_get_blob(h, k, g_devices[i].addr, &len);
        snprintf(k, sizeof(k), "t%d", i); nvs_get_u8(h, k, &g_devices[i].addr_type);
        snprintf(k, sizeof(k), "i%d", i); len = sizeof(g_devices[i].device_id); nvs_get_str(h, k, g_devices[i].device_id, &len);
        snprintf(k, sizeof(k), "n%d", i); len = sizeof(g_devices[i].name); nvs_get_str(h, k, g_devices[i].name, &len);
        snprintf(k, sizeof(k), "c%d", i); len = sizeof(g_devices[i].capabilities); nvs_get_str(h, k, g_devices[i].capabilities, &len);
        snprintf(k, sizeof(k), "r%d", i); len = sizeof(g_devices[i].room); nvs_get_str(h, k, g_devices[i].room, &len);
        g_device_count++;
    }
    nvs_close(h);
    ESP_LOGI(TAG, "NVS: loaded %d devices", g_device_count);
    return g_device_count;
}

/* cmd=connect-known: 幂等同步命令 — 已连设备重报缓存, 未连设备连接订阅 */
static void handle_connect_known(uint8_t seq);
static void handle_connect_known(uint8_t seq)
{
    ESP_LOGI(TAG, "connect-known seq=%d: busy=%d devs=%d", seq, g_busy, g_device_count);

    if (g_busy) {
        ESP_LOGW(TAG, "connect-known: BUSY, reject seq=%d", seq);
        char evt[150];
        snprintf(evt, sizeof(evt), "{\"type\":\"ble_reconnect_finished\",\"seq\":%d,\"ok\":false,\"count\":0,\"reason\":\"busy\"}", seq);
        ble_send_event_json(evt);
        return;
    }

    g_scan_seq = seq;
    g_reconnect_mode = true;

    /* NVS only stores identity. Preserve live GATT state and restore it by MAC. */
    static device_entry_t saved_devices[MAX_DEVICES];
    int saved_count = g_device_count;
    memcpy(saved_devices, g_devices, sizeof(saved_devices));

    int loaded = nvs_load_devices();

    for (int i = 0; i < loaded; i++) {
        for (int j = 0; j < saved_count; j++) {
            if (memcmp(saved_devices[j].addr, g_devices[i].addr, 6) == 0 &&
                saved_devices[j].conn_handle != 0xFFFF) {
                struct ble_gap_conn_desc desc;
                if (ble_gap_conn_find(saved_devices[j].conn_handle, &desc) == 0 &&
                    memcmp(desc.peer_ota_addr.val, g_devices[i].addr, 6) == 0) {
                    g_devices[i].conn_handle = saved_devices[j].conn_handle;
                    g_devices[i].business_cmd_handle = saved_devices[j].business_cmd_handle;
                    g_devices[i].hello_read = saved_devices[j].hello_read;
                    g_devices[i].notify_ready = saved_devices[j].notify_ready;
                }
                break;
            }
        }
    }

    if (loaded == 0) {
        char evt[128];
        snprintf(evt, sizeof(evt), "{\"type\":\"ble_reconnect_finished\",\"seq\":%d,\"ok\":true,\"count\":0,\"reason\":\"no_devices\"}", seq);
        usb_send_json(TYPE_GATEWAY_BLE_EVT, seq, evt);
        ESP_LOGI(TAG, "connect-known → no_devices");
        g_reconnect_mode = false;
        return;
    }

    /* 统计已连接设备数 */
    int alive_count = 0;
    for (int i = 0; i < g_device_count; i++) {
        if (g_devices[i].conn_handle != 0xFFFF) {
            struct ble_gap_conn_desc desc;
            if (ble_gap_conn_find(g_devices[i].conn_handle, &desc) == 0 &&
                g_devices[i].notify_ready && g_devices[i].business_cmd_handle != 0) {
                alive_count++;
            } else if (ble_gap_conn_find(g_devices[i].conn_handle, &desc) != 0) {
                g_devices[i].conn_handle = 0xFFFF;
                g_devices[i].business_cmd_handle = 0;
                g_devices[i].notify_ready = false;
            }
        }
    }

    ESP_LOGI(TAG, "connect-known: %d loaded, %d alive, %d cached",
             loaded, alive_count,
             (g_device_count > 0 && g_devices[0].device_id[0]) ? 1 : 0);

    /* 重报所有已知设备 (已连设备报 connected=true) */
    for (int i = 0; i < g_device_count; i++) {
        char addr_str[18];
        snprintf(addr_str, sizeof(addr_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                 g_devices[i].addr[5], g_devices[i].addr[4], g_devices[i].addr[3],
                 g_devices[i].addr[2], g_devices[i].addr[1], g_devices[i].addr[0]);

        bool alive = (g_devices[i].conn_handle != 0xFFFF &&
                      g_devices[i].notify_ready &&
                      g_devices[i].business_cmd_handle != 0);
        bool has_id = (g_devices[i].device_id[0] != '\0');

        char evt[500];
        snprintf(evt, sizeof(evt),
            "{\"type\":\"ble_device\",\"seq\":%d,\"deviceId\":\"%s\",\"name\":\"%s\","
            "\"address\":\"%s\",\"rssi\":%d,\"connected\":%s,\"capabilities\":%s}",
            seq, has_id ? g_devices[i].device_id : addr_str,
            has_id ? g_devices[i].name : (g_devices[i].name[0] ? g_devices[i].name : "unknown"),
            addr_str, g_devices[i].rssi,
            alive ? "true" : "false",
            g_devices[i].capabilities[0] ? g_devices[i].capabilities : "[]");
        ble_send_event_json(evt);

        /* NVS 缓存重报: device_hello 只说明已知设备, connected 必须反映实际 GATT 状态 */
        if (has_id) {
            char hello[600];
            snprintf(hello, sizeof(hello),
                "{\"type\":\"device_hello\",\"seq\":%d,\"deviceId\":\"%s\",\"name\":\"%s\",\"room\":\"%s\","
                "\"address\":\"%s\",\"rssi\":%d,\"connected\":%s,"
                "\"capabilities\":%s,\"transport\":\"ble\",\"crypto\":\"sm4\",\"epoch\":0}",
                seq, g_devices[i].device_id, g_devices[i].name,
                g_devices[i].room, addr_str, g_devices[i].rssi,
                alive ? "true" : "false",
                g_devices[i].capabilities[0] ? g_devices[i].capabilities : "[]");
            ble_send_event_json(hello);

            char st[300];
            snprintf(st, sizeof(st),
                "{\"type\":\"ble_device_state\",\"seq\":%d,\"deviceId\":\"%s\","
                "\"address\":\"%s\",\"connected\":%s}",
                seq, g_devices[i].device_id, addr_str, alive ? "true" : "false");
            ble_send_event_json(st);
            if (alive) {
                char ready[320];
                snprintf(ready, sizeof(ready),
                    "{\"type\":\"ble_ready\",\"seq\":%d,\"deviceId\":\"%s\","
                    "\"address\":\"%s\",\"connected\":true,\"notifyReady\":true}",
                    seq, g_devices[i].device_id, addr_str);
                ble_send_event_json(ready);
            }
        }
    }

    /* 所有设备已在线 → 直接完成, 不设 busy */
    if (alive_count == g_device_count) {
        char evt[128];
        snprintf(evt, sizeof(evt), "{\"type\":\"ble_reconnect_finished\",\"seq\":%d,\"ok\":true,\"count\":%d,\"reason\":\"all_alive\"}", seq, alive_count);
        ble_send_event_json(evt);
        ESP_LOGI(TAG, "connect-known → all_alive (%d)", alive_count);
        g_reconnect_mode = false;
        return;
    }

    /* 有设备离线 → 连接 + 订阅, 设 busy */
    g_busy = true;
    g_busy_since = esp_timer_get_time();
    g_hello_done = 0;
    g_pending_idx = 0;
    try_connect_next();
}

/* base64 解码, 返回 malloc 的 buffer, 长度写入 *out_len */
static uint8_t *b64_decode(const char *in, int *out_len)
{
    static const signed char d[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
    };
    int ilen = (int)strlen(in);
    while (ilen > 0 && in[ilen - 1] == '=') ilen--;
    int olen = (ilen * 3) / 4;
    uint8_t *out = malloc(olen + 1);
    if (!out) { *out_len = 0; return NULL; }
    int ip = 0, op = 0;
    while (ip < ilen) {
        int v = 0, b = 0;
        for (int i = 0; i < 4 && ip < ilen; i++, ip++) {
            int c = d[(uint8_t)in[ip]];
            if (c < 0) { free(out); *out_len = 0; return NULL; }
            v = (v << 6) | c; b++;
        }
        /* 补齐到 24 位: b=3→18→24, b=2→12→24 (修复最后一组移位 bug) */
        if (b < 4) v <<= (4 - b) * 6;
        if (b >= 2) { out[op++] = (v >> 16) & 0xFF; v <<= 8; b--; }
        if (b >= 2) { out[op++] = (v >> 16) & 0xFF; v <<= 8; b--; }
        if (b >= 2) { out[op++] = (v >> 16) & 0xFF; v <<= 8; b--; }
    }
    *out_len = op; return out;
}

/* 网关重启状态 */
static int64_t g_reboot_time = 0;
static int g_reboot_seq = 0;

/* ======================== 0x62 BLE 命令处理 ======================== */
static void handle_ble_command(uint8_t seq, const uint8_t *payload, uint16_t payload_len)
{
    char json[FRAME_MAX_PAYLOAD + 1];
    size_t cl = payload_len < sizeof(json) - 1 ? payload_len : sizeof(json) - 1;
    memcpy(json, payload, cl); json[cl] = '\0';
    ESP_LOGI(TAG, "RX 0x62 seq=%d payload=%s", seq, json);

    char type_buf[64] = {0}, cmd_buf[16] = {0}, action_buf[32] = {0};

    if (!json_get_str(json, "type", type_buf, sizeof(type_buf))) {
        ESP_LOGW(TAG, "0x62: missing type"); return;
    }
    if (strcmp(type_buf, "gateway_ble_command") != 0) {
        ESP_LOGW(TAG, "0x62: bad type '%s'", type_buf); return;
    }
    if (!json_get_str(json, "cmd", cmd_buf, sizeof(cmd_buf))) {
        ESP_LOGW(TAG, "0x62: missing cmd"); return;
    }
    if (strcmp(cmd_buf, "ble") != 0) {
        ESP_LOGW(TAG, "0x62: bad cmd '%s'", cmd_buf); return;
    }
    if (!json_get_str(json, "action", action_buf, sizeof(action_buf))) {
        ESP_LOGW(TAG, "0x62: missing action"); return;
    }

    /* 诊断: 打印 action 完整内容 */
    ESP_LOGI(TAG, "0x62 action='%s' len=%d hex=%02X%02X%02X%02X... g_busy=%d",
             action_buf, (int)strlen(action_buf),
             (uint8_t)action_buf[0], (uint8_t)action_buf[1],
             (uint8_t)action_buf[2], (uint8_t)action_buf[3], g_busy);

    if (strcmp(action_buf, "scan-start") == 0) {
        ESP_LOGI(TAG, "scan-start seq=%d: busy=%d devs=%d", seq, g_busy, g_device_count);
        if (g_busy) {
            ESP_LOGW(TAG, "scan-start: BUSY, reject seq=%d", seq);
            char evt[150];
            snprintf(evt, sizeof(evt), "{\"type\":\"ble_scan_finished\",\"seq\":%d,\"ok\":false,\"count\":0,\"reason\":\"busy\"}", seq);
            ble_send_event_json(evt);
            return;
        }

        g_scan_seq = (int)seq;
        g_busy = true;
        g_busy_since = esp_timer_get_time();

        int duration_ms = 12000, max_devices = 8;
        bool auto_connect = true;
        json_get_int(json, "durationMs", &duration_ms);
        json_get_int(json, "maxDevices", &max_devices);
        json_get_bool(json, "autoConnect", &auto_connect);

        /* 回复 ble_scan_started */
        char ack[200];
        snprintf(ack, sizeof(ack),
            "{\"type\":\"ble_scan_started\",\"seq\":%d,\"ok\":true}", g_scan_seq);
        usb_send_json(TYPE_GATEWAY_BLE_EVT, (uint8_t)seq, ack);
        ESP_LOGI(TAG, "→ ble_scan_started seq=%d", g_scan_seq);

        /* 重报已缓存设备信息 (优先用 NVS 缓存, 不依赖 alive) */
        for (int i = 0; i < g_device_count; i++) {
            char addr_str[18];
            snprintf(addr_str, sizeof(addr_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                     g_devices[i].addr[5], g_devices[i].addr[4], g_devices[i].addr[3],
                     g_devices[i].addr[2], g_devices[i].addr[1], g_devices[i].addr[0]);
            bool cached = (g_devices[i].device_id[0] != '\0');
            bool ready = false;
            if (g_devices[i].conn_handle != 0xFFFF &&
                g_devices[i].notify_ready &&
                g_devices[i].business_cmd_handle != 0) {
                struct ble_gap_conn_desc desc;
                ready = ble_gap_conn_find(g_devices[i].conn_handle, &desc) == 0;
                if (!ready) {
                    g_devices[i].conn_handle = 0xFFFF;
                    g_devices[i].business_cmd_handle = 0;
                    g_devices[i].notify_ready = false;
                }
            }
            char evt[500];
            snprintf(evt, sizeof(evt),
                "{\"type\":\"ble_device\",\"seq\":%d,\"deviceId\":\"%s\",\"name\":\"%s\","
                "\"address\":\"%s\",\"rssi\":%d,\"connected\":%s,\"capabilities\":%s}",
                seq, cached ? g_devices[i].device_id : addr_str,
                cached ? g_devices[i].name : (g_devices[i].name[0] ? g_devices[i].name : "unknown"),
                addr_str, g_devices[i].rssi, ready ? "true" : "false",
                g_devices[i].capabilities[0] ? g_devices[i].capabilities : "[]");
            ble_send_event_json(evt);
            if (cached) {
                char hello[600];
                snprintf(hello, sizeof(hello),
                    "{\"type\":\"device_hello\",\"seq\":%d,"
                    "\"deviceId\":\"%s\",\"name\":\"%s\",\"room\":\"%s\","
                    "\"address\":\"%s\",\"rssi\":%d,\"connected\":%s,"
                    "\"capabilities\":%s,\"transport\":\"ble\",\"crypto\":\"sm4\",\"epoch\":0}",
                    seq, g_devices[i].device_id, g_devices[i].name,
                    g_devices[i].room, addr_str, g_devices[i].rssi, ready ? "true" : "false",
                    g_devices[i].capabilities[0] ? g_devices[i].capabilities : "[]");
                ble_send_event_json(hello);
                char st[300];
                snprintf(st, sizeof(st),
                    "{\"type\":\"ble_device_state\",\"seq\":%d,\"deviceId\":\"%s\","
                    "\"address\":\"%s\",\"connected\":%s}",
                    seq, g_devices[i].device_id, addr_str, ready ? "true" : "false");
                ble_send_event_json(st);
                if (ready) {
                    char ready_evt[320];
                    snprintf(ready_evt, sizeof(ready_evt),
                        "{\"type\":\"ble_ready\",\"seq\":%d,\"deviceId\":\"%s\","
                        "\"address\":\"%s\",\"connected\":true,\"notifyReady\":true}",
                        seq, g_devices[i].device_id, addr_str);
                    ble_send_event_json(ready_evt);
                }
            }
        }

        /* 启动扫描 */
        ble_scan_start(duration_ms, max_devices, auto_connect);
    } else if (strcmp(action_buf, "control") == 0) {
        char did_buf[40] = {0}, b64_buf[1024] = {0};
        json_get_str(json, "deviceId", did_buf, sizeof(did_buf));
        json_get_str(json, "payloadBase64", b64_buf, sizeof(b64_buf));

        int blen = 0; uint8_t *raw = b64_decode(b64_buf, &blen);
        ESP_LOGI(TAG, "control: b64_len=%d raw_len=%d tail8=%02X%02X%02X%02X%02X%02X%02X%02X",
                 (int)strlen(b64_buf), blen,
                 blen>0?raw[blen-8]:0, blen>1?raw[blen-7]:0, blen>2?raw[blen-6]:0, blen>3?raw[blen-5]:0,
                 blen>4?raw[blen-4]:0, blen>5?raw[blen-3]:0, blen>6?raw[blen-2]:0, blen>7?raw[blen-1]:0);
        char result[300];
        if (!raw || blen == 0) {
            snprintf(result, sizeof(result), "{\"type\":\"ble_control_result\",\"seq\":%d,\"deviceId\":\"%s\",\"ok\":false,\"message\":\"base64 decode failed\"}", seq, did_buf);
            usb_send_json(TYPE_GATEWAY_BLE_EVT, seq, result);
        } else {
            /* 找对应设备的连接和 business_cmd handle */
            int didx = -1;
            for (int i = 0; i < g_device_count; i++) {
                if (g_devices[i].device_id[0] && strcmp(g_devices[i].device_id, did_buf) == 0) {
                    didx = i; break;
                }
            }
            if (didx < 0 || g_devices[didx].conn_handle == 0xFFFF ||
                g_devices[didx].business_cmd_handle == 0 || !g_devices[didx].notify_ready) {
                snprintf(result, sizeof(result), "{\"type\":\"ble_control_result\",\"seq\":%d,\"deviceId\":\"%s\",\"ok\":false,\"message\":\"device not connected\"}", seq, did_buf);
                usb_send_json(TYPE_GATEWAY_BLE_EVT, seq, result);
            } else {
                int wrc = ble_gattc_write_flat(g_devices[didx].conn_handle,
                    g_devices[didx].business_cmd_handle, raw, blen, NULL, NULL);
                snprintf(result, sizeof(result), "{\"type\":\"ble_control_result\",\"seq\":%d,\"deviceId\":\"%s\",\"ok\":%s,\"message\":\"%s\"}",
                    seq, did_buf, wrc == 0 ? "true" : "false", wrc == 0 ? "written" : "write_failed");
                usb_send_json(TYPE_GATEWAY_BLE_EVT, seq, result);
                ESP_LOGI(TAG, "control: device=%s write=%d bytes rc=%d", did_buf, blen, wrc);
            }
            free(raw);
        }

    } else if (strcmp(action_buf, "connect-known") == 0) {
        handle_connect_known(seq);
    } else if (strcmp(action_buf, "gateway-reboot") == 0) {
        ESP_LOGI(TAG, "RX gateway-reboot seq=%d", seq);
        char ack[128];
        snprintf(ack, sizeof(ack),
            "{\"type\":\"gateway_reboot_ack\",\"seq\":%d,\"ok\":true,\"delayMs\":500}", seq);
        /* 通过事件队列发送 ACK (确保 USB 帧编码+CRC+分片完成) */
        char *copy = strdup(ack);
        evt_item_t item = { .data = copy, .len = copy ? (int)strlen(copy) : 0 };
        if (copy && xQueueSend(g_evt_queue, &item, pdMS_TO_TICKS(100)) == pdTRUE) {
            ESP_LOGI(TAG, "gateway_reboot_ack queued, restarting in 500ms");
            g_reboot_seq = seq;
            g_reboot_time = esp_timer_get_time() + 500000;
        } else {
            ESP_LOGE(TAG, "gateway_reboot_ack queue failed");
            free(copy);
        }
    } else {
        ESP_LOGW(TAG, "0x62: unknown action '%s'", action_buf);
    }
}

/* ======================== JSON 字段解析 ======================== */

/* ======================== Main ======================== */
void app_main(void)
{
    /* NVS */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase(); nvs_flash_init();
    }

    /* UART0 调试日志 */
    uart_config_t uart_cfg = {
        .baud_rate = 115200, .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE, .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
    };
    uart_param_config(UART_NUM_0, &uart_cfg);
    uart_driver_install(UART_NUM_0, 1024, 0, 0, NULL, 0);

    /* USB Serial/JTAG 协议通道 */
    usb_serial_jtag_driver_config_t usj_cfg = USB_SERIAL_JTAG_DRIVER_CONFIG_DEFAULT();
    usb_serial_jtag_driver_install(&usj_cfg);
    uint8_t flush[64]; usb_serial_jtag_read_bytes(flush, sizeof(flush), pdMS_TO_TICKS(50));

    ESP_LOGI(TAG, "============================================");
    ESP_LOGI(TAG, "ESP32-S3 USB BLE Gateway — Stage 2");
    ESP_LOGI(TAG, "USB: 0x01/0x81, BLE: NimBLE Central");
    ESP_LOGI(TAG, "BLE capacity: host_connections=%d controller_activities=%d",
             CONFIG_BT_NIMBLE_MAX_CONNECTIONS, CONFIG_BT_CTRL_BLE_MAX_ACT);
    ESP_LOGI(TAG, "usb_connected=%d", usb_serial_jtag_is_connected());
    ESP_LOGI(TAG, "============================================");

    /* BLE 事件队列: NimBLE 回调 → 主循环 USB 发送 */
    g_evt_queue = xQueueCreate(32, sizeof(evt_item_t));
    g_usb_tx_mutex = xSemaphoreCreateMutex();
    if (!g_evt_queue || !g_usb_tx_mutex) {
        ESP_LOGE(TAG, "USB event transport init failed");
        return;
    }
    xTaskCreate(usb_event_tx_task, "usb_evt_tx", 4096, NULL, 6, NULL);

    /* 启动 BLE Central */
    ble_central_init();

    /* USB 帧接收主循环 (静态分配, 避免栈溢出) */
    static frame_reader_t fr;
    static uint8_t rx_payload[FRAME_MAX_PAYLOAD];
    fr_reset(&fr);
    uint16_t rx_payload_len = 0;
    uint8_t rx_type = 0, rx_seq = 0;

    while (1) {
        /* 自动重连: 断连设备到期后自动尝试重连 */
        int64_t now = esp_timer_get_time();
        if (!g_busy) {
            for (int i = 0; i < g_device_count; i++) {
                if (g_devices[i].reconnect_at > 0 && now > g_devices[i].reconnect_at
                    && g_devices[i].conn_handle == 0xFFFF && g_devices[i].device_id[0]) {
                    ESP_LOGI(TAG, "Auto-reconnect dev[%d] %s", i, g_devices[i].device_id);
                    g_devices[i].reconnect_at = 0;
                    g_busy = true;
                    g_busy_since = now;
                    g_reconnect_mode = true;
                    g_hello_done = 0;
                    g_pending_idx = i;
                    try_connect_next();
                    break;
                }
            }
        }

        /* 网关重启: ACK 发送完成后延迟 500ms 执行 */
        if (g_reboot_time > 0 && esp_timer_get_time() > g_reboot_time) {
            usb_serial_jtag_wait_tx_done(pdMS_TO_TICKS(1000));
            ESP_LOGI(TAG, "restarting now (seq=%d)", g_reboot_seq);
            vTaskDelay(pdMS_TO_TICKS(100));
            esp_restart();
        }

        /* 消费 BLE 事件队列 (NimBLE 回调推送, 主循环发送) */
        /* BLE operation timeout: two devices may need sequential discovery. */
        if (g_busy && (esp_timer_get_time() - g_busy_since) > 90000000) {
            ESP_LOGE(TAG, "BLE operation timeout (90s), force finish");
            char evt[200];
            snprintf(evt, sizeof(evt),
                "{\"type\":\"%s\",\"seq\":%d,\"ok\":false,\"count\":0,\"reason\":\"timeout\"}",
                g_reconnect_mode ? "ble_reconnect_finished" : "ble_scan_finished", g_scan_seq);
            usb_send_json(TYPE_GATEWAY_BLE_EVT, (uint8_t)g_scan_seq, evt);
            g_busy = false;
            g_reconnect_mode = false;
            g_pending_idx = -1;
        }

        uint8_t b;
        int n = usb_serial_jtag_read_bytes(&b, 1, pdMS_TO_TICKS(10));
        if (n <= 0) { continue; }

        int rc = fr_feed(&fr, b, &rx_type, &rx_seq, rx_payload, &rx_payload_len);
        if (rc != 1) { if (rc == -1) ESP_LOGE(TAG, "CRC FAIL seq=%d", rx_seq); continue; }

        ESP_LOGI(TAG, "FRAME: type=0x%02X seq=%d len=%d", rx_type, rx_seq, rx_payload_len);

        switch (rx_type) {
        case TYPE_GATEWAY_TEST:      /* 0x60 */
            handle_test_request(rx_seq, rx_payload, rx_payload_len);
            break;
        case TYPE_GATEWAY_BLE_CMD:   /* 0x62 */
            handle_ble_command(rx_seq, rx_payload, rx_payload_len);
            break;
        default:
            ESP_LOGW(TAG, "Unknown type 0x%02X", rx_type);
            break;
        }
    }
}
