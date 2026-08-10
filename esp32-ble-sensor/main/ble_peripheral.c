/**
 * @file  ble_peripheral.c
 * @brief BLE Peripheral module using NimBLE stack for ESP32-S3 (ESP-IDF v6.0.1 API)
 *
 * GATT Service: 7A6A0001-6B2D-4F01-9C6A-7E8B1A2C0001
 * Characteristics:
 *   - device_hello (READ + NOTIFY): 7A6A0002-...
 *   - business_cmd (WRITE):         7A6A0003-...
 *   - device_event (NOTIFY):        7A6A0004-...
 */
#include "ble_peripheral.h"
#include "ble_crypto.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_coexist.h"
#include "esp_wifi.h"
#include "freertos/task.h"
#include <stdio.h>
#include <string.h>

/* NimBLE includes */
#include "host/ble_hs.h"
#include "host/ble_gap.h"
#include "host/ble_gatt.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"

/* ======================== Constants ======================== */

#define BLE_SERVICE_UUID       0x01, 0x00, 0x2C, 0x1A, 0x8B, 0x7E, 0x6A, 0x9C, \
                               0x01, 0x4F, 0x2D, 0x6B, 0x01, 0x00, 0x6A, 0x7A
#define BLE_CHR_DEVICE_HELLO   0x02, 0x00, 0x2C, 0x1A, 0x8B, 0x7E, 0x6A, 0x9C, \
                               0x01, 0x4F, 0x2D, 0x6B, 0x01, 0x00, 0x6A, 0x7A
#define BLE_CHR_BUSINESS_CMD   0x03, 0x00, 0x2C, 0x1A, 0x8B, 0x7E, 0x6A, 0x9C, \
                               0x01, 0x4F, 0x2D, 0x6B, 0x01, 0x00, 0x6A, 0x7A
#define BLE_CHR_DEVICE_EVENT   0x04, 0x00, 0x2C, 0x1A, 0x8B, 0x7E, 0x6A, 0x9C, \
                               0x01, 0x4F, 0x2D, 0x6B, 0x01, 0x00, 0x6A, 0x7A

#define BLE_DEVICE_ID_LEN      32
#define BLE_ADV_NAME_MAX       16

/* ======================== Static Variables ======================== */

static char s_ble_device_id[BLE_DEVICE_ID_LEN];
static char s_adv_name[BLE_ADV_NAME_MAX];
static uint8_t s_ble_addr[6];

/* GATT attribute handles */
static uint16_t s_handle_device_hello;
static uint16_t s_handle_business_cmd;
static uint16_t s_handle_device_event;

/* ======================== GATT Callbacks ======================== */

static int gatt_device_hello_cb(uint16_t conn, uint16_t attr,
                                struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    char json_buf[256];
    int len = snprintf(json_buf, sizeof(json_buf),
        "{"
        "\"type\":\"device_hello\","
        "\"deviceId\":\"%s\","
        "\"name\":\"Sensor Controller\","
        "\"room\":\"\","
        "\"capabilities\":[\"sensor\",\"door\",\"light\"],"
        "\"transport\":\"ble\","
        "\"crypto\":\"sm4\","
        "\"epoch\":0"
        "}",
        s_ble_device_id);
    int rc = os_mbuf_append(ctxt->om, json_buf, (uint16_t)len);
    if (rc != 0) ESP_LOGE("BLE", "hello: os_mbuf_append failed: %d", rc);
    return (rc == 0) ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
}

static ble_business_cmd_cb_t s_business_cmd_cb = NULL;
static uint16_t s_current_conn_handle = 0xFFFF;

static int gatt_business_cmd_cb(uint16_t conn, uint16_t attr,
                                struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    uint16_t om_len = OS_MBUF_PKTLEN(ctxt->om);
    ESP_LOGI("BLE", "business_cmd WRITE (len=%u)", (unsigned)om_len);
    if (s_business_cmd_cb && om_len > 0) {
        uint8_t buf[256];
        uint16_t out = 0;
        ble_hs_mbuf_to_flat(ctxt->om, buf, sizeof(buf), &out);
        s_business_cmd_cb(buf, out);
    }
    return 0;
}

static int gatt_device_event_cb(uint16_t conn, uint16_t attr,
                                struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    return 0;
}

void ble_set_business_cmd_callback(ble_business_cmd_cb_t cb) { s_business_cmd_cb = cb; }

/* 延迟通知队列: GATT 回调内不能直接调 ble_gattc_notify_custom (NimBLE 锁冲突)
 * 支持快速连续多条 Notify, 不会互相覆盖 */
#define NOTIFY_QUEUE_MAX 8
static uint8_t s_notify_buf[NOTIFY_QUEUE_MAX][600];
static uint16_t s_notify_len[NOTIFY_QUEUE_MAX];
static int s_notify_head = 0;  /* 下一条待发送 */
static int s_notify_tail = 0;  /* 下一条可写入 */
static struct ble_npl_callout s_notify_callout;
static volatile bool s_notify_enabled = false;
static portMUX_TYPE s_notify_lock = portMUX_INITIALIZER_UNLOCKED;

#define NOTIFY_GAP_MS 120

static void clear_notify_queue(void)
{
    portENTER_CRITICAL(&s_notify_lock);
    s_notify_head = 0;
    s_notify_tail = 0;
    portEXIT_CRITICAL(&s_notify_lock);
    ble_npl_callout_stop(&s_notify_callout);
}

static void deferred_notify_cb(struct ble_npl_event *ev)
{
    if (s_current_conn_handle == 0xFFFF || s_handle_device_event == 0 || !s_notify_enabled) return;

    int slot = -1;
    uint16_t len = 0;
    portENTER_CRITICAL(&s_notify_lock);
    if (s_notify_head != s_notify_tail) {
        slot = s_notify_head;
        len = s_notify_len[slot];
    }
    portEXIT_CRITICAL(&s_notify_lock);

    if (slot >= 0) {
        if (len == 0) {
            portENTER_CRITICAL(&s_notify_lock);
            s_notify_head = (s_notify_head + 1) % NOTIFY_QUEUE_MAX;
            portEXIT_CRITICAL(&s_notify_lock);
        } else {
            struct os_mbuf *om = os_msys_get_pkthdr(len, 0);
            if (!om) {
                ESP_LOGE("BLE", "def-notify OOM (len=%u q[%d/%d]), retry 100ms",
                         len, s_notify_head, s_notify_tail);
                ble_npl_callout_reset(&s_notify_callout, ble_npl_time_ms_to_ticks32(100));
                return;
            }
            if (os_mbuf_append(om, s_notify_buf[slot], len) != 0) {
                os_mbuf_free_chain(om);
                ESP_LOGE("BLE", "def-notify mbuf_append fail, retry");
                ble_npl_callout_reset(&s_notify_callout, ble_npl_time_ms_to_ticks32(100));
                return;
            }
            int rc = ble_gattc_notify_custom(s_current_conn_handle, s_handle_device_event, om);
            ESP_LOGI("BLE", "def-notify sent: len=%u rc=%d slot=%d", len, rc, slot);
            portENTER_CRITICAL(&s_notify_lock);
            s_notify_head = (s_notify_head + 1) % NOTIFY_QUEUE_MAX;
            portEXIT_CRITICAL(&s_notify_lock);
        }
    }
    portENTER_CRITICAL(&s_notify_lock);
    bool has_more = s_notify_head != s_notify_tail;
    portEXIT_CRITICAL(&s_notify_lock);
    if (has_more) {
        ble_npl_callout_reset(&s_notify_callout, ble_npl_time_ms_to_ticks32(NOTIFY_GAP_MS));
    }
}

void ble_notify_device_event(const uint8_t *data, uint16_t len)
{
    if (s_current_conn_handle == 0xFFFF || s_handle_device_event == 0 || !s_notify_enabled) {
        ESP_LOGW("BLE", "def-notify skipped: link/CCCD not ready len=%d", (int)len);
        return;
    }
    uint16_t mtu = ble_att_mtu(s_current_conn_handle);
    uint16_t max_payload = mtu > 3 ? mtu - 3 : 20;
    if (len > max_payload) {
        ESP_LOGE("BLE", "def-notify rejected: len=%u exceeds ATT payload=%u", len, max_payload);
        return;
    }
    if (len > sizeof(s_notify_buf[0])) return;

    portENTER_CRITICAL(&s_notify_lock);
    bool was_empty = s_notify_head == s_notify_tail;
    int next = (s_notify_tail + 1) % NOTIFY_QUEUE_MAX;
    if (next == s_notify_head) {
        portEXIT_CRITICAL(&s_notify_lock);
        ESP_LOGW("BLE", "def-notify queue full! drop len=%d", (int)len);
        return;
    }
    memcpy(s_notify_buf[s_notify_tail], data, len);
    s_notify_len[s_notify_tail] = len;
    s_notify_tail = next;
    portEXIT_CRITICAL(&s_notify_lock);
    if (was_empty) {
        ble_npl_callout_reset(&s_notify_callout, ble_npl_time_ms_to_ticks32(20));
    }
}

bool ble_is_connected(void) { return s_current_conn_handle != 0xFFFF; }

/* ======================== GATT Service Definition (v6.0.1 API) ======================== */

static const ble_uuid128_t gatt_svr_svc_uuid =
    BLE_UUID128_INIT(BLE_SERVICE_UUID);

static const ble_uuid128_t chr_device_hello =
    BLE_UUID128_INIT(BLE_CHR_DEVICE_HELLO);
static const ble_uuid128_t chr_business_cmd =
    BLE_UUID128_INIT(BLE_CHR_BUSINESS_CMD);
static const ble_uuid128_t chr_device_event =
    BLE_UUID128_INIT(BLE_CHR_DEVICE_EVENT);

/* Characteristic definitions */
static const struct ble_gatt_chr_def gatt_chars[] = {
    {
        .uuid       = &chr_device_hello.u,
        .access_cb  = gatt_device_hello_cb,
        .flags      = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_NOTIFY,
        .val_handle = &s_handle_device_hello,
    },
    {
        .uuid       = &chr_business_cmd.u,
        .access_cb  = gatt_business_cmd_cb,
        .flags      = BLE_GATT_CHR_F_WRITE,
        .val_handle = &s_handle_business_cmd,
    },
    {
        .uuid       = &chr_device_event.u,
        .access_cb  = gatt_device_event_cb,
        .flags      = BLE_GATT_CHR_F_NOTIFY,
        .val_handle = &s_handle_device_event,
    },
    { 0 } /* terminator */
};

/* Service definition */
static const struct ble_gatt_svc_def gatt_svcs[] = {
    {
        .type            = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid            = &gatt_svr_svc_uuid.u,
        .characteristics = gatt_chars,
    },
    { 0 } /* terminator */
};

static int gatt_svr_register(void)
{
    int rc;
    ble_svc_gap_init();
    ble_svc_gatt_init();

    rc = ble_gatts_count_cfg(gatt_svcs);
    if (rc != 0) { ESP_LOGE("BLE", "count_cfg failed: %d", rc); return rc; }
    rc = ble_gatts_add_svcs(gatt_svcs);
    if (rc != 0) { ESP_LOGE("BLE", "add_svcs failed: %d", rc); return rc; }

    ESP_LOGI("BLE", "GATT services queued (handles assigned at host start)");
    return 0;
}

/* Registration callback — called during ble_gatts_start() */
static void gatt_svr_register_cb(struct ble_gatt_register_ctxt *ctxt, void *arg)
{
    char buf[BLE_UUID_STR_LEN];
    switch (ctxt->op) {
    case BLE_GATT_REGISTER_OP_SVC:
        ESP_LOGI("BLE", "REG-CB: service %s handle=%d",
                 ble_uuid_to_str(ctxt->svc.svc_def->uuid, buf),
                 ctxt->svc.handle);
        break;
    case BLE_GATT_REGISTER_OP_CHR:
        ESP_LOGI("BLE", "REG-CB: char %s def_handle=%d val_handle=%d",
                 ble_uuid_to_str(ctxt->chr.chr_def->uuid, buf),
                 ctxt->chr.def_handle, ctxt->chr.val_handle);
        break;
    default:
        break;
    }
}

/* ======================== NimBLE GAP Event Handler ======================== */

static int ble_gap_event_handler(struct ble_gap_event *event, void *arg)
{
    struct ble_gap_adv_params adv = {0};
    adv.conn_mode = BLE_GAP_CONN_MODE_UND;
    adv.disc_mode = BLE_GAP_DISC_MODE_GEN;

    switch (event->type) {
    case BLE_GAP_EVENT_CONNECT:
        if (event->connect.status == 0) {
            clear_notify_queue();
            s_notify_enabled = false;
            s_current_conn_handle = event->connect.conn_handle;
            ESP_LOGI("BLE", "Connected: handle=%u (WiFi coexists)",
                     event->connect.conn_handle);
        } else {
            ESP_LOGI("BLE", "Connect failed: status=%u", event->connect.status);
            ble_gap_adv_start(BLE_OWN_ADDR_PUBLIC, NULL, BLE_HS_FOREVER,
                              &adv, ble_gap_event_handler, NULL);
        }
        return 0;
    case BLE_GAP_EVENT_DISCONNECT:
        clear_notify_queue();
        s_notify_enabled = false;
        s_current_conn_handle = 0xFFFF;
        ESP_LOGI("BLE", "Disconnected: handle=%u reason=%u",
                 event->disconnect.conn.conn_handle, event->disconnect.reason);
        ble_crypto_reset();
        ble_gap_adv_start(BLE_OWN_ADDR_PUBLIC, NULL, BLE_HS_FOREVER,
                          &adv, ble_gap_event_handler, NULL);
        return 0;
    case BLE_GAP_EVENT_ADV_COMPLETE:
        ESP_LOGI("BLE", "Adv complete, restarting...");
        ble_gap_adv_start(BLE_OWN_ADDR_PUBLIC, NULL, BLE_HS_FOREVER,
                          &adv, ble_gap_event_handler, NULL);
        return 0;
    case BLE_GAP_EVENT_SUBSCRIBE:
        if (event->subscribe.conn_handle == s_current_conn_handle) {
            s_notify_enabled = event->subscribe.cur_notify != 0;
            if (!s_notify_enabled) clear_notify_queue();
        }
        ESP_LOGI("BLE", "Subscribe: conn=%u attr=%u notify=%u indicate=%u",
                 event->subscribe.conn_handle, event->subscribe.attr_handle,
                 event->subscribe.cur_notify, event->subscribe.cur_indicate);
        return 0;
    default:
        return 0;
    }
}

/* ======================== Advertising Setup ======================== */

static int ble_start_advertising(void)
{
    /* 广告包: flags + 128-bit Service UUID (AD 0x07) = 21B < 31B */
    struct ble_hs_adv_fields adv = {0};
    adv.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
    adv.uuids128 = &gatt_svr_svc_uuid;
    adv.num_uuids128 = 1;
    adv.uuids128_is_complete = 1;

    int rc = ble_gap_adv_set_fields(&adv);
    if (rc != 0) { ESP_LOGE("BLE", "adv_set_fields failed: %d", rc); return rc; }

    /* 扫描响应: 设备名称 */
    struct ble_hs_adv_fields rsp = {0};
    rsp.name = (uint8_t *)s_adv_name;
    rsp.name_len = (uint8_t)strlen(s_adv_name);
    rsp.name_is_complete = 1;
    rc = ble_gap_adv_rsp_set_fields(&rsp);
    if (rc != 0) { ESP_LOGW("BLE", "adv_rsp_set_fields failed: %d", rc); }

    struct ble_gap_adv_params adv_params = {0};
    adv_params.conn_mode = BLE_GAP_CONN_MODE_UND;
    adv_params.disc_mode = BLE_GAP_DISC_MODE_GEN;
    adv_params.itvl_min = BLE_GAP_ADV_ITVL_MS(20);
    adv_params.itvl_max = BLE_GAP_ADV_ITVL_MS(30);

    /* 启动失败重试 3 次 */
    for (int retry = 0; retry < 3; retry++) {
        rc = ble_gap_adv_start(BLE_OWN_ADDR_PUBLIC, NULL, BLE_HS_FOREVER,
                               &adv_params, ble_gap_event_handler, NULL);
        if (rc == 0) break;
        ESP_LOGW("BLE", "adv_start retry %d/3: rc=%d", retry + 1, rc);
        vTaskDelay(pdMS_TO_TICKS(500));
    }
    if (rc != 0) { ESP_LOGE("BLE", "adv_start failed after 3 retries: %d", rc); return rc; }

    ESP_LOGI("BLE", "BLE peripheral started");
    ESP_LOGI("BLE", "deviceId=%s", s_ble_device_id);
    ESP_LOGI("BLE", "advertising_name=%s", s_adv_name);
    ESP_LOGI("BLE", "service_uuid=7A6A0001-6B2D-4F01-9C6A-7E8B1A2C0001");
    ESP_LOGI("BLE", "advertising started");
    return 0;
}

/* ======================== NimBLE Host Task ======================== */

static void ble_host_task(void *param)
{
    /* WiFi 驱动优先级 23, 默认 NimBLE 只有 21, 被饿死. 提到 24 确保 BLE 事件能被处理 */
    vTaskPrioritySet(NULL, 24);
    ESP_LOGI("BLE", "NimBLE host task started (prio=%u)", (unsigned)uxTaskPriorityGet(NULL));
    nimble_port_run();
    ESP_LOGW("BLE", "NimBLE host task exit");
    vTaskDelete(NULL);
}

/* ======================== Public API ======================== */

/* NimBLE sync callback — host 就绪后配置 GATT + 开始广播 */
static void ble_on_sync(void)
{
    ble_npl_callout_init(&s_notify_callout, nimble_port_get_dflt_eventq(),
                          deferred_notify_cb, NULL);
    int mtu_rc = ble_att_set_preferred_mtu(256);
    if (mtu_rc != 0) ESP_LOGW("BLE", "set preferred MTU failed: rc=%d", mtu_rc);
    ESP_LOGI("BLE", "NimBLE host ready");
    if (ble_start_advertising() != 0) {
        ESP_LOGE("BLE", "Advertising start failed");
        return;
    }
    ESP_LOGI("BLE", "BLE Peripheral initialized OK");
}

void ble_peripheral_init(void)
{
    ESP_LOGI("BLE", "Initializing BLE Peripheral...");

    /* WiFi/BLE 共存: BLE 优先, 确保 GATT 响应不被 WiFi 饿死 */
    esp_coex_preference_set(ESP_COEX_PREFER_BT);
    ESP_LOGI("BLE", "Coexistence: BT preferred");

    esp_read_mac(s_ble_addr, ESP_MAC_WIFI_STA);  /* 与 MQTT 统一用 WiFi MAC */
    snprintf(s_ble_device_id, sizeof(s_ble_device_id),
             "esp32-%02X%02X%02X%02X%02X%02X",
             s_ble_addr[0], s_ble_addr[1], s_ble_addr[2],
             s_ble_addr[3], s_ble_addr[4], s_ble_addr[5]);
    snprintf(s_adv_name, sizeof(s_adv_name), "YJ-SENSOR-%02X%02X",
             s_ble_addr[4], s_ble_addr[5]);

    ESP_LOGI("BLE", "BT MAC: %02X:%02X:%02X:%02X:%02X:%02X",
             s_ble_addr[0], s_ble_addr[1], s_ble_addr[2],
             s_ble_addr[3], s_ble_addr[4], s_ble_addr[5]);
    ESP_LOGI("BLE", "deviceId=%s  advName=%s", s_ble_device_id, s_adv_name);

    nimble_port_init();

    /* GATT 服务必须在 ble_gatts_start() 之前注册！
     * ble_gatts_start() 在 nimble_port_freertos_init → nimble_port_run 中执行，
     * 晚于 sync_cb 不行，必须在这里注册。 */
    if (gatt_svr_register() != 0) {
        ESP_LOGE("BLE", "GATT service registration failed");
        return;
    }

    /* 设置回调 */
    ble_hs_cfg.sync_cb = ble_on_sync;
    ble_hs_cfg.gatts_register_cb = gatt_svr_register_cb;

    /* 启动 NimBLE host 线程 */
    nimble_port_freertos_init(ble_host_task);
}
