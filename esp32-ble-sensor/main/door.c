/**
 * @file  door.c
 * @brief 门禁控制 — 双 GPIO 电机驱动 + 10s 自动关门 + ACK
 *
 * GPIO16 HIGH = 关门, GPIO17 HIGH = 开门
 * 默认关门状态 (GPIO16 HIGH, GPIO17 LOW)
 * 收到开门指令 → GPIO16 LOW, GPIO17 HIGH → 10s 后自动恢复关门
 */
#include "door.h"

static const char *TAG_DOOR = "DOOR";

static TimerHandle_t s_door_auto_close_timer = NULL;
static bool s_door_open_hw = false;  /* 当前硬件是否处于开门状态 */

/* ======================== 自动关门回调 (FreeRTOS Timer) ======================== */

static void door_auto_close_cb(TimerHandle_t timer)
{
#if DOOR_HARDWARE_ENABLE
    gpio_set_level(DOOR_OPEN_GPIO,  DOOR_ACTIVE_LEVEL ? 0 : 1);   /* 开门 OFF */
    gpio_set_level(DOOR_CLOSE_GPIO, DOOR_ACTIVE_LEVEL);            /* 关门 ON  */
#endif
    s_door_open_hw = false;

    /* 更新状态: 门已关上锁 */
    if (xSemaphoreTake(s_sys_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
        s_sys_data.door_open   = 0;
        s_sys_data.door_locked = 1;
        memset(&s_sys_data.door_lock, 0, sizeof(s_sys_data.door_lock));
        xSemaphoreGive(s_sys_mutex);
    }
    ESP_LOGI(TAG_DOOR, "10s 自动关门");
}

/* ======================== 初始化 ======================== */

void door_init(void)
{
#if DOOR_HARDWARE_ENABLE
    /* 1. 关门 GPIO16 → 输出模式, 默认 HIGH (关门) */
    gpio_config_t close_conf = {
        .pin_bit_mask = (1ULL << DOOR_CLOSE_GPIO),
        .mode         = GPIO_MODE_OUTPUT,
        .pull_up_en   = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    gpio_config(&close_conf);
    gpio_set_level(DOOR_CLOSE_GPIO, DOOR_ACTIVE_LEVEL);  /* 初始关门 */

    /* 2. 开门 GPIO17 → 输出模式, 默认 LOW (不动作) */
    gpio_config_t open_conf = {
        .pin_bit_mask = (1ULL << DOOR_OPEN_GPIO),
        .mode         = GPIO_MODE_OUTPUT,
        .pull_up_en   = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    gpio_config(&open_conf);
    gpio_set_level(DOOR_OPEN_GPIO, DOOR_ACTIVE_LEVEL ? 0 : 1);  /* 初始不开门 */

    /* 3. 门磁传感器 GPIO15 → 输入模式 */
    gpio_config_t sense_conf = {
        .pin_bit_mask = (1ULL << DOOR_SENSE_GPIO),
        .mode         = GPIO_MODE_INPUT,
        .pull_up_en   = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    gpio_config(&sense_conf);

    /* 4. 自动关门定时器 (10s 单次触发) */
    s_door_auto_close_timer = xTimerCreate(
        "door_close", pdMS_TO_TICKS(DOOR_OPEN_DURATION_MS),
        pdFALSE, NULL, door_auto_close_cb);
#endif

    /* 5. 初始化系统数据 */
    if (xSemaphoreTake(s_sys_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
        s_sys_data.door_open   = 0;
        s_sys_data.door_locked = 1;
        memset(&s_sys_data.door_lock, 0, sizeof(s_sys_data.door_lock));
        xSemaphoreGive(s_sys_mutex);
    }

    ESP_LOGI(TAG_DOOR, "门禁 OK (硬件:%s CLOSE=GPIO%d OPEN=GPIO%d SENSE=GPIO%d)",
             DOOR_HARDWARE_ENABLE ? "ON" : "OFF",
             DOOR_CLOSE_GPIO, DOOR_OPEN_GPIO, DOOR_SENSE_GPIO);
}

/* ======================== 开锁 ======================== */

bool door_unlock(int priority, uint32_t lock_ms, int seq)
{
    /* 如果已经在开门状态, 先取消旧定时器 */
    if (s_door_auto_close_timer && xTimerIsTimerActive(s_door_auto_close_timer)) {
        xTimerStop(s_door_auto_close_timer, 0);
    }

#if DOOR_HARDWARE_ENABLE
    /* 关门 OFF, 开门 ON */
    gpio_set_level(DOOR_CLOSE_GPIO, DOOR_ACTIVE_LEVEL ? 0 : 1);
    gpio_set_level(DOOR_OPEN_GPIO,  DOOR_ACTIVE_LEVEL);
    s_door_open_hw = true;

    /* lock_ms=0 时不启动自动关门 (大禹已移除 lockMs, 仅 val:0 时关门) */
    if (lock_ms > 0 && s_door_auto_close_timer) {
        xTimerStart(s_door_auto_close_timer, 0);
    }
#endif

    /* 更新系统数据 */
    if (xSemaphoreTake(s_sys_mutex, pdMS_TO_TICKS(100)) != pdTRUE)
        return false;

    s_sys_data.door_open   = 1;
    s_sys_data.door_locked = 0;

    strncpy(s_sys_data.door_lock.owner, "dayu", 15);
    s_sys_data.door_lock.owner[15] = '\0';
    s_sys_data.door_lock.priority  = priority;
    s_sys_data.door_lock.lock_until_ms =
        xTaskGetTickCount() + pdMS_TO_TICKS(lock_ms > 0 ? lock_ms : 0);
    s_sys_data.door_lock.last_seq = seq;
    xSemaphoreGive(s_sys_mutex);

    ESP_LOGI(TAG_DOOR, "开门 (priority=%d, lock=%lums, seq=%d, %s)",
             priority, (unsigned long)lock_ms, seq,
             lock_ms > 0 ? "定时自动关" : "不自关");
    return true;
}

/* ======================== 上锁 (手动关门) ======================== */

bool door_lock(int priority, int seq)
{
    /* 取消自动关门定时器 */
    if (s_door_auto_close_timer && xTimerIsTimerActive(s_door_auto_close_timer)) {
        xTimerStop(s_door_auto_close_timer, 0);
    }

#if DOOR_HARDWARE_ENABLE
    /* 开门 OFF, 关门 ON */
    gpio_set_level(DOOR_OPEN_GPIO,  DOOR_ACTIVE_LEVEL ? 0 : 1);
    gpio_set_level(DOOR_CLOSE_GPIO, DOOR_ACTIVE_LEVEL);
    s_door_open_hw = false;
#endif

    /* 更新系统数据 */
    if (xSemaphoreTake(s_sys_mutex, pdMS_TO_TICKS(100)) != pdTRUE)
        return false;

    s_sys_data.door_open   = 0;
    s_sys_data.door_locked = 1;

    strncpy(s_sys_data.door_lock.owner, "dayu", 15);
    s_sys_data.door_lock.owner[15] = '\0';
    s_sys_data.door_lock.priority  = priority;
    s_sys_data.door_lock.lock_until_ms =
        xTaskGetTickCount() + pdMS_TO_TICKS(10000);
    s_sys_data.door_lock.last_seq = seq;
    xSemaphoreGive(s_sys_mutex);

    ESP_LOGI(TAG_DOOR, "关门 (priority=%d, seq=%d)", priority, seq);
    return true;
}

/* ======================== 状态查询 ======================== */

bool door_is_locked(void)
{
    bool locked = true;
    if (xSemaphoreTake(s_sys_mutex, pdMS_TO_TICKS(50)) == pdTRUE) {
        locked = (s_sys_data.door_locked != 0);
        xSemaphoreGive(s_sys_mutex);
    }
    return locked;
}

bool door_is_open(void)
{
#if DOOR_HARDWARE_ENABLE
    int level = gpio_get_level(DOOR_SENSE_GPIO);
    return (level == DOOR_OPEN_LEVEL);
#else
    bool locked = true;
    if (xSemaphoreTake(s_sys_mutex, pdMS_TO_TICKS(50)) == pdTRUE) {
        locked = (s_sys_data.door_locked != 0);
        xSemaphoreGive(s_sys_mutex);
    }
    return !locked;
#endif
}

/* ======================== ACK 构造 ======================== */

int door_build_ack(char *buf, int buf_size, int seq, bool ok,
                   bool locked, const char *message)
{
    if (message && message[0] != '\0') {
        return snprintf(buf, buf_size,
            "{\"type\":\"ack\",\"cmd\":\"door\",\"seq\":%d,\"ok\":%s,"
            "\"locked\":%s,\"message\":\"%s\",\"deviceId\":\"%s\"}",
            seq, ok ? "true" : "false",
            locked ? "true" : "false", message, s_device_id);
    }
    return snprintf(buf, buf_size,
        "{\"type\":\"ack\",\"cmd\":\"door\",\"seq\":%d,\"ok\":%s,"
        "\"locked\":%s,\"deviceId\":\"%s\"}",
        seq, ok ? "true" : "false", locked ? "true" : "false", s_device_id);
}
