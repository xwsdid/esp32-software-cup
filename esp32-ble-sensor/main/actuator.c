#include "actuator.h"

/* ======================== LED 执行器 ======================== */

/* 防抖动配置 */
#define DEBOUNCE_SAMPLES    3       /* 连续采样次数 */
#define DEBOUNCE_INTERVAL_MS 500    /* 采样间隔 (ms) */
#define LOCK_CHECK_INTERVAL_MS 100   /* 锁状态检查间隔 (ms, 被锁时用) */

void led_gpio_init(void)
{
    gpio_config_t io_conf = {
        .pin_bit_mask = (1ULL << LED_GPIO),
        .mode         = GPIO_MODE_OUTPUT,
        .pull_up_en   = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    gpio_config(&io_conf);
    gpio_set_level(LED_GPIO, LED_ON_LEVEL ? 0 : 1);
}

/**
 * @brief 执行器控制任务: 有人且照度<阈值时点亮LED
 *
 * 防抖动: 连续采样 3 次, 每次间隔 500ms, 状态一致才执行动作。
 */
void actuator_task(void *pvParameters)
{
    ESP_LOGI(TAG_ACTUATOR, "执行器启动 GPIO=%d (防抖:%d次×%dms)",
             LED_GPIO, DEBOUNCE_SAMPLES, DEBOUNCE_INTERVAL_MS);

    bool led_on        = false;       /* LED 当前状态 */
    bool last_should   = false;       /* 上一次采样的 should_on */
    int  debounce_cnt  = 0;           /* 连续一致计数 */

    while (1) {
        uint8_t pir;
        float   lux;

        if (xSemaphoreTake(s_sys_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
            pir = s_sys_data.pir_detected;
            lux = s_sys_data.light_lux;
            xSemaphoreGive(s_sys_mutex);
        } else {
            vTaskDelay(pdMS_TO_TICKS(DEBOUNCE_INTERVAL_MS));
            continue;
        }

        /* 检查控制锁: 大禹锁有效时, 本地不覆盖, 重置防抖计数 */
        bool locked = false;
        if (xSemaphoreTake(s_sys_mutex, pdMS_TO_TICKS(50)) == pdTRUE) {
            if (s_sys_data.led_lock.owner[0] != '\0') {
                int32_t remaining = (int32_t)(s_sys_data.led_lock.lock_until_ms
                    - xTaskGetTickCount());
                if (remaining > 0 && s_sys_data.led_lock.priority >= 10) {
                    locked = true;
                }
            }
            xSemaphoreGive(s_sys_mutex);
        }

        if (locked) {
            /* 被大禹锁住: 重置防抖计数, 快速轮询等待锁释放 */
            debounce_cnt = 0;
            vTaskDelay(pdMS_TO_TICKS(LOCK_CHECK_INTERVAL_MS));
            continue;
        }

        /* 判断: 有人 且 照度 < 阈值 → 应点亮LED */
        bool should_on = (pir == 1) && (lux < LIGHT_THRESHOLD_LUX);

        /* ---- 防抖动: 连续 DEBOUNCE_SAMPLES 次一致才执行 ---- */
        if (should_on == last_should) {
            debounce_cnt++;
        } else {
            debounce_cnt = 1;
            last_should  = should_on;
        }

        if (debounce_cnt >= DEBOUNCE_SAMPLES && should_on != led_on) {
            /* 确认状态已稳定, 执行动作 */
            led_on = should_on;
            gpio_set_level(LED_GPIO, led_on ? LED_ON_LEVEL : (1 - LED_ON_LEVEL));

            /* 更新系统数据中的 LED 状态 */
            if (xSemaphoreTake(s_sys_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
                s_sys_data.led_cmd = should_on ? 1 : 0;
                s_sys_data.led_on  = led_on ? 1 : 0;
                xSemaphoreGive(s_sys_mutex);
            }

            ESP_LOGI(TAG_ACTUATOR, "LED %s (PIR=%s, 光照=%.1f lux, 防抖确认%d次)",
                     led_on ? "点亮 ✓" : "熄灭",
                     pir ? "有人" : "无人", lux, debounce_cnt);

            /* 动作执行后重置计数, 避免重复触发 */
            debounce_cnt = 0;
        } else if (debounce_cnt >= DEBOUNCE_SAMPLES) {
            /* 状态一致但与当前 LED 状态相同, 周期性重置避免溢出 */
            if (debounce_cnt >= DEBOUNCE_SAMPLES * 10) {
                debounce_cnt = DEBOUNCE_SAMPLES;  /* 保持稳定态不重置 */
            }
        }

        vTaskDelay(pdMS_TO_TICKS(DEBOUNCE_INTERVAL_MS));
    }
}