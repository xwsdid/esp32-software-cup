/**
 * @file  stepper.c
 * @brief 4 相步进电机驱动 — 8 拍 (half-step) 序列 + 位置跟踪
 */
#include "stepper.h"
#include "driver/gpio.h"
#include "esp_log.h"
#include "esp_rom_sys.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "STEPPER";

/* GPIO mask (低 4 位对应 IN1~IN4) */
#define STEPPER_PIN_MASK \
    ((1ULL << STEPPER_IN1_GPIO) | (1ULL << STEPPER_IN2_GPIO) | \
     (1ULL << STEPPER_IN3_GPIO) | (1ULL << STEPPER_IN4_GPIO))

/* 方向 */
typedef enum {
    DIR_OPEN  = 0,
    DIR_CLOSE = 1,
} stepper_dir_t;

/* 8 拍半步序列 — LSB=IN1 (力矩较小但平滑) */
static const uint8_t s_half_step[8] = {
    0b1001, 0b0001, 0b0011, 0b0010,
    0b0110, 0b0100, 0b1100, 0b1000,
};

/* 4 拍全步序列 — 力矩大, 适合起步 */
static const uint8_t s_full_step[4] = {
    0b1001,  /* IN1=1 IN2=0 IN3=0 IN4=1 */
    0b0011,  /* IN1=1 IN2=1 IN3=0 IN4=0 */
    0b0110,  /* IN1=0 IN2=1 IN3=1 IN4=0 */
    0b1100,  /* IN1=0 IN2=0 IN3=1 IN4=1 */
};

static const int s_pins[4] = {
    STEPPER_IN1_GPIO, STEPPER_IN2_GPIO,
    STEPPER_IN3_GPIO, STEPPER_IN4_GPIO,
};

/* 当前位置: 0=全关, 100=全开 */
static uint8_t s_cur_position = 0;

static inline void stepper_write_phases(uint8_t phases)
{
    for (int i = 0; i < 4; i++) {
        gpio_set_level(s_pins[i], (phases >> i) & 0x01);
    }
}

/**
 * @brief 步进电机转动 (内部使用)
 * @param mode  false=全步(力矩大), true=半步(平滑)
 */
static void stepper_run(stepper_dir_t dir, uint32_t steps, bool half)
{
    int step_count = half ? 8 : 4;
    const uint8_t *seq = half ? s_half_step : s_full_step;
    int8_t idx = 0;
    int8_t delta = (dir == DIR_OPEN) ? 1 : -1;
    int us_delay = half ? STEPPER_DELAY_US : (STEPPER_DELAY_US * 2);

    for (uint32_t i = 0; i < steps; i++) {
        uint8_t ph = seq[(uint8_t)idx];
        stepper_write_phases(ph);

        if (i < 8) {
            ESP_LOGI(TAG, "step[%lu] phase=0x%02X "
                     "GPIO7=%d GPIO8=%d GPIO9=%d GPIO10=%d",
                     i, ph,
                     (ph >> 0) & 1, (ph >> 1) & 1,
                     (ph >> 2) & 1, (ph >> 3) & 1);
        }

        esp_rom_delay_us(us_delay);
        idx = (idx + delta) & (step_count - 1);

        if ((i & 0x3F) == 0x3F) {  /* 每 64 步让出 CPU */
            vTaskDelay(1);
        }
    }
}

/* ======================== Public API ======================== */

void stepper_init(void)
{
    /* GPIO 输出 + 最大驱动强度 */
    gpio_config_t cfg = {
        .pin_bit_mask = STEPPER_PIN_MASK,
        .mode         = GPIO_MODE_OUTPUT,
        .pull_up_en   = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    gpio_config(&cfg);

    /* 设置最大驱动强度 (20mA → 40mA), 提升 ULN2003 输入电压 */
    for (int i = 0; i < 4; i++) {
        gpio_set_drive_capability(s_pins[i], GPIO_DRIVE_CAP_3);
    }

    stepper_write_phases(0x00);
    s_cur_position = 0;

    ESP_LOGI(TAG, "OK IN1=GPIO%d IN2=GPIO%d IN3=GPIO%d IN4=GPIO%d "
             "total_steps=%d pos=%d%%",
             STEPPER_IN1_GPIO, STEPPER_IN2_GPIO,
             STEPPER_IN3_GPIO, STEPPER_IN4_GPIO,
             STEPPER_TOTAL_STEPS, s_cur_position);
}

void stepper_stop(void)
{
    stepper_write_phases(0x00);
    ESP_LOGI(TAG, "STOP (pos=%d%%)", s_cur_position);
}

uint8_t stepper_get_position(void)
{
    return s_cur_position;
}

void stepper_set_target(uint8_t val)
{
    if (val > 100) val = 100;

    int8_t delta = (int8_t)s_cur_position - (int8_t)val;  /* 方向反转 */
    if (delta == 0) {
        ESP_LOGI(TAG, "already at %d%%, skip", val);
        return;
    }

    stepper_dir_t dir;
    if (delta > 0) dir = DIR_OPEN;
    else           dir = DIR_CLOSE;

    /* 用全步模式, 力矩更大 */
    uint32_t abs_delta = (uint32_t)(delta > 0 ? delta : -delta);
    uint32_t steps = abs_delta * STEPPER_TOTAL_STEPS / 100;
    if (steps == 0) steps = 1;

    ESP_LOGI(TAG, "target=%d%% cur=%d%% delta=%d steps=%lu dir=%s",
             val, s_cur_position, delta, steps,
             (dir == DIR_OPEN) ? "OPEN" : "CLOSE");

    stepper_run(dir, steps, true);  /* true=半步模式 */
    stepper_write_phases(0x00);

    s_cur_position = val;
    ESP_LOGI(TAG, "done pos=%d%%", s_cur_position);
}
