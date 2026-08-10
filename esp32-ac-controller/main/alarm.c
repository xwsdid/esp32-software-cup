/**
 * @file  alarm.c
 * @brief 烟雾 + 水浸 ADC 传感器驱动 — 阈值报警 + 蜂鸣器
 */
#include "alarm.h"
#include "esp_adc/adc_oneshot.h"
#include "driver/gpio.h"
#include "driver/ledc.h"
#include "esp_log.h"
#include "esp_timer.h"

static const char *TAG = "ALARM";
static adc_oneshot_unit_handle_t s_adc1_handle = NULL;

/* 上一次状态 (用于边缘检测) */
static bool s_last_smoke_alarm = false;
static bool s_last_water_alarm = false;

/* ---- 报警红灯: 0.5s 闪烁 ---- */
static esp_timer_handle_t s_led_timer = NULL;

static void led_timer_cb(void *arg)
{
    static bool led_on = false;
    led_on = !led_on;
    gpio_set_level(ALARM_LED_GPIO, led_on ? 1 : 0);
}

static void alarm_led_start(void)
{
    if (s_led_timer) return;  /* 已在闪烁 */
    esp_timer_create_args_t args = {
        .callback = led_timer_cb,
        .name = "alarm_led",
    };
    esp_timer_create(&args, &s_led_timer);
    esp_timer_start_periodic(s_led_timer, 500000);  /* 500ms */
    ESP_LOGI(TAG, "Alarm LED blink start (GPIO%d, 500ms)", ALARM_LED_GPIO);
}

static void alarm_led_stop(void)
{
    if (!s_led_timer) return;
    esp_timer_stop(s_led_timer);
    esp_timer_delete(s_led_timer);
    s_led_timer = NULL;
    gpio_set_level(ALARM_LED_GPIO, 0);
    ESP_LOGI(TAG, "Alarm LED off");
}

/* ---- 无源蜂鸣器 PWM ---- */
#define BUZZER_FREQ_HZ          2000    /* 蜂鸣器频率 2kHz */
#define BUZZER_DUTY_10BIT_MAX   1023    /* 10bit 分辨率, 2^10 - 1 */
#define BUZZER_DUTY_ON          512     /* 50% 占空比 */
#define BUZZER_DUTY_OFF         0

static void buzzer_on(void)
{
    ledc_set_duty_and_update(LEDC_LOW_SPEED_MODE, LEDC_CHANNEL_0, BUZZER_DUTY_ON, 0);
    ESP_LOGI(TAG, "Buzzer ON: duty=%d freq=%dHz", BUZZER_DUTY_ON, BUZZER_FREQ_HZ);
}

static void buzzer_off(void)
{
    ledc_set_duty_and_update(LEDC_LOW_SPEED_MODE, LEDC_CHANNEL_0, BUZZER_DUTY_OFF, 0);
    ESP_LOGI(TAG, "Buzzer OFF");
}

alarm_data_t      s_alarm_data = {0};
SemaphoreHandle_t s_alarm_mutex = NULL;

void alarm_init(void)
{
    s_alarm_mutex = xSemaphoreCreateMutex();

    /* ADC1 */
    adc_oneshot_unit_init_cfg_t unit_cfg = {
        .unit_id  = ADC_UNIT_1,
        .clk_src  = ADC_DIGI_CLK_SRC_DEFAULT,
        .ulp_mode = ADC_ULP_MODE_DISABLE,
    };
    adc_oneshot_new_unit(&unit_cfg, &s_adc1_handle);

    adc_oneshot_chan_cfg_t chan_cfg = {
        .atten    = ADC_ATTEN_DB_12,
        .bitwidth = ADC_BITWIDTH_12,
    };
    adc_oneshot_config_channel(s_adc1_handle, SMOKE_ADC_CHANNEL, &chan_cfg);
    adc_oneshot_config_channel(s_adc1_handle, WATER_ADC_CHANNEL, &chan_cfg);

    /* 无源蜂鸣器 — LEDC PWM */
    ESP_ERROR_CHECK(ledc_fade_func_install(0));

    ledc_timer_config_t ledc_timer = {
        .speed_mode       = LEDC_LOW_SPEED_MODE,
        .duty_resolution  = LEDC_TIMER_10_BIT,
        .timer_num        = LEDC_TIMER_0,
        .freq_hz          = BUZZER_FREQ_HZ,
        .clk_cfg          = LEDC_USE_APB_CLK,
    };
    ESP_ERROR_CHECK(ledc_timer_config(&ledc_timer));

    ledc_channel_config_t ledc_ch = {
        .gpio_num       = BUZZER_GPIO,
        .speed_mode     = LEDC_LOW_SPEED_MODE,
        .channel        = LEDC_CHANNEL_0,
        .timer_sel      = LEDC_TIMER_0,
        .duty           = BUZZER_DUTY_OFF,
        .hpoint         = 0,
    };
    ESP_ERROR_CHECK(ledc_channel_config(&ledc_ch));

    /* 报警红灯 GPIO */
    gpio_config_t led_cfg = {
        .pin_bit_mask = (1ULL << ALARM_LED_GPIO),
        .mode         = GPIO_MODE_OUTPUT,
        .pull_up_en   = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    gpio_config(&led_cfg);
    gpio_set_level(ALARM_LED_GPIO, 0);  /* 默认灭 */

    ESP_LOGI(TAG, "OK smoke=GPIO%d water=GPIO%d buzzer=GPIO%d led=GPIO%d "
             "smoke_thres=%d water_thres=%d",
             SMOKE_GPIO, WATER_GPIO, BUZZER_GPIO, ALARM_LED_GPIO,
             SMOKE_THRESHOLD_RAW, WATER_THRESHOLD_RAW);
}

void alarm_read(void)
{
    int raw;
    float v;

    adc_oneshot_read(s_adc1_handle, SMOKE_ADC_CHANNEL, &raw);
    v = (raw / 4095.0f) * 3.3f;

    if (xSemaphoreTake(s_alarm_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
        s_alarm_data.smoke_raw     = raw;
        s_alarm_data.smoke_voltage = v;
        /* 烟雾: 活性高触发, 带回差 */
        if (s_alarm_data.smoke_alarm)
            s_alarm_data.smoke_alarm = (raw > SMOKE_THRESHOLD_RAW - ALARM_HYSTERESIS);
        else
            s_alarm_data.smoke_alarm = (raw > SMOKE_THRESHOLD_RAW);
        xSemaphoreGive(s_alarm_mutex);
    }

    adc_oneshot_read(s_adc1_handle, WATER_ADC_CHANNEL, &raw);
    v = (raw / 4095.0f) * 3.3f;

    if (xSemaphoreTake(s_alarm_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
        s_alarm_data.water_raw     = raw;
        s_alarm_data.water_voltage = v;
        /* 水浸: 低电平触发, 带回差 */
        if (s_alarm_data.water_alarm)
            s_alarm_data.water_alarm = (raw > 0 && raw < WATER_THRESHOLD_RAW + ALARM_HYSTERESIS);
        else
            s_alarm_data.water_alarm = (raw > 0 && raw < WATER_THRESHOLD_RAW);
        xSemaphoreGive(s_alarm_mutex);
    }

    ESP_LOGI(TAG, "smoke raw=%d %.2fV %s | water raw=%d %.2fV %s",
             s_alarm_data.smoke_raw, s_alarm_data.smoke_voltage,
             s_alarm_data.smoke_alarm ? "⚠" : "OK",
             s_alarm_data.water_raw, s_alarm_data.water_voltage,
             s_alarm_data.water_alarm ? "⚠" : "OK");
}

/**
 * @brief 检测报警状态变化 (边缘触发)
 * @return true=上升沿触发, 需要上报 alarm 事件给大禹
 *
 * 上升沿: 打开蜂鸣器 + 发送 alarm 事件
 * 下降沿: 只发状态更新, 蜂鸣器保持 (等大禹发解除指令才能关)
 */
bool alarm_check_and_send(void)
{
    bool send_alarm = false;

    if (xSemaphoreTake(s_alarm_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
        bool smoke = s_alarm_data.smoke_alarm;
        bool water = s_alarm_data.water_alarm;

        /* 烟雾: 上升沿 → 响蜂鸣器 + 红灯闪烁 */
        if (smoke && !s_last_smoke_alarm) {
            ESP_LOGW(TAG, "!!! 烟雾报警触发 !!! (raw=%d)", s_alarm_data.smoke_raw);
            buzzer_on();
            alarm_led_start();
        }
        if (!smoke && s_last_smoke_alarm) {
            ESP_LOGI(TAG, "烟雾恢复, 等待大禹解除 (raw=%d)", s_alarm_data.smoke_raw);
        }

        /* 水浸: 上升沿 → 响蜂鸣器 + 红灯闪烁 */
        if (water && !s_last_water_alarm) {
            ESP_LOGW(TAG, "!!! 水浸报警触发 !!! (raw=%d)", s_alarm_data.water_raw);
            buzzer_on();
            alarm_led_start();
        }
        if (!water && s_last_water_alarm) {
            ESP_LOGI(TAG, "水浸恢复, 等待大禹解除 (raw=%d)", s_alarm_data.water_raw);
        }

        /* 只要任一报警持续中, 就持续发 alarm 事件 */
        if (smoke || water) {
            send_alarm = true;
        }

        s_last_smoke_alarm = smoke;
        s_last_water_alarm = water;
        xSemaphoreGive(s_alarm_mutex);
    }

    return send_alarm;
}

/**
 * @brief 大禹发指令解除报警 — 关蜂鸣器 + 清报警状态
 */
int alarm_clear(void)
{
    buzzer_off();
    alarm_led_stop();
    if (xSemaphoreTake(s_alarm_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
        s_last_smoke_alarm = false;
        s_last_water_alarm = false;
        s_alarm_data.smoke_alarm = false;
        s_alarm_data.water_alarm = false;
        xSemaphoreGive(s_alarm_mutex);
    }
    ESP_LOGI(TAG, "报警已解除, 蜂鸣器+红灯关闭");
    return 0;
}
