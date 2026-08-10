/**
 * @file  alarm.h
 * @brief 烟雾传感器 + 水浸传感器 — ADC 读取 + 阈值报警 + 蜂鸣器
 */
#ifndef ALARM_H
#define ALARM_H

#include <stdint.h>
#include <stdbool.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

/* ---- 引脚 ---- */
#define SMOKE_GPIO              4
#define WATER_GPIO              5
#define SMOKE_ADC_CHANNEL       ADC_CHANNEL_3   /* GPIO4, ADC1_CH3 */
#define WATER_ADC_CHANNEL       ADC_CHANNEL_4   /* GPIO5, ADC1_CH4 */
#define BUZZER_GPIO             6               /* 无源蜂鸣器 PWM */
#define ALARM_LED_GPIO          18              /* 报警红灯: 0.5s 闪烁 */

/* ---- 阈值 (ADC 原始值, 0-4095, 12bit) ---- */
#define SMOKE_THRESHOLD_RAW     2800    /* 烟雾: raw>2800 触发 (活性高) */
#define WATER_THRESHOLD_RAW     2000    /* 水浸: 0<raw<2000 触发 (活性低) */
#define ALARM_HYSTERESIS        150     /* 回差: 防止阈值附近振荡 */

/* ---- 报警数据 ---- */
typedef struct {
    int     smoke_raw;
    float   smoke_voltage;
    int     water_raw;
    float   water_voltage;
    bool    smoke_alarm;      /* 当前烟雾是否处于报警状态 */
    bool    water_alarm;      /* 当前水浸是否处于报警状态 */
} alarm_data_t;

extern alarm_data_t         s_alarm_data;
extern SemaphoreHandle_t    s_alarm_mutex;

/* ---- API ---- */
void alarm_init(void);
void alarm_read(void);        /* 读传感器 + 阈值判断 */
bool alarm_check_and_send(void); /* 检测上升沿, 触发蜂鸣器+上报alarm事件 */
int  alarm_clear(void);          /* 大禹发指令解除报警: 关蜂鸣器+清状态 */

#endif
