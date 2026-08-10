/**
 * @file  stepper.h
 * @brief 4 相步进电机驱动 — 窗帘位置控制 (0~100%)
 *
 * 28BYJ-48 减速步进电机, ULN2003 驱动板
 * 8 拍 (half-step) 驱动
 *
 * 接线: IN1→GPIO7  IN2→GPIO8  IN3→GPIO9  IN4→GPIO10
 */
#ifndef STEPPER_H
#define STEPPER_H

#include <stdint.h>

/* ---- 引脚 ---- */
#define STEPPER_IN1_GPIO    7
#define STEPPER_IN2_GPIO    8
#define STEPPER_IN3_GPIO    9
#define STEPPER_IN4_GPIO    10

/* 全行程总步数 (全关→全开=输出轴2圈=8192步) */
#define STEPPER_TOTAL_STEPS  8192

/* 每步延迟 (微秒), 越小越快. 28BYJ-48 可靠范围 1000~3000us */
#define STEPPER_DELAY_US     1200

/* ---- API ---- */
void     stepper_init(void);
void     stepper_set_target(uint8_t val);   /* val: 0=全关, 100=全开 */
void     stepper_stop(void);
uint8_t  stepper_get_position(void);        /* 返回当前开合度 0~100 */

#endif
