/**
 * @file  door.h
 * @brief 门禁控制模块 — GPIO 控制 + 状态管理 + ACK 组装
 */
#ifndef DOOR_H
#define DOOR_H

#include "main_config.h"
#include <stdbool.h>

/* ====================== 门禁配置 ====================== */

/* 硬件开关: 0=纯协议通信 (硬件未接), 1=GPIO 硬件控制 */
#define DOOR_HARDWARE_ENABLE 1

/* 双 GPIO 电机控制: GPIO16 HIGH=关门, GPIO17 HIGH=开门 */
#define DOOR_CLOSE_GPIO     GPIO_NUM_16
#define DOOR_OPEN_GPIO      GPIO_NUM_17
#define DOOR_ACTIVE_LEVEL   1       /* HIGH=动作有效 */
#define DOOR_OPEN_DURATION_MS 10000 /* 开门保持 10 秒后自动关门 */

/* 门磁传感器 (可选, 检测门是否被物理打开) */
#define DOOR_SENSE_GPIO     GPIO_NUM_15
#define DOOR_OPEN_LEVEL     0       /* 门磁: 0=门开 (磁铁远离), 1=门关 */

/* ====================== API ====================== */

/**
 * @brief 初始化门禁 GPIO
 */
void door_init(void);

/**
 * @brief 开锁 (大禹指令)
 *
 * @param priority  优先级
 * @param lock_ms   锁定时间 (ms), 在此期间本地自动逻辑不覆盖
 * @param seq       指令序号 (用于 ACK)
 * @return true     执行成功
 */
bool door_unlock(int priority, uint32_t lock_ms, int seq);

/**
 * @brief 上锁 (大禹指令)
 *
 * @param priority  优先级
 * @param seq       指令序号 (用于 ACK)
 * @return true     执行成功
 */
bool door_lock(int priority, int seq);

/**
 * @brief 查询门锁状态
 * @return true=已上锁, false=已解锁
 */
bool door_is_locked(void);

/**
 * @brief 查询门是否被物理打开 (门磁传感器)
 * @return true=门开着, false=门关着
 */
bool door_is_open(void);

/**
 * @brief 构造门禁 ACK JSON
 *
 * @param buf       输出缓冲区
 * @param buf_size  缓冲区大小
 * @param seq       指令序号
 * @param ok        执行是否成功
 * @param locked    执行后门锁状态
 * @param message   失败原因 (ok=true 时可传 NULL)
 * @return 写入字节数
 */
int door_build_ack(char *buf, int buf_size, int seq, bool ok,
                   bool locked, const char *message);

#endif /* DOOR_H */
