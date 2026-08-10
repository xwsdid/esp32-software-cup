#pragma once

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ================================================================
 *  协议常量定义
 * ================================================================ */

/* 帧定界符 */
#define IR_FRAME_HEADER      0x68
#define IR_FRAME_TAIL        0x16

/* 广播地址 & 默认地址 */
#define IR_ADDR_BROADCAST    0xFF
#define IR_ADDR_DEFAULT      0x00

/* 最大缓冲区 */
#define IR_FRAME_MAX_LEN     600       /* 足够容纳最大帧 (头+长度+地址+AFN+数据+校验+尾) */
#define IR_DATA_MAX_LEN      512       /* 数据域最大 */

/* ---- 功能码 AFN ---- */
/* 系统级 */
#define IR_AFN_ACK           0x01      /* 应答帧 */
#define IR_AFN_REPORT        0x02      /* 上报帧 */
#define IR_AFN_SET_BAUDRATE  0x03      /* 设置波特率 */
#define IR_AFN_GET_BAUDRATE  0x04      /* 获取波特率 */
#define IR_AFN_SET_ADDR      0x05      /* 设置模块地址 */
#define IR_AFN_GET_ADDR      0x06      /* 获取模块地址 */
#define IR_AFN_RESET         0x07      /* 复位 */
#define IR_AFN_FORMAT        0x08      /* 格式化 */

/* 内部存储 */
#define IR_AFN_ENTER_LEARN   0x10      /* 进入内部编码存储学习模式 */
#define IR_AFN_EXIT_LEARN    0x11      /* 退出内部编码学习模式 */
#define IR_AFN_SEND_CODE     0x12      /* 发送内部存储红外编码 */
#define IR_AFN_SET_PWR_SEND  0x13      /* 设置上电自动发送内部存储编码 */
#define IR_AFN_GET_PWR_SEND  0x14      /* 获取上电自动发送内部存储编码状态 */
#define IR_AFN_SET_PWR_DELAY 0x15      /* 设置上电自动发送内码的延时时间 */
#define IR_AFN_GET_PWR_DELAY 0x16      /* 获取上电自动发送内码的延时时间 */
#define IR_AFN_WRITE_CODE    0x17      /* 写入内部存储编码 */
#define IR_AFN_READ_CODE     0x18      /* 读取内部存储编码 */

/* 外部存储 */
#define IR_AFN_EXT_LEARN     0x20      /* 进入外部编码存储学习模式 */
#define IR_AFN_EXT_EXIT      0x21      /* 退出外部编码存储学习模式 */
#define IR_AFN_EXT_SEND      0x22      /* 返回/发送外部存储编码 */

/* ---- 上报帧标志 ---- */
#define IR_REPORT_LEARN_OK   0x80      /* 学习成功且已存储 */
#define IR_REPORT_PWR_SENT   0x81      /* 上电自动报文已发送 */

/* ---- 应答状态 ---- */
#define IR_STATUS_OK         0x00      /* 成功 */
#define IR_STATUS_ERR        0x01      /* 参数错误/繁忙，已拒绝 */

/* ---- 波特率索引 ---- */
typedef enum {
    IR_BAUD_9600   = 0,
    IR_BAUD_19200  = 1,
    IR_BAUD_38400  = 2,
    IR_BAUD_57600  = 3,
    IR_BAUD_115200 = 4,
} ir_baud_rate_t;

/* ================================================================
 *  帧结构体
 * ================================================================ */

/**
 * @brief 解析后的接收帧
 */
typedef struct {
    uint8_t  addr;          /* 模块地址 */
    uint8_t  afn;           /* 功能码 */
    uint16_t data_len;      /* 数据域长度 */
    uint8_t  data[IR_DATA_MAX_LEN];  /* 数据域 */
} ir_frame_t;

/**
 * @brief 上报帧 (AFN=02H) 数据解析
 */
typedef struct {
    uint8_t flag;           /* 0x80=学习成功, 0x81=上电自动发送完成 */
    uint8_t index;          /* 内部编码存储索引 0~6 */
    uint8_t status;         /* 0=成功, 1=失败 */
} ir_report_t;

/* ================================================================
 *  API 声明
 * ================================================================ */

/**
 * @brief 初始化红外学习模块 UART
 * @param tx_pin  TX 引脚号 (默认 17)
 * @param rx_pin  RX 引脚号 (默认 16)
 * @param baud    波特率 (默认 115200)
 * @return true=成功
 */
bool ir_init(int tx_pin, int rx_pin, int baud);

/**
 * @brief 发送原始帧（底层接口）
 * @param addr  模块地址
 * @param afn   功能码
 * @param data  数据域指针
 * @param len   数据域长度
 * @return true=发送成功
 */
bool ir_send_frame(uint8_t addr, uint8_t afn, const uint8_t *data, uint16_t len);

/**
 * @brief 接收并解析一帧（阻塞，超时 ms）
 * @param frame  输出解析后的帧
 * @param timeout_ms  超时时间(毫秒)
 * @return true=收到有效帧
 */
bool ir_recv_frame(ir_frame_t *frame, uint32_t timeout_ms);

/**
 * @brief 发送命令并等待应答帧 (AFN=01H)
 * @param addr   模块地址
 * @param afn    功能码
 * @param data   数据域
 * @param len    数据域长度
 * @param timeout_ms 超时
 * @return 0=成功, 1=失败/超时
 */
int ir_send_cmd_wait_ack(uint8_t addr, uint8_t afn,
                         const uint8_t *data, uint16_t len,
                         uint32_t timeout_ms);

/* ---------- 高级 API ---------- */

/**
 * @brief 进入内部学习模式 (AFN=10H)
 * @param index  存储索引 0~6
 * @return 0=成功进入
 */
int ir_enter_learn(uint8_t index);

/**
 * @brief 退出内部学习模式 (AFN=11H)
 * @return 0=成功
 */
int ir_exit_learn(void);

/**
 * @brief 发送已存储的红外编码 (AFN=12H)
 * @param index  存储索引 0~6
 * @return 0=成功
 */
int ir_send_stored_code(uint8_t index);

/**
 * @brief 等待学习结果上报 (AFN=02H)
 * @param report  输出上报内容
 * @param timeout_ms  超时
 * @return 0=成功
 */
int ir_wait_learn_report(ir_report_t *report, uint32_t timeout_ms);

/**
 * @brief 写入内部存储编码 (AFN=17H)
 * @param index  索引 0~6
 * @param code  编码数据
 * @param len   编码长度(字节)
 * @return 0=成功
 */
int ir_write_code(uint8_t index, const uint8_t *code, uint16_t len);

/**
 * @brief 读取内部存储编码 (AFN=18H)
 * @param index  索引 0~6
 * @param code  输出缓冲区
 * @param max_len  缓冲区最大长度
 * @param out_len  实际数据长度
 * @return 0=成功
 */
int ir_read_code(uint8_t index, uint8_t *code, uint16_t max_len, uint16_t *out_len);

/**
 * @brief 设置上电自动发送 (AFN=13H)
 * @param index    索引 0~6
 * @param enable   1=启用, 0=取消
 * @return 0=成功
 */
int ir_set_poweron_send(uint8_t index, uint8_t enable);

/**
 * @brief 获取上电自动发送状态 (AFN=14H)
 * @param index   索引
 * @param enable  输出: 1=启用, 0=未启用
 * @return 0=成功
 */
int ir_get_poweron_send(uint8_t index, uint8_t *enable);

/**
 * @brief 设置上电自动发码延时 (AFN=15H)
 * @param delay_sec  延时秒数 0~65535
 * @return 0=成功
 */
int ir_set_poweron_delay(uint16_t delay_sec);

/**
 * @brief 获取上电自动发码延时 (AFN=16H)
 * @param delay_sec  输出延时秒数
 * @return 0=成功
 */
int ir_get_poweron_delay(uint16_t *delay_sec);

/**
 * @brief 复位模块 (AFN=07H)
 * @return 0=成功
 */
int ir_reset(void);

/**
 * @brief 格式化模块 (AFN=08H)
 *        清除所有内部存储编码 / 清除上电自动发送标志 / 恢复默认波特率
 * @return 0=成功
 */
int ir_format(void);

/**
 * @brief 设置模块地址 (AFN=05H)
 * @param new_addr  新地址 0x00~0xFE
 * @return 0=成功
 */
int ir_set_addr(uint8_t new_addr);

/**
 * @brief 获取模块地址 (AFN=06H)
 * @param addr  输出地址
 * @return 0=成功
 */
int ir_get_addr(uint8_t *addr);

/**
 * @brief 计算校验和: (地址 + AFN + 所有数据字节) % 256
 */
uint8_t ir_checksum(uint8_t addr, uint8_t afn, const uint8_t *data, uint16_t len);

#ifdef __cplusplus
}
#endif
