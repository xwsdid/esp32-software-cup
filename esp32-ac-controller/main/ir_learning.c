#include "ir_learning.h"

#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/uart.h"
#include "esp_log.h"

static const char *TAG = "IR_LEARN";

/* ================================================================
 *  UART 配置
 * ================================================================ */
#define IR_UART_PORT        UART_NUM_2
#define IR_UART_BUF_SIZE    (1024)

static int s_uart_port = IR_UART_PORT;

/* ================================================================
 *  校验和计算
 * ================================================================ */
uint8_t ir_checksum(uint8_t addr, uint8_t afn, const uint8_t *data, uint16_t len)
{
    uint32_t sum = addr + afn;
    for (uint16_t i = 0; i < len; i++) {
        sum += data[i];
    }
    return (uint8_t)(sum % 256);
}

/* ================================================================
 *  初始化
 * ================================================================ */
bool ir_init(int tx_pin, int rx_pin, int baud)
{
    uart_config_t uart_cfg = {
        .baud_rate  = baud,
        .data_bits  = UART_DATA_8_BITS,
        .parity     = UART_PARITY_DISABLE,
        .stop_bits  = UART_STOP_BITS_1,
        .flow_ctrl  = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };

    esp_err_t err;

    err = uart_driver_install(s_uart_port, IR_UART_BUF_SIZE,
                              IR_UART_BUF_SIZE, 0, NULL, 0);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "UART driver install failed: %d", err);
        return false;
    }

    err = uart_param_config(s_uart_port, &uart_cfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "UART param config failed: %d", err);
        return false;
    }

    err = uart_set_pin(s_uart_port, tx_pin, rx_pin,
                       UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "UART set pin failed: %d", err);
        return false;
    }

    /* 清空缓冲区 */
    uart_flush_input(s_uart_port);

    ESP_LOGI(TAG, "Initialized: TX=GPIO%d, RX=GPIO%d, Baud=%d",
             tx_pin, rx_pin, baud);
    return true;
}

/* ================================================================
 *  发送帧
 * ================================================================ */
bool ir_send_frame(uint8_t addr, uint8_t afn, const uint8_t *data, uint16_t len)
{
    /*
     *  帧格式:
     *  [HEADER(1)] [LENGTH(2 LE)] [ADDR(1)] [AFN(1)] [DATA(N)] [CHK(1)] [TAIL(1)]
    *  长度 = 1 + 2 + 1 + 1 + N + 1 + 1 = N + 7
     */

    uint16_t total_len = len + 7;   /* 总字节数 = 数据长度 + 7 个固定字段 */
    uint8_t chk = ir_checksum(addr, afn, data, len);

    uint8_t buf[IR_FRAME_MAX_LEN];
    uint16_t pos = 0;

    buf[pos++] = IR_FRAME_HEADER;                    /* 帧头 68H */
    buf[pos++] = (uint8_t)(total_len & 0xFF);        /* 长度 低字节 */
    buf[pos++] = (uint8_t)((total_len >> 8) & 0xFF);  /* 长度 高字节 */
    buf[pos++] = addr;                                /* 模块地址 */
    buf[pos++] = afn;                                 /* 功能码 */

    if (len > 0 && data != NULL) {
        memcpy(&buf[pos], data, len);
        pos += len;
    }

    buf[pos++] = chk;                                 /* 校验和 */
    buf[pos++] = IR_FRAME_TAIL;                       /* 帧尾 16H */

    int written = uart_write_bytes(s_uart_port, buf, pos);
    if (written < 0) {
        ESP_LOGE(TAG, "UART write error");
        return false;
    }

    /* 打印发送帧用于调试 */
    ESP_LOG_BUFFER_HEX(TAG, buf, pos);

    return true;
}

/* ================================================================
 *  接收帧 (状态机解析)
 * ================================================================ */
bool ir_recv_frame(ir_frame_t *frame, uint32_t timeout_ms)
{
    if (frame == NULL) return false;

    memset(frame, 0, sizeof(*frame));

    /*
     *  状态机:
     *  0 = 等待 HEADER (0x68)
     *  1 = 读取长度(2字节)
     *  2 = 读取剩余帧 (addr+afn+data+chk+tail)
     */

    uint8_t byte;
    int state = 0;
    uint16_t total_len = 0;
    uint8_t raw_buf[IR_FRAME_MAX_LEN];
    uint16_t buf_pos = 0;
    TickType_t start = xTaskGetTickCount();

    while (1) {
        /* 检查超时 */
        if ((xTaskGetTickCount() - start) * portTICK_PERIOD_MS >= timeout_ms) {
            return false;
        }

        int len = uart_read_bytes(s_uart_port, &byte, 1, pdMS_TO_TICKS(50));
        if (len <= 0) continue;

        switch (state) {
        case 0: /* 等待帧头 0x68 */
            if (byte == IR_FRAME_HEADER) {
                raw_buf[0] = byte;
                buf_pos = 1;
                state = 1;
                start = xTaskGetTickCount();  /* 重置超时 */
            }
            break;

        case 1: /* 读取长度 (2字节, 小端) */
            raw_buf[buf_pos++] = byte;
            if (buf_pos >= 3) {
                total_len = raw_buf[1] | ((uint16_t)raw_buf[2] << 8);
                if (total_len < 6 || total_len > IR_FRAME_MAX_LEN) {
                    /* 无效长度, 重新开始 */
                    ESP_LOGW(TAG, "Invalid frame length: %d", total_len);
                    state = 0;
                    buf_pos = 0;
                } else {
                    state = 2;
                }
            }
            break;

        case 2: /* 读取剩余: addr + afn + data + chk + tail */
            raw_buf[buf_pos++] = byte;

            /* 需要读取的总字节 = total_len，已经读了 buf_pos 个 */
            if (buf_pos >= total_len) {
                /* 帧接收完毕, 开始解析 */

                /* 校验帧尾 */
                if (raw_buf[total_len - 1] != IR_FRAME_TAIL) {
                    ESP_LOGW(TAG, "Invalid frame tail");
                    state = 0;
                    buf_pos = 0;
                    continue;
                }

                /* 提取各字段 */
                frame->addr = raw_buf[3];
                frame->afn  = raw_buf[4];
                frame->data_len = total_len - 7;  /* 减去 header+len(2)+addr+afn+chk+tail */

                if (frame->data_len > 0) {
                    memcpy(frame->data, &raw_buf[5], frame->data_len);
                }

                /* 校验校验和 */
                uint8_t expected_chk = ir_checksum(frame->addr, frame->afn,
                                                    frame->data, frame->data_len);
                uint8_t received_chk = raw_buf[total_len - 2];

                if (expected_chk != received_chk) {
                    ESP_LOGW(TAG, "Checksum mismatch: calc=%02X recv=%02X",
                             expected_chk, received_chk);
                    state = 0;
                    buf_pos = 0;
                    continue;
                }

                /* 打印接收帧用于调试 */
                ESP_LOG_BUFFER_HEX(TAG, raw_buf, total_len);

                return true;
            }
            break;
        }
    }
}

/* ================================================================
 *  发送命令并等待应答帧
 * ================================================================ */
int ir_send_cmd_wait_ack(uint8_t addr, uint8_t afn,
                         const uint8_t *data, uint16_t len,
                         uint32_t timeout_ms)
{
    if (!ir_send_frame(addr, afn, data, len)) {
        return 1;
    }

    ir_frame_t resp;
    if (!ir_recv_frame(&resp, timeout_ms)) {
        ESP_LOGE(TAG, "No response for AFN=%02X", afn);
        return 1;
    }

    /* 应答帧 AFN=01H，数据域第1字节是状态 */
    if (resp.afn == IR_AFN_ACK) {
        if (resp.data_len >= 1 && resp.data[0] == IR_STATUS_OK) {
            return 0;
        } else {
            ESP_LOGE(TAG, "ACK error status: %02X", resp.data_len > 0 ? resp.data[0] : 0xFF);
            return 1;
        }
    }

    /* 部分命令返回的不一定是 AFN=01H，也视为有效 */
    return 0;
}

/* ================================================================
 *  高级 API 实现
 * ================================================================ */

int ir_enter_learn(uint8_t index)
{
    if (index > 6) return 1;
    uint8_t data = index;
    ESP_LOGI(TAG, "Enter internal learn mode, index=%d", index);
    return ir_send_cmd_wait_ack(IR_ADDR_DEFAULT, IR_AFN_ENTER_LEARN,
                                &data, 1, 2000);
}

int ir_exit_learn(void)
{
    ESP_LOGI(TAG, "Exit internal learn mode");
    return ir_send_cmd_wait_ack(IR_ADDR_DEFAULT, IR_AFN_EXIT_LEARN,
                                NULL, 0, 2000);
}

int ir_send_stored_code(uint8_t index)
{
    if (index > 6) return 1;
    uint8_t data = index;
    ESP_LOGI(TAG, "Send stored code, index=%d", index);
    return ir_send_cmd_wait_ack(IR_ADDR_DEFAULT, IR_AFN_SEND_CODE,
                                &data, 1, 2000);
}

int ir_wait_learn_report(ir_report_t *report, uint32_t timeout_ms)
{
    if (report == NULL) return 1;

    ir_frame_t frame;
    if (!ir_recv_frame(&frame, timeout_ms)) {
        return 1;
    }

    if (frame.afn != IR_AFN_REPORT) {
        ESP_LOGW(TAG, "Expected report frame (AFN=02H), got AFN=%02X", frame.afn);
        return 1;
    }

    if (frame.data_len >= 3) {
        report->flag   = frame.data[0];
        report->index  = frame.data[1];
        report->status = frame.data[2];
        return 0;
    }

    return 1;
}

int ir_write_code(uint8_t index, const uint8_t *code, uint16_t len)
{
    if (index > 6 || code == NULL || len == 0 || len > IR_DATA_MAX_LEN) {
        return 1;
    }

    /* 数据域 = 1字节索引 + N字节编码 */
    uint8_t data[IR_DATA_MAX_LEN + 1];
    data[0] = index;
    memcpy(&data[1], code, len);

    ESP_LOGI(TAG, "Write code to index=%d, len=%d", index, len);
    return ir_send_cmd_wait_ack(IR_ADDR_DEFAULT, IR_AFN_WRITE_CODE,
                                data, len + 1, 3000);
}

int ir_read_code(uint8_t index, uint8_t *code, uint16_t max_len, uint16_t *out_len)
{
    if (index > 6 || code == NULL) return 1;

    uint8_t data = index;
    if (!ir_send_frame(IR_ADDR_DEFAULT, IR_AFN_READ_CODE, &data, 1)) {
        return 1;
    }

    ir_frame_t resp;
    if (!ir_recv_frame(&resp, 3000)) {
        return 1;
    }

    /*
     * 响应: data[0]=索引, data[1]=状态(0=成功), data[2..]=红外编码
     */
    if (resp.afn != IR_AFN_READ_CODE) {
        ESP_LOGE(TAG, "Expected AFN=18H, got %02X", resp.afn);
        return 1;
    }

    if (resp.data_len < 2 || resp.data[1] != 0) {
        ESP_LOGE(TAG, "Read code failed, index=%d", index);
        return 1;
    }

    uint16_t code_len = resp.data_len - 2;
    if (code_len > max_len) code_len = max_len;
    memcpy(code, &resp.data[2], code_len);
    if (out_len) *out_len = code_len;

    ESP_LOGI(TAG, "Read code from index=%d, len=%d", index, code_len);
    return 0;
}

int ir_set_poweron_send(uint8_t index, uint8_t enable)
{
    if (index > 6) return 1;
    uint8_t data[2] = { index, enable ? 1 : 0 };
    ESP_LOGI(TAG, "Set power-on send: index=%d, enable=%d", index, enable);
    return ir_send_cmd_wait_ack(IR_ADDR_DEFAULT, IR_AFN_SET_PWR_SEND,
                                data, 2, 2000);
}

int ir_get_poweron_send(uint8_t index, uint8_t *enable)
{
    if (index > 6 || enable == NULL) return 1;

    uint8_t data = index;
    if (!ir_send_frame(IR_ADDR_DEFAULT, IR_AFN_GET_PWR_SEND, &data, 1)) {
        return 1;
    }

    ir_frame_t resp;
    if (!ir_recv_frame(&resp, 2000)) return 1;

    if (resp.afn == IR_AFN_GET_PWR_SEND && resp.data_len >= 2) {
        *enable = resp.data[1];
        return 0;
    }

    return 1;
}

int ir_set_poweron_delay(uint16_t delay_sec)
{
    uint8_t data[2];
    data[0] = (uint8_t)(delay_sec & 0xFF);       /* 低字节 */
    data[1] = (uint8_t)((delay_sec >> 8) & 0xFF); /* 高字节 */

    ESP_LOGI(TAG, "Set power-on delay: %d sec", delay_sec);
    return ir_send_cmd_wait_ack(IR_ADDR_DEFAULT, IR_AFN_SET_PWR_DELAY,
                                data, 2, 2000);
}

int ir_get_poweron_delay(uint16_t *delay_sec)
{
    if (delay_sec == NULL) return 1;

    if (!ir_send_frame(IR_ADDR_DEFAULT, IR_AFN_GET_PWR_DELAY, NULL, 0)) {
        return 1;
    }

    ir_frame_t resp;
    if (!ir_recv_frame(&resp, 2000)) return 1;

    if (resp.afn == IR_AFN_GET_PWR_DELAY && resp.data_len >= 2) {
        *delay_sec = resp.data[0] | ((uint16_t)resp.data[1] << 8);
        return 0;
    }

    return 1;
}

int ir_reset(void)
{
    ESP_LOGI(TAG, "Reset module");
    return ir_send_cmd_wait_ack(IR_ADDR_DEFAULT, IR_AFN_RESET, NULL, 0, 2000);
}

int ir_format(void)
{
    ESP_LOGI(TAG, "Format module");
    return ir_send_cmd_wait_ack(IR_ADDR_DEFAULT, IR_AFN_FORMAT, NULL, 0, 2000);
}

int ir_set_addr(uint8_t new_addr)
{
    if (new_addr >= 0xFF) return 1;  /* 不能设为广播地址 */
    uint8_t data = new_addr;
    ESP_LOGI(TAG, "Set address to %02X", new_addr);
    return ir_send_cmd_wait_ack(IR_ADDR_DEFAULT, IR_AFN_SET_ADDR,
                                &data, 1, 2000);
}

int ir_get_addr(uint8_t *addr)
{
    if (addr == NULL) return 1;

    if (!ir_send_frame(IR_ADDR_DEFAULT, IR_AFN_GET_ADDR, NULL, 0)) {
        return 1;
    }

    ir_frame_t resp;
    if (!ir_recv_frame(&resp, 2000)) return 1;

    if (resp.afn == IR_AFN_GET_ADDR) {
        if (resp.data_len >= 1) {
            *addr = resp.data[0];
        } else {
            /* Some modules return the address only in the frame address field. */
            *addr = resp.addr;
        }
        return 0;
    }

    return 1;
}
