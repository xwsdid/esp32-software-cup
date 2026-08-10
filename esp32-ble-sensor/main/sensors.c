#include "sensors.h"
#include "ble_bridge.h"

/* ======================== SR602 PIR 传感器 ======================== */

void pir_gpio_init(void)
{
    gpio_config_t io_conf = {
        .pin_bit_mask = (1ULL << PIR_SENSOR_GPIO),
        .mode         = GPIO_MODE_INPUT,
        .pull_up_en   = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    gpio_config(&io_conf);
}

uint8_t pir_read(void)
{
    return (uint8_t)gpio_get_level(PIR_SENSOR_GPIO);
}

/* ======================== GY-30 BH1750 光照传感器 ======================== */

void gy30_i2c_init(void)
{
    i2c_master_bus_config_t bus_cfg = {
        .i2c_port   = I2C_NUM_0,
        .sda_io_num = GY30_I2C_SDA_PIN,
        .scl_io_num = GY30_I2C_SCL_PIN,
        .clk_source = I2C_CLK_SRC_DEFAULT,
        .glitch_ignore_cnt = 7,
        .flags.enable_internal_pullup = true,
    };
    ESP_ERROR_CHECK(i2c_new_master_bus(&bus_cfg, &s_i2c_bus));

    i2c_device_config_t dev_cfg = {
        .dev_addr_length = I2C_ADDR_BIT_LEN_7,
        .device_address  = GY30_SENSOR_ADDR,
        .scl_speed_hz    = GY30_I2C_FREQ_HZ,
    };
    ESP_ERROR_CHECK(i2c_master_bus_add_device(s_i2c_bus, &dev_cfg, &s_gy30_dev));

    ESP_LOGI(TAG_GY30, "GY30 OK SDA=%d SCL=%d", GY30_I2C_SDA_PIN, GY30_I2C_SCL_PIN);
}

float gy30_read_lux(void)
{
    uint8_t cmd_power_on = 0x01;
    uint8_t cmd_measure  = 0x10;

    esp_err_t ret = i2c_master_transmit(s_gy30_dev, &cmd_power_on, 1, 100);
    if (ret != ESP_OK) return -1.0f;

    ret = i2c_master_transmit(s_gy30_dev, &cmd_measure, 1, 100);
    if (ret != ESP_OK) return -1.0f;

    vTaskDelay(pdMS_TO_TICKS(200));

    uint8_t data_buf[2] = {0};
    ret = i2c_master_receive(s_gy30_dev, data_buf, 2, 100);
    if (ret != ESP_OK) return -1.0f;

    uint16_t raw = ((uint16_t)data_buf[0] << 8) | data_buf[1];
    return (float)raw / 1.2f;
}

/* ======================== SHT31 温湿度传感器 (UART) ======================== */

/**
 * @brief 初始化 SHT31 UART 并切换为手动模式
 */
void sht31_uart_init(void)
{
    uart_config_t uart_config = {
        .baud_rate  = SHT31_UART_BAUD_RATE,
        .data_bits  = UART_DATA_8_BITS,
        .parity     = UART_PARITY_DISABLE,
        .stop_bits  = UART_STOP_BITS_1,
        .flow_ctrl  = UART_HW_FLOWCTRL_DISABLE,
    };
    uart_param_config(SHT31_UART_PORT, &uart_config);
    uart_set_pin(SHT31_UART_PORT, SHT31_UART_TX_PIN, SHT31_UART_RX_PIN,
                 UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
    uart_driver_install(SHT31_UART_PORT, 512, 0, 0, NULL, 0);

    /* 发送 Hand\r\n 切换为手动模式, 停止自动上报 */
    vTaskDelay(pdMS_TO_TICKS(500));  /* 等待模块稳定 */
    const char *cmd_hand = "Hand\r\n";
    uart_write_bytes(SHT31_UART_PORT, cmd_hand, strlen(cmd_hand));
    vTaskDelay(pdMS_TO_TICKS(200));
    /* 清空可能收到的 "OK\r\n" 回复 */
    uint8_t flush_buf[32];
    uart_read_bytes(SHT31_UART_PORT, flush_buf, sizeof(flush_buf), pdMS_TO_TICKS(100));

#if SHT31_DEBUG_LOG
    ESP_LOGI(TAG_SHT31, "UART%d 初始化完成 (RX=GPIO%d, TX=GPIO%d, 波特率=%d, 手动模式)",
             SHT31_UART_PORT, SHT31_UART_RX_PIN, SHT31_UART_TX_PIN, SHT31_UART_BAUD_RATE);
#endif
}

/**
 * @brief 解析 SHT31 ASCII 字符串
 *
 * 模块自动上报格式 (ASCII + \r\n):
 *   R:xxx.xRH yyy.yC\r\n
 *
 * 示例: R:070.0RH 032.4C\r\n
 *   → 湿度 70.0%RH, 温度 32.4°C
 *
 * 字段固定: R后3位整数+1位小数, RH后空格+3位整数+1位小数+C
 *
 * @param[in]  buf         接收到的原始数据
 * @param[in]  len         数据长度
 * @param[out] temperature 解析出的温度 (°C)
 * @param[out] humidity    解析出的湿度 (%RH)
 * @return true 解析成功, false 解析失败
 */
bool sht31_parse_frame(const uint8_t *buf, uint16_t len,
                               float *temperature, float *humidity)
{
#if SHT31_DEBUG_LOG
    ESP_LOGI(TAG_SHT31, "解析: len=%d, buf[0..17]=%02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
             len, buf[0],buf[1],buf[2],buf[3],buf[4],buf[5],buf[6],buf[7],
             buf[8],buf[9],buf[10],buf[11],buf[12],buf[13],buf[14],buf[15],
             len>16?buf[16]:0xFF, len>17?buf[17]:0xFF);
#endif

    /* 在缓冲区中查找 "R:" 起始标志 */
    for (int i = 0; i + 15 <= len; i++) {
        if (buf[i] != 'R' || buf[i + 1] != ':') {
            continue;
        }

#if SHT31_DEBUG_LOG
        ESP_LOGI(TAG_SHT31, "找到R: at %d, 校验: buf[%d]=%02X(R?) buf[%d]=%02X(H?) buf[%d]=%02X(SP?) buf[%d]=%02X(C?)",
                 i, i+7, buf[i+7], i+8, buf[i+8], i+9, buf[i+9], i+15, buf[i+15]);
#endif

        /* 期望格式: R:xxx.xRH yyy.yC\r\n  (共16字节) */
        /* 验证关键位置字符: R在i+7, H在i+8, 空格在i+9, C在i+15 */
        if (buf[i + 7] != 'R' || buf[i + 8] != 'H' ||
            buf[i + 9] != ' ' || buf[i + 15] != 'C') {
#if SHT31_DEBUG_LOG
            ESP_LOGW(TAG_SHT31, "格式校验失败, 跳过");
#endif
            continue;
        }

        /* 提取湿度字符串 (xxx.x), 位置 i+2 ~ i+6 (5字符) */
        char hum_str[6] = {0};
        memcpy(hum_str, &buf[i + 2], 5);
        hum_str[5] = '\0';

        /* 提取温度字符串 (yyy.y), 位置 i+10 ~ i+14 (5字符) */
        char temp_str[6] = {0};
        memcpy(temp_str, &buf[i + 10], 5);
        temp_str[5] = '\0';

        *humidity    = strtof(hum_str,  NULL);
        *temperature = strtof(temp_str, NULL);

#if SHT31_DEBUG_LOG
        ESP_LOGI(TAG_SHT31, "提取: hum_str=%s -> %.1f, temp_str=%s -> %.1f",
                 hum_str, *humidity, temp_str, *temperature);
#endif

        /* 合理性检查 */
#if SHT31_DEBUG_LOG
        if (*temperature >= -40.0f && *temperature <= 80.0f &&
            *humidity >= 0.0f && *humidity <= 100.0f) {
            ESP_LOGI(TAG_SHT31, "解析成功!");
            return true;
        }
        ESP_LOGW(TAG_SHT31, "合理性检查失败: T=%.1f H=%.1f", *temperature, *humidity);
#else
        if (*temperature >= -40.0f && *temperature <= 80.0f &&
            *humidity >= 0.0f && *humidity <= 100.0f) {
            return true;
        }
#endif
    }

#if SHT31_DEBUG_LOG
    ESP_LOGW(TAG_SHT31, "未找到有效帧");
#endif
    return false;
}

/**
 * @brief 轮询读取 SHT31 温湿度
 *
 * 发送 Read\r\n 命令, 等待模块回复 R:xxx.xRH yyy.yC\r\n
 * 轮询间隔与 SENSOR_READ_INTERVAL_MS 一致
 *
 * @param[out] temperature 解析出的温度 (°C)
 * @param[out] humidity    解析出的湿度 (%RH)
 * @return true 读取并解析成功, false 失败
 */
bool sht31_read(float *temperature, float *humidity)
{
    /* 1. 清空接收缓冲区, 避免残留旧数据 */
    uint8_t flush_buf[64];
    uart_read_bytes(SHT31_UART_PORT, flush_buf, sizeof(flush_buf), pdMS_TO_TICKS(50));

    /* 2. 发送 Read 命令 */
    const char *cmd_read = "Read\r\n";
    uart_write_bytes(SHT31_UART_PORT, cmd_read, strlen(cmd_read));

    /* 3. 等待回复 (最多 500ms) */
    uint8_t rx_buf[64];
    int len = uart_read_bytes(SHT31_UART_PORT, rx_buf, sizeof(rx_buf),
                              pdMS_TO_TICKS(500));
    if (len <= 0) {
#if SHT31_DEBUG_LOG
        ESP_LOGW(TAG_SHT31, "SHT31 无响应");
#endif
        return false;
    }

    /* 打印原始数据便于调试 */
#if SHT31_DEBUG_LOG
    char hex_str[128] = {0};
    for (int i = 0; i < len && i < 32; i++) {
        snprintf(hex_str + i * 3, sizeof(hex_str) - i * 3, "%02X ", rx_buf[i]);
    }
    ESP_LOGI(TAG_SHT31, "收到 %d 字节: [%s]", len, hex_str);
#endif

    /* 4. 解析 ASCII 帧 R:xxx.xRH yyy.yC */
    return sht31_parse_frame(rx_buf, len, temperature, humidity);
}

/* ======================== 传感器采集任务 ======================== */

/**
 * @brief 传感器采集任务 (SR602 PIR + GY-30 光照 + SHT31 温湿度)
 *
 * 所有传感器的读取均在此任务中完成
 */
void sensor_task(void *pvParameters)
{
    ESP_LOGI(TAG_SR602, "传感器启动 PIR=GPIO%d GY30=SDA%d/SCL%d SHT31=UART%d",
             PIR_SENSOR_GPIO, GY30_I2C_SDA_PIN, GY30_I2C_SCL_PIN, SHT31_UART_PORT);

    int  last_pir = -1;
    int  report_tick = 0;

    while (1) {
        /* ---- 1. 读取 SR602 PIR 状态 ---- */
        uint8_t level = pir_read();
        dbg_uart_printf("[SR602] 数字量: %s\r\n", level ? "有人" : "无人");

        /* ---- 2. 读取 GY-30 光照度 ---- */
        float lux = gy30_read_lux();
        if (lux >= 0.0f) {
            dbg_uart_printf("[GY30] 光照度: %.1f lux\r\n", lux);
        } else {
            ESP_LOGW(TAG_GY30, "GY-30 读取失败");
            lux = 0.0f;
        }

        /* ---- 3. 读取 SHT31 温湿度 ---- */
        float temp = 0.0f, hum = 0.0f;
        if (sht31_read(&temp, &hum)) {
            dbg_uart_printf("[SHT31] 温度: %.1f °C, 湿度: %.1f %%RH\r\n", temp, hum);
        }

        /* ---- 4. 统一更新系统数据 ---- */
        if (xSemaphoreTake(s_sys_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
            s_sys_data.pir_detected = level;
            s_sys_data.light_lux    = lux;
            s_sys_data.temperature  = temp;
            s_sys_data.humidity     = hum;
            s_sys_data.timestamp    = xTaskGetTickCount();
            xSemaphoreGive(s_sys_mutex);
        }

        /* ---- 5. BLE 传感器上报 (周期 3s + PIR 变化即时) ---- */
        report_tick++;
        bool pir_changed = (last_pir >= 0 && (int)level != last_pir);
        /* 必须 <2s, 否则 BLE supervision_timeout=2.56s 会断开 */
        if (pir_changed || report_tick >= 2) {
            ble_bridge_report_sensor(temp, hum, (int)level, lux);
            if (pir_changed) report_tick = 0;
        }
        if (pir_changed) last_pir = (int)level;
        if (last_pir < 0) last_pir = (int)level;

        vTaskDelay(pdMS_TO_TICKS(SENSOR_READ_INTERVAL_MS));
    }
}