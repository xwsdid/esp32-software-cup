#ifndef BLE_BRIDGE_H
#define BLE_BRIDGE_H
#include <stdbool.h>
#include <stdint.h>

/* 初始化 BLE 桥接: 注册 business_cmd 回调 */
void ble_bridge_init(const char *device_id);

/* business_cmd 回调 (由 ble_peripheral 调用) */
bool ble_bridge_on_command(const uint8_t *data, uint16_t len);

/* 构建 ACK → 加密 → device_event Notify */
void ble_bridge_send_response(const char *cmd, bool ok, int seq, const char *msg);

/* BLE 传感器主动上报: 温湿度/PIR/光照 (烟雾水浸在另一板) */
void ble_bridge_report_sensor(float temp, float hum, int pir, float lux);

#endif
