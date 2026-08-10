#ifndef BLE_PERIPHERAL_H
#define BLE_PERIPHERAL_H
#include <stdint.h>
#include <stdbool.h>

void ble_peripheral_init(void);

/* 应用层调用: 发送 device_event Notify */
void ble_notify_device_event(const uint8_t *data, uint16_t len);

/* 应用层注册回调: BLE 收到 business_cmd 时调用, 返回 true 表示已处理 */
typedef bool (*ble_business_cmd_cb_t)(const uint8_t *data, uint16_t len);
void ble_set_business_cmd_callback(ble_business_cmd_cb_t cb);

/* 应用层查询: 是否有 Central 已连接 */
bool ble_is_connected(void);

#endif
