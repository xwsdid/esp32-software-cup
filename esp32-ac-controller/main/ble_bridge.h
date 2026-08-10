#ifndef BLE_BRIDGE_H
#define BLE_BRIDGE_H
#include <stdbool.h>
#include <stdint.h>
void ble_bridge_init(const char *device_id);
bool ble_bridge_on_command(const uint8_t *data, uint16_t len);
void ble_bridge_report_sensor(void);
#endif
