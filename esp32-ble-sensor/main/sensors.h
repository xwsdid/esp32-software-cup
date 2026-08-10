#ifndef SENSORS_H
#define SENSORS_H
#include "main_config.h"

void pir_gpio_init(void);
uint8_t pir_read(void);
void gy30_i2c_init(void);
float gy30_read_lux(void);
void sht31_uart_init(void);
bool sht31_read(float *temperature, float *humidity);
void sensor_task(void *pvParameters);
#endif
