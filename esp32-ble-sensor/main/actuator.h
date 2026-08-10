#ifndef ACTUATOR_H
#define ACTUATOR_H
#include "main_config.h"

void led_gpio_init(void);
void actuator_task(void *pvParameters);
#endif
