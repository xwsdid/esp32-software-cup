#ifndef MQTT_APP_H
#define MQTT_APP_H
#include "main_config.h"

void mqtt_task(void *pvParameters);
void mqtt_event_handler(void *arg, esp_event_base_t base, int32_t event_id, void *event_data);
#endif
