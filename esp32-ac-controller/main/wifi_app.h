#ifndef WIFI_APP_H
#define WIFI_APP_H
#include "main_config.h"

void wifi_init_sta(void);
void wifi_event_handler(void *arg, esp_event_base_t base, int32_t event_id, void *event_data);
#endif
