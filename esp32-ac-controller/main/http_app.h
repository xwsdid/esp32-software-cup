/**
 * @file  http_app.h
 * @brief HTTP 数据上报任务
 */
#ifndef HTTP_APP_H
#define HTTP_APP_H
#include "main_config.h"

#if PROTO_ENABLE_HTTP
void http_task(void *pvParameters);
#endif

#endif
