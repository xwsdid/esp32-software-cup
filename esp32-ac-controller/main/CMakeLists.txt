idf_component_register(SRCS "alarm.c" "ir_learning.c" "pairing.c" "main.c" "wifi_app.c" "mqtt_app.c" "http_app.c" "crypto_layer.c" "key_layer.c" "stepper.c" "ble_peripheral.c" "ble_bridge.c" "ble_crypto.c"
                    INCLUDE_DIRS "."
                    REQUIRES esp_driver_gpio esp_driver_uart esp_adc
                             esp_driver_usb_serial_jtag
                             esp_wifi esp_netif esp_event nvs_flash
                             mqtt mbedtls esp_http_client
                             bt
                             esp_coex
                             esp_driver_ledc)
