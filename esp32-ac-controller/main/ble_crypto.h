#ifndef BLE_CRYPTO_H
#define BLE_CRYPTO_H
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define BLE_AES_KEY_LEN  32
#define BLE_SM4_KEY_LEN  16
#define BLE_IV_LEN       12
#define BLE_TAG_LEN      16

void ble_crypto_init(const char *device_id);
bool ble_crypto_ready(void);
int  ble_crypto_epoch(void);
void ble_crypto_do_ecdh(const char *pub_b64, int epoch);
void ble_crypto_activate(void);
void ble_crypto_reset(void);
int  ble_crypto_get_pubkey_b64(char *out, size_t sz);

bool ble_crypto_sm4_decrypt(const uint8_t *ct, size_t ct_len, const uint8_t *iv, const uint8_t *tag, uint8_t *pt, size_t *pt_len);
int  ble_crypto_sm4_encrypt(const uint8_t *pt, size_t pt_len, uint8_t *out, size_t out_size);
bool ble_crypto_aes_decrypt(const uint8_t *ct, size_t ct_len, const uint8_t *iv, const uint8_t *tag, uint8_t *pt, size_t *pt_len);
int  ble_crypto_aes_encrypt(const uint8_t *pt, size_t pt_len, uint8_t *out, size_t out_size);

#define ble_crypto_decrypt ble_crypto_sm4_decrypt
#define ble_crypto_encrypt ble_crypto_sm4_encrypt
#endif
