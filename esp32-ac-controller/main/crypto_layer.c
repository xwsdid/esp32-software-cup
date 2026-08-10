/**
 * @file  crypto_layer.c
 * @brief 数据层加密实现 — 基于 PSA Crypto (mbedtls 4.x / ESP-IDF v6.x)
 *        支持 AES-256-GCM + SM4-GCM
 */
#include "crypto_layer.h"
#include "esp_log.h"
#include <string.h>

#include "psa/crypto.h"

static const char *TAG_CRYPTO = "CRYPTO";

/* PSA 密钥 ID (提前导入, 全局复用, 避免每次加密都 import) */
static psa_key_id_t s_aes_key_id = 0;
static bool s_psa_initialized = false;
static bool g_sm4_mode = CRYPTO_USE_SM4_DEFAULT;  /* 运行时切换 */

void crypto_set_mode(bool use_sm4) { g_sm4_mode = use_sm4; }
bool crypto_get_mode(void)           { return g_sm4_mode; }

/* 动态密钥 (ECDH 协商后更新) */
static uint8_t g_dynamic_sm4_key[16] = {
    0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
    0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10,
};  /* 初始值 = 测试密钥, ECDH 协商后覆盖 */

static uint8_t g_static_sm4_key[16] = {
    0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
    0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10,
};  /* 静态密钥备份 (切换瞬间兜底) */

/* 前置声明 (定义在后面) */
bool sm4_gcm_decrypt(const uint8_t *key, const uint8_t *ct, size_t ct_len,
                      const uint8_t *iv, const uint8_t *tag, uint8_t *pt);

/* 解密容错: 动态key失败→静态key→对端算法动态→对端算法静态 */
bool crypto_decrypt_fallback(const uint8_t *ct, size_t ct_len,
                             const uint8_t *iv, size_t iv_len,
                             const uint8_t *tag, size_t tag_len,
                             uint8_t *pt, size_t *pt_len) {
    /* 1. 当前算法 + 动态key */
    if (crypto_aes_decrypt(ct, ct_len, iv, iv_len, tag, tag_len, pt, pt_len))
        return true;

    /* 2. 当前算法 + 静态key */
    ESP_LOGW(TAG_CRYPTO, "动态key失败, 尝试当前算法静态key");
    if (g_sm4_mode) {
        if (sm4_gcm_decrypt(g_static_sm4_key, ct, ct_len, iv, tag, pt)) {
            *pt_len = ct_len;
            ESP_LOGW(TAG_CRYPTO, "SM4 static fallback OK");
            return true;
        }
    }

    /* 3. 对端算法 + 动态key */
    ESP_LOGW(TAG_CRYPTO, "尝试对端算法...");
    {
        bool saved = g_sm4_mode;
        g_sm4_mode = !saved;
        bool ok = crypto_aes_decrypt(ct, ct_len, iv, iv_len, tag, tag_len, pt, pt_len);
        g_sm4_mode = saved;  /* 无论成败都恢复 */
        if (ok) {
            *pt_len = ct_len;
            ESP_LOGW(TAG_CRYPTO, "%s dynamic fallback OK", saved ? "AES" : "SM4");
            return true;
        }
    }

    return false;
}

void crypto_update_aes_key(const uint8_t new_key[32]) {
    if (s_aes_key_id != 0) {
        psa_destroy_key(s_aes_key_id);
        s_aes_key_id = 0;
    }
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_GCM);
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 256);
    psa_import_key(&attr, new_key, 32, &s_aes_key_id);
    ESP_LOGI(TAG_CRYPTO, "AES 密钥已更新 (ECHD 动态)");
}

void crypto_update_sm4_key(const uint8_t new_key[16]) {
    memcpy(g_dynamic_sm4_key, new_key, 16);
    ESP_LOGI(TAG_CRYPTO, "SM4 密钥已更新 (ECDH 动态)");
}

const uint8_t* crypto_get_dynamic_sm4_key(void) { return g_dynamic_sm4_key; }

/* ======================== PSA 初始化 ======================== */

static bool crypto_psa_init(void)
{
    if (s_psa_initialized) return true;

    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG_CRYPTO, "PSA Crypto 初始化失败: %d", (int)status);
        return false;
    }
    s_psa_initialized = true;
    return true;
}

/* ======================== AES-256-GCM ======================== */

static void crypto_aes_ensure_key(void)
{
    if (s_aes_key_id != 0) return;

    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_GCM);
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, AES_KEY_LEN * 8);

    psa_status_t status = psa_import_key(&attr,
                                         CRYPTO_AES_KEY, AES_KEY_LEN,
                                         &s_aes_key_id);
    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG_CRYPTO, "AES 密钥导入失败: %d", (int)status);
    } else {
        ESP_LOGI(TAG_CRYPTO, "AES-256 密钥已导入 (PSA ID=%lu)", s_aes_key_id);
    }
}

bool crypto_aes_encrypt(const uint8_t *plaintext,  size_t  plain_len,
                        const uint8_t *iv,          size_t  iv_len,
                        uint8_t       *ciphertext, size_t *cipher_len,
                        uint8_t       *tag,         size_t  tag_len)
{
    if (g_sm4_mode)
        return crypto_sm4_encrypt(plaintext, plain_len, iv, iv_len,
                                  ciphertext, cipher_len, tag, tag_len);
    if (!crypto_psa_init()) return false;
    crypto_aes_ensure_key();
    if (s_aes_key_id == 0) return false;

    size_t out_len = 0;
    psa_status_t status = psa_aead_encrypt(
        s_aes_key_id,
        PSA_ALG_GCM,
        iv, iv_len,
        NULL, 0,            /* 无额外 AAD */
        plaintext, plain_len,
        ciphertext, plain_len + tag_len, &out_len);

    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG_CRYPTO, "AES GCM 加密失败: %d", (int)status);
        return false;
    }
    /* PSA 输出格式: [ciphertext][tag], 需要拆开 */
    *cipher_len = plain_len;
    memcpy(tag, ciphertext + plain_len, tag_len);
    return true;
}

bool crypto_aes_decrypt(const uint8_t *ciphertext, size_t  cipher_len,
                        const uint8_t *iv,          size_t  iv_len,
                        const uint8_t *tag,         size_t  tag_len,
                        uint8_t       *plaintext,  size_t *plain_len)
{
    if (g_sm4_mode)
        return crypto_sm4_decrypt(ciphertext, cipher_len, iv, iv_len,
                                  tag, tag_len, plaintext, plain_len);
    if (!crypto_psa_init()) return false;
    crypto_aes_ensure_key();
    if (s_aes_key_id == 0) return false;

    /* PSA 需要把 [ciphertext][tag] 拼在一起输入 */
    uint8_t combined[512];
    if (cipher_len + tag_len > sizeof(combined)) return false;
    memcpy(combined, ciphertext, cipher_len);
    memcpy(combined + cipher_len, tag, tag_len);

    size_t out_len = 0;
    psa_status_t status = psa_aead_decrypt(
        s_aes_key_id,
        PSA_ALG_GCM,
        iv, iv_len,
        NULL, 0,
        combined, cipher_len + tag_len,
        plaintext, cipher_len, &out_len);

    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG_CRYPTO, "AES GCM 解密/认证失败: %d", (int)status);
        return false;
    }
    *plain_len = out_len;
    return true;
}


/* ======================== SM4 S-Box ======================== */
static const uint8_t SM4_SBOX[256] = {
    0xD6,0x90,0xE9,0xFE,0xCC,0xE1,0x3D,0xB7,0x16,0xB6,0x14,0xC2,0x28,0xFB,0x2C,0x05,
    0x2B,0x67,0x9A,0x76,0x2A,0xBE,0x04,0xC3,0xAA,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
    0x9C,0x42,0x50,0xF4,0x91,0xEF,0x98,0x7A,0x33,0x54,0x0B,0x43,0xED,0xCF,0xAC,0x62,
    0xE4,0xB3,0x1C,0xA9,0xC9,0x08,0xE8,0x95,0x80,0xDF,0x94,0xFA,0x75,0x8F,0x3F,0xA6,
    0x47,0x07,0xA7,0xFC,0xF3,0x73,0x17,0xBA,0x83,0x59,0x3C,0x19,0xE6,0x85,0x4F,0xA8,
    0x68,0x6B,0x81,0xB2,0x71,0x64,0xDA,0x8B,0xF8,0xEB,0x0F,0x4B,0x70,0x56,0x9D,0x35,
    0x1E,0x24,0x0E,0x5E,0x63,0x58,0xD1,0xA2,0x25,0x22,0x7C,0x3B,0x01,0x21,0x78,0x87,
    0xD4,0x00,0x46,0x57,0x9F,0xD3,0x27,0x52,0x4C,0x36,0x02,0xE7,0xA0,0xC4,0xC8,0x9E,
    0xEA,0xBF,0x8A,0xD2,0x40,0xC7,0x38,0xB5,0xA3,0xF7,0xF2,0xCE,0xF9,0x61,0x15,0xA1,
    0xE0,0xAE,0x5D,0xA4,0x9B,0x34,0x1A,0x55,0xAD,0x93,0x32,0x30,0xF5,0x8C,0xB1,0xE3,
    0x1D,0xF6,0xE2,0x2E,0x82,0x66,0xCA,0x60,0xC0,0x29,0x23,0xAB,0x0D,0x53,0x4E,0x6F,
    0xD5,0xDB,0x37,0x45,0xDE,0xFD,0x8E,0x2F,0x03,0xFF,0x6A,0x72,0x6D,0x6C,0x5B,0x51,
    0x8D,0x1B,0xAF,0x92,0xBB,0xDD,0xBC,0x7F,0x11,0xD9,0x5C,0x41,0x1F,0x10,0x5A,0xD8,
    0x0A,0xC1,0x31,0x88,0xA5,0xCD,0x7B,0xBD,0x2D,0x74,0xD0,0x12,0xB8,0xE5,0xB4,0xB0,
    0x89,0x69,0x97,0x4A,0x0C,0x96,0x77,0x7E,0x65,0xB9,0xF1,0x09,0xC5,0x6E,0xC6,0x84,
    0x18,0xF0,0x7D,0xEC,0x3A,0xDC,0x4D,0x20,0x79,0xEE,0x5F,0x3E,0xD7,0xCB,0x39,0x48,
};

/* ======================== SM4 密钥扩展 ======================== */
static const uint32_t SM4_FK[4] = {
    0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC
};
static const uint32_t SM4_CK[32] = {
    0x00070E15,0x1C232A31,0x383F464D,0x545B6269,
    0x70777E85,0x8C939AA1,0xA8AFB6BD,0xC4CBD2D9,
    0xE0E7EEF5,0xFC030A11,0x181F262D,0x343B4249,
    0x50575E65,0x6C737A81,0x888F969D,0xA4ABB2B9,
    0xC0C7CED5,0xDCE3EAF1,0xF8FF060D,0x141B2229,
    0x30373E45,0x4C535A61,0x686F767D,0x848B9299,
    0xA0A7AEB5,0xBCC3CAD1,0xD8DFE6ED,0xF4FB0209,
    0x10171E25,0x2C333A41,0x484F565D,0x646B7279
};

static uint32_t sm4_rotl(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

static uint8_t sm4_sbox(uint8_t a) {
    return SM4_SBOX[a];
}

static void sm4_key_expand(const uint8_t *key, uint32_t *rk) {
    uint32_t K[4];
    for (int i = 0; i < 4; i++) {
        K[i] = ((uint32_t)key[4*i] << 24) | ((uint32_t)key[4*i+1] << 16) |
               ((uint32_t)key[4*i+2] << 8) | (uint32_t)key[4*i+3];
        K[i] ^= SM4_FK[i];
    }

    for (int i = 0; i < 32; i++) {
        uint32_t B = K[1] ^ K[2] ^ K[3] ^ SM4_CK[i];
        uint8_t b[4] = { (uint8_t)(B >> 24), (uint8_t)(B >> 16),
                          (uint8_t)(B >> 8), (uint8_t)B };
        uint32_t T = ((uint32_t)sm4_sbox(b[0]) << 24) |
                     ((uint32_t)sm4_sbox(b[1]) << 16) |
                     ((uint32_t)sm4_sbox(b[2]) << 8)  |
                     (uint32_t)sm4_sbox(b[3]);
        T ^= sm4_rotl(T, 13) ^ sm4_rotl(T, 23);
        rk[i] = K[0] ^ T;  /* rk[i] = K[i] ^ T'(K[i+1]^K[i+2]^K[i+3]^CK[i]) */
        K[0] = K[1]; K[1] = K[2]; K[2] = K[3]; K[3] = rk[i];
    }
}

static void sm4_encrypt_block(const uint32_t *rk, const uint8_t *in,
                               uint8_t *out) {
    uint32_t X[36];
    for (int i = 0; i < 4; i++) {
        X[i] = ((uint32_t)in[4*i] << 24) | ((uint32_t)in[4*i+1] << 16) |
               ((uint32_t)in[4*i+2] << 8) | (uint32_t)in[4*i+3];
    }

    for (int i = 0; i < 32; i++) {
        uint32_t B = X[i+1] ^ X[i+2] ^ X[i+3] ^ rk[i];
        uint8_t b[4] = { (uint8_t)(B >> 24), (uint8_t)(B >> 16),
                          (uint8_t)(B >> 8), (uint8_t)B };
        uint32_t T = ((uint32_t)sm4_sbox(b[0]) << 24) |
                     ((uint32_t)sm4_sbox(b[1]) << 16) |
                     ((uint32_t)sm4_sbox(b[2]) << 8)  |
                     (uint32_t)sm4_sbox(b[3]);
        T ^= sm4_rotl(T, 2) ^ sm4_rotl(T, 10) ^
              sm4_rotl(T, 18) ^ sm4_rotl(T, 24);
        X[i+4] = X[i] ^ T;
    }

    for (int i = 0; i < 4; i++) {
        uint32_t v = X[35 - i];
        out[4*i]   = (uint8_t)(v >> 24);
        out[4*i+1] = (uint8_t)(v >> 16);
        out[4*i+2] = (uint8_t)(v >> 8);
        out[4*i+3] = (uint8_t)v;
    }
}

/* ======================== GCM (GF(2^128) / GHASH) ======================== */

static void gf128_mul(uint8_t *X, const uint8_t *Y) {
    int i, j;
    unsigned char lo, rem;
    unsigned char Z[16];
    unsigned char V[16];
    memcpy(V, Y, 16);
    memset(Z, 0, 16);
    for (i = 0; i < 128; i++) {
        if (X[i >> 3] & (1 << (i & 7))) {
            for (j = 0; j < 16; j++)
                Z[j] ^= V[j];
        }
        lo = (unsigned char)(V[15] & 1);
        for (j = 15; j > 0; j--) {
            rem = (unsigned char)(V[j - 1] & 1);
            V[j] = (unsigned char)((V[j] >> 1) | (rem << 7));
        }
        V[0] = (unsigned char)(V[0] >> 1);
        if (lo) {
            V[0] = (unsigned char)(V[0] ^ 0xE1);
        }
    }
    memcpy(X, Z, 16);
}

static void bit_reflect_block(uint8_t *blk) {
    for (int i = 0; i < 16; i++) {
        uint8_t b = blk[i], r = 0;
        for (int k = 0; k < 8; k++)
            if (b & (1 << k)) r |= (1 << (7 - k));
        blk[i] = r;
    }
}

static void ghash(const uint8_t *H, const uint8_t *A, size_t a_len,
                  const uint8_t *C, size_t c_len, uint8_t *Y) {
    memset(Y, 0, 16);

    /* Process AAD (reflect before mul, output already un-reflected) */
    for (size_t i = 0; i < a_len; i += 16) {
        size_t blk = (a_len - i < 16) ? (a_len - i) : 16;
        uint8_t tmp[16] = {0};
        memcpy(tmp, A + i, blk);
        for (int j = 0; j < 16; j++) Y[j] ^= tmp[j];
        bit_reflect_block(Y);
        gf128_mul(Y, H);
    }

    /* Process ciphertext */
    for (size_t i = 0; i < c_len; i += 16) {
        size_t blk = (c_len - i < 16) ? (c_len - i) : 16;
        uint8_t tmp[16] = {0};
        memcpy(tmp, C + i, blk);
        for (int j = 0; j < 16; j++) Y[j] ^= tmp[j];
        bit_reflect_block(Y);
        gf128_mul(Y, H);
    }

    /* Process lengths: [a_len*8]64 || [c_len*8]64 */
    uint8_t len_block[16] = {0};
    uint64_t a_bits = (uint64_t)a_len * 8;
    uint64_t c_bits = (uint64_t)c_len * 8;
    len_block[0]  = (uint8_t)(a_bits >> 56);
    len_block[1]  = (uint8_t)(a_bits >> 48);
    len_block[2]  = (uint8_t)(a_bits >> 40);
    len_block[3]  = (uint8_t)(a_bits >> 32);
    len_block[4]  = (uint8_t)(a_bits >> 24);
    len_block[5]  = (uint8_t)(a_bits >> 16);
    len_block[6]  = (uint8_t)(a_bits >> 8);
    len_block[7]  = (uint8_t)a_bits;
    len_block[8]  = (uint8_t)(c_bits >> 56);
    len_block[9]  = (uint8_t)(c_bits >> 48);
    len_block[10] = (uint8_t)(c_bits >> 40);
    len_block[11] = (uint8_t)(c_bits >> 32);
    len_block[12] = (uint8_t)(c_bits >> 24);
    len_block[13] = (uint8_t)(c_bits >> 16);
    len_block[14] = (uint8_t)(c_bits >> 8);
    len_block[15] = (uint8_t)c_bits;

    for (int j = 0; j < 16; j++) Y[j] ^= len_block[j];
    bit_reflect_block(Y);
    gf128_mul(Y, H);
}

/* ======================== SM4-GCM 加密/解密 ======================== */

void sm4_gcm_encrypt(const uint8_t *key,
                     const uint8_t *plaintext, size_t plain_len,
                     const uint8_t *iv,
                     uint8_t *ciphertext,
                     uint8_t *tag) {
    uint32_t rk[32];
    sm4_key_expand(key, rk);

    /* 1. 计算 H = SM4(0^128) */
    uint8_t zero[16] = {0};
    uint8_t H[16];
    sm4_encrypt_block(rk, zero, H);

    /* 2. 构造初始计数器: J0 = IV || 0^31 || 1 */
    uint8_t J0[16] = {0};
    memcpy(J0, iv, 12);
    J0[15] = 1;

    /* 3. 加密 J0 → 用于 XOR 到最终 TAG */
    uint8_t enc_J0[16];
    sm4_encrypt_block(rk, J0, enc_J0);

    /* 4. CTR 模式加密: 第一块 counter = inc32(J0) */
    uint8_t counter[16];
    memcpy(counter, J0, 16);
    /* inc32: 递增最后 4 字节 (big-endian) */
    for (int j = 15; j >= 12; j--) {
        counter[j]++;
        if (counter[j] != 0) break;
    }
    for (size_t i = 0; i < plain_len; i += 16) {
        if (i > 0) {
            for (int j = 15; j >= 12; j--) {
                counter[j]++;
                if (counter[j] != 0) break;
            }
        }
        uint8_t enc_ctr[16];
        sm4_encrypt_block(rk, counter, enc_ctr);
        size_t blk = (plain_len - i < 16) ? (plain_len - i) : 16;
        for (size_t j = 0; j < blk; j++)
            ciphertext[i + j] = plaintext[i + j] ^ enc_ctr[j];
    }

    /* 5. GHASH → TAG */
    uint8_t gh[16];
    ghash(H, NULL, 0, ciphertext, plain_len, gh);
    for (int j = 0; j < 16; j++) tag[j] = gh[j] ^ enc_J0[j];
}

bool sm4_gcm_decrypt(const uint8_t *key,
                     const uint8_t *ciphertext, size_t cipher_len,
                     const uint8_t *iv,
                     const uint8_t *tag,
                     uint8_t *plaintext) {
    uint32_t rk[32];
    sm4_key_expand(key, rk);

    /* 1. 计算 H */
    uint8_t zero[16] = {0};
    uint8_t H[16];
    sm4_encrypt_block(rk, zero, H);

    /* 2. J0, enc_J0 */
    uint8_t J0[16] = {0};
    memcpy(J0, iv, 12);
    J0[15] = 1;
    uint8_t enc_J0[16];
    sm4_encrypt_block(rk, J0, enc_J0);

    /* 3. 验证 TAG */
    uint8_t expected_tag[16];
    ghash(H, NULL, 0, ciphertext, cipher_len, expected_tag);
    for (int j = 0; j < 16; j++) expected_tag[j] ^= enc_J0[j];

    if (memcmp(expected_tag, tag, 16) != 0) {
        printf("SM4-GCM TAG mismatch! ct_len=%d\n", (int)cipher_len);
        printf("  key: "); for(int i=0;i<16;i++) printf("%02X",key[i]); printf("\n");
        printf("  iv:  "); for(int i=0;i<12;i++) printf("%02X",iv[i]); printf("\n");
        printf("  H:   "); for(int i=0;i<16;i++) printf("%02X",H[i]); printf("\n");
        printf("  J0:  "); for(int i=0;i<16;i++) printf("%02X",J0[i]); printf("\n");
        printf("  encJ0:"); for(int i=0;i<16;i++) printf("%02X",enc_J0[i]); printf("\n");
        printf("  expect: "); for(int i=0;i<16;i++) printf("%02X",expected_tag[i]); printf("\n");
        printf("  actual: "); for(int i=0;i<16;i++) printf("%02X",tag[i]); printf("\n");
        /* 详细GHASH追踪 */
        {
            uint8_t gh_trace[16];
            memset(gh_trace, 0, 16);
            /* 末块填充 */
            size_t last_blk_start = (cipher_len / 16) * 16;
            size_t last_blk_len = cipher_len - last_blk_start;
            printf("  ctBlocks=%d lastLen=%d\n", (int)(cipher_len/16)+1, (int)last_blk_len);
            uint8_t last_block[16] = {0};
            memcpy(last_block, ciphertext + last_blk_start, last_blk_len);
            printf("  lastBlk:"); for(int i=0;i<16;i++) printf("%02X",last_block[i]); printf("\n");
            /* lengthBlock */
            uint8_t lb[16] = {0};
            uint64_t c_bits = (uint64_t)cipher_len * 8;
            lb[8]  = (uint8_t)(c_bits >> 56);
            lb[9]  = (uint8_t)(c_bits >> 48);
            lb[10] = (uint8_t)(c_bits >> 40);
            lb[11] = (uint8_t)(c_bits >> 32);
            lb[12] = (uint8_t)(c_bits >> 24);
            lb[13] = (uint8_t)(c_bits >> 16);
            lb[14] = (uint8_t)(c_bits >> 8);
            lb[15] = (uint8_t)(c_bits);
            printf("  lenBlk:"); for(int i=0;i<16;i++) printf("%02X",lb[i]); printf("\n");
            printf("  c_bits=%llu (0x%llX)\n",
                   (unsigned long long)c_bits, (unsigned long long)c_bits);
        }
        return false;
    }

    /* 4. CTR 解密: 第一块 counter = inc32(J0) */
    uint8_t counter[16];
    memcpy(counter, J0, 16);
    for (int j = 15; j >= 12; j--) {
        counter[j]++;
        if (counter[j] != 0) break;
    }
    for (size_t i = 0; i < cipher_len; i += 16) {
        if (i > 0) {
            for (int j = 15; j >= 12; j--) {
                counter[j]++;
                if (counter[j] != 0) break;
            }
        }
        uint8_t enc_ctr[16];
        sm4_encrypt_block(rk, counter, enc_ctr);
        size_t blk = (cipher_len - i < 16) ? (cipher_len - i) : 16;
        for (size_t j = 0; j < blk; j++)
            plaintext[i + j] = ciphertext[i + j] ^ enc_ctr[j];
    }
    return true;
}

/* ======================== SM4 Wrapper (供 crypto_aes_* 运行时调度) ======================== */

bool crypto_sm4_encrypt(const uint8_t *plaintext,  size_t  plain_len,
                        const uint8_t *iv,          size_t  iv_len,
                        uint8_t       *ciphertext, size_t *cipher_len,
                        uint8_t       *tag,         size_t  tag_len)
{
    sm4_gcm_encrypt(g_dynamic_sm4_key, plaintext, plain_len,
                    iv, ciphertext, tag);
    *cipher_len = plain_len;
    return true;
}

bool crypto_sm4_decrypt(const uint8_t *ciphertext, size_t  cipher_len,
                        const uint8_t *iv,          size_t  iv_len,
                        const uint8_t *tag,         size_t  tag_len,
                        uint8_t       *plaintext,  size_t *plain_len)
{
    if (sm4_gcm_decrypt(g_dynamic_sm4_key, ciphertext, cipher_len,
                        iv, tag, plaintext)) {
        *plain_len = cipher_len;
        return true;
    }
    return false;
}
