// Copyright 2021-2021 The jdh99 Authors. All rights reserved.
// tzflash适配器
// Authors: jdh99 <jdh821@163.com>

#include "tzflashadapter.h"
#include "tzflash.h"
#include "tzmalloc.h"
#include "tztype.h"

#include <string.h>

#include "esp_partition.h"
#include "esp_system.h"
#include "lagan.h"
#include "mbedtls/aes.h"

#define TAG "tzflashadapter"

#define MALLOC_SIZE 4096

#define PAGE_SIZE 4096
#define ALIGN_NUM 1

#define PARTITION_NAME_LEN_MAX 32
#define ENCRYPT_KEY_LEN_MAX 32

#define AES_BLOCK_SIZE 16

static int gMid = -1;

static char gPartitionName[PARTITION_NAME_LEN_MAX] = {0};

static TZFlashAdapterEncryptType gEncryptType = TZFLASHADAPTER_ENCRYPT_NONE;
static uint8_t gEncryptKey[ENCRYPT_KEY_LEN_MAX] = {0};
static uint8_t gEncryptKeyLen = 0;

static bool encryptData(const esp_partition_t *partition, uint32_t addr, const uint8_t *input, int inputLen);
static bool decryptData(const esp_partition_t *partition, uint32_t addr, uint8_t *out, int outLen);

// TZFlashAdapterLoad 模块载入.partitionName是分区名
bool TZFlashAdapterLoad(char* partitionName) {
    if (strlen(partitionName) > PARTITION_NAME_LEN_MAX - 1) {
        return false;
    }
    strcpy(gPartitionName, partitionName);

    return TZFlashLoad(PAGE_SIZE, ALIGN_NUM, TZFlashAdapterErase, TZFlashAdapterWrite, TZFlashAdapterRead);
}

// TZFlashAdapterErase 擦除flash
// addr:起始地址.size:擦除字节数
// 成功返回true,失败返回false
bool TZFlashAdapterErase(uint32_t addr, int size) {
    const esp_partition_t *partition = esp_partition_find_first(ESP_PARTITION_TYPE_DATA,
                                                                ESP_PARTITION_SUBTYPE_ANY, gPartitionName);
    if (partition == NULL) {
        return false;
    }
    if (addr + size > partition->size || addr % PAGE_SIZE != 0 || size % PAGE_SIZE != 0) {
        return false;
    }

    return esp_partition_erase_range(partition, addr, size) == ESP_OK;
}

// TZFlashAdapterWrite 写入flash
// addr:起始地址.bytes:待写入的字节流.size:写入字节数
// 成功返回true,失败返回false
bool TZFlashAdapterWrite(uint32_t addr, uint8_t *bytes, int size) {
    const esp_partition_t *partition = esp_partition_find_first(ESP_PARTITION_TYPE_DATA,
                                                                ESP_PARTITION_SUBTYPE_ANY, gPartitionName);
    if (partition == NULL) {
        return false;
    }
    if (addr + size > partition->size) {
        return false;
    }

    if (gEncryptType == TZFLASHADAPTER_ENCRYPT_NONE) {
        return esp_partition_write(partition, addr, bytes, size) == ESP_OK;
    }

    if (encryptData(partition, addr, bytes, size) == false) {
        return false;
    }

    return true;
}

static bool encryptData(const esp_partition_t *partition, uint32_t addr, const uint8_t *input, int inputLen) {
    if (gEncryptType == TZFLASHADAPTER_ENCRYPT_NONE) {
        return false;
    }

    int len = inputLen;
    if (len % AES_BLOCK_SIZE != 0) {
        len = (len / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
    }

    if (addr + len > partition->size) {
        LE(TAG, "read flash failed!addr + size > partition size");
        return false;
    }

    TZBufferDynamic *buffer = TZMalloc(gMid, sizeof(TZBufferDynamic) + len);
    if (buffer == NULL) {
        LE(TAG, "encrypt data failed!malloc buffer failed");
        return false;
    }
    buffer->len = 0;

    mbedtls_aes_context aesCtx;
    mbedtls_aes_init(&aesCtx);

    if (mbedtls_aes_setkey_enc(&aesCtx, gEncryptKey, gEncryptKeyLen * 8) != 0) {
        LE(TAG, "load failed!mbedtls aes setkey failed");
        TZFree(buffer);
        mbedtls_aes_free(&aesCtx);
        return false;
    }

    for (int i = 0; i < len; i += AES_BLOCK_SIZE) {
        if (i + AES_BLOCK_SIZE > inputLen) {
            break;
        }
        mbedtls_aes_crypt_ecb(&aesCtx, MBEDTLS_AES_ENCRYPT, input + i, buffer->buf + i);
        buffer->len = i + AES_BLOCK_SIZE;
    }

    if (inputLen > buffer->len) {
        uint8_t temp[AES_BLOCK_SIZE] = {0};
        memcpy(temp, input + buffer->len, inputLen - buffer->len);
        mbedtls_aes_crypt_ecb(&aesCtx, MBEDTLS_AES_ENCRYPT, temp, buffer->buf + buffer->len);
        buffer->len += AES_BLOCK_SIZE;
    }

    mbedtls_aes_free(&aesCtx);

    if (esp_partition_write(partition, addr, buffer->buf, buffer->len) != ESP_OK) {
        LE(TAG, "write flash failed!esp partition write failed");
        TZFree(buffer);
        return false;
    }

    TZFree(buffer);

    return true;
}

// TZFlashAdapterRead 读取flash
// addr:起始地址.bytes:读取的字节流存放的缓存.size:读取的字节数
// 成功返回true,失败返回false
bool TZFlashAdapterRead(uint32_t addr, uint8_t *bytes, int size) {
    const esp_partition_t *partition = esp_partition_find_first(ESP_PARTITION_TYPE_DATA,
                                                                ESP_PARTITION_SUBTYPE_ANY, gPartitionName);
    if (partition == NULL) {
        return false;
    }
    if (addr + size > partition->size) {
        return false;
    }

    if (gEncryptType == TZFLASHADAPTER_ENCRYPT_NONE) {
        bool result = esp_partition_read(partition, addr, bytes, size) == ESP_OK;
        if (result == false) {
            LE(TAG, "read flash failed!esp partition read failed");
        }
        return result;
    }

    if (decryptData(partition, addr, bytes, size) == false) {
        LE(TAG, "read flash failed!decrypt data failed");
        return false;
    }

    return true;
}

static bool decryptData(const esp_partition_t *partition, uint32_t addr, uint8_t *out, int outLen) {
    if (gEncryptType == TZFLASHADAPTER_ENCRYPT_NONE) {
        return false;
    }

    int len = outLen;
    if (len % AES_BLOCK_SIZE != 0) {
        len = (len / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
    }

    if (addr + len > partition->size) {
        LE(TAG, "read flash failed!addr + size > partition size");
        return false;
    }

    TZBufferDynamic *buffer = TZMalloc(gMid, sizeof(TZBufferDynamic) + len);
    if (buffer == NULL) {
        LE(TAG, "decrypt data failed!decrypt data failed");
        return false;
    }
    buffer->len = 0;

    if (esp_partition_read(partition, addr, buffer->buf, len) != ESP_OK) {
        LE(TAG, "read flash failed!esp partition read failed");
        TZFree(buffer);
        return false;
    }

    mbedtls_aes_context aesCtx;
    mbedtls_aes_init(&aesCtx);
    if (mbedtls_aes_setkey_dec(&aesCtx, gEncryptKey, gEncryptKeyLen * 8) != 0) {
        LE(TAG, "Failed to set AES key");
        TZFree(buffer);
        return false;
    }

    for (int i = 0; i < len; i += AES_BLOCK_SIZE) {
        if (i + AES_BLOCK_SIZE > outLen) {
            break;
        }
        mbedtls_aes_crypt_ecb(&aesCtx, MBEDTLS_AES_DECRYPT, buffer->buf + i, out + i);
        buffer->len = i + AES_BLOCK_SIZE;
    }

    if (outLen > buffer->len) {
        uint8_t temp[AES_BLOCK_SIZE] = {0};
        mbedtls_aes_crypt_ecb(&aesCtx, MBEDTLS_AES_DECRYPT, buffer->buf + buffer->len, temp);
        memcpy(out + buffer->len, temp, outLen - buffer->len);
    }

    TZFree(buffer);

    mbedtls_aes_free(&aesCtx);

    return true;
}

// TZFlashAdapterEnableEncrypt 开启加密
bool TZFlashAdapterEnableEncrypt(TZFlashAdapterEncryptType type, uint8_t *key, uint8_t keyLen) {
    if (keyLen > ENCRYPT_KEY_LEN_MAX || key == NULL || type == TZFLASHADAPTER_ENCRYPT_NONE) {
        return false;
    }

    if (gMid == -1) {
        gMid = TZMallocRegister(0, TAG, MALLOC_SIZE);
        if (gMid == -1) {
            LE(TAG, "load failed!malloc register failed");
            return false;
        }
    }

    gEncryptType = type;
    memcpy(gEncryptKey, key, keyLen);
    gEncryptKeyLen = keyLen;

    return true;
}

// TZFlashAdapterDisableEncrypt 关闭加密
bool TZFlashAdapterDisableEncrypt(void) {
    gEncryptType = TZFLASHADAPTER_ENCRYPT_NONE;
    return true;
}
