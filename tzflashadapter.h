// Copyright 2021-2021 The jdh99 Authors. All rights reserved.
// tzflash适配器
// Authors: jdh99 <jdh821@163.com>

#ifndef TZFLASHADAPTER_H
#define TZFLASHADAPTER_H

#include <stdint.h>
#include <stdbool.h>

typedef enum {
    TZFLASHADAPTER_ENCRYPT_NONE = 0,
    TZFLASHADAPTER_ENCRYPT_AES = 1
} TZFlashAdapterEncryptType;

typedef struct {
    char* PartitionName;
    TZFlashAdapterEncryptType EncryptType;
    uint8_t EncryptKey[16];
    uint8_t EncryptKeyLen;
} TZFlashAdapterParam;

// TZFlashAdapterLoad 模块载入.partitionName是分区名
bool TZFlashAdapterLoad(char* partitionName);

// TZFlashAdapterErase 擦除flash
bool TZFlashAdapterErase(uint32_t addr, int size);

// TZFlashAdapterWrite 写入flash
bool TZFlashAdapterWrite(uint32_t addr, uint8_t* bytes, int size);

// TZFlashAdapterRead 读取flash
bool TZFlashAdapterRead(uint32_t addr, uint8_t* bytes, int size);

// TZFlashAdapterEnableEncrypt 开启加密
bool TZFlashAdapterEnableEncrypt(TZFlashAdapterEncryptType type, uint8_t* key, uint8_t keyLen);

// TZFlashAdapterDisableEncrypt 关闭加密
bool TZFlashAdapterDisableEncrypt(void);

#endif
