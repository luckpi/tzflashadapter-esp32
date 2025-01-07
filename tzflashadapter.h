// Copyright 2021-2021 The jdh99 Authors. All rights reserved.
// tzflash������
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

// TZFlashAdapterLoad ģ������.partitionName�Ƿ�����
bool TZFlashAdapterLoad(char* partitionName);

// TZFlashAdapterErase ����flash
bool TZFlashAdapterErase(uint32_t addr, int size);

// TZFlashAdapterWrite д��flash
bool TZFlashAdapterWrite(uint32_t addr, uint8_t* bytes, int size);

// TZFlashAdapterRead ��ȡflash
bool TZFlashAdapterRead(uint32_t addr, uint8_t* bytes, int size);

// TZFlashAdapterEnableEncrypt ��������
bool TZFlashAdapterEnableEncrypt(TZFlashAdapterEncryptType type, uint8_t* key, uint8_t keyLen);

// TZFlashAdapterDisableEncrypt �رռ���
bool TZFlashAdapterDisableEncrypt(void);

#endif
