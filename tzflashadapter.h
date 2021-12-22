// Copyright 2021-2021 The jdh99 Authors. All rights reserved.
// tzflash适配器
// Authors: jdh99 <jdh821@163.com>

#ifndef TZFLASHADAPTER_H
#define TZFLASHADAPTER_H

#include <stdint.h>
#include <stdbool.h>

// TZFlashAdapterLoad 模块载入.partitionName是分区名
bool TZFlashAdapterLoad(char* partitionName);

// TZFlashEraseFlash 擦除flash
bool TZFlashEraseFlash(uint32_t addr, int size);

// TZFlashWriteFlash 写入flash
bool TZFlashWriteFlash(uint32_t addr, uint8_t* bytes, int size);

// TZFlashReadFlash 读取flash
bool TZFlashReadFlash(uint32_t addr, uint8_t* bytes, int size);

#endif
