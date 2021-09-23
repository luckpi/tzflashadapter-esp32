// Copyright 2021-2021 The jdh99 Authors. All rights reserved.
// tzflash适配器
// Authors: jdh99 <jdh821@163.com>

#ifndef TZFLASHADAPTER_H
#define TZFLASHADAPTER_H

#include <stdint.h>
#include <stdbool.h>

// TZFlashAdapterLoad 模块载入.partitionName是分区名
bool TZFlashAdapterLoad(char* partitionName);

#endif
