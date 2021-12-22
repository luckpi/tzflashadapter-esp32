// Copyright 2021-2021 The jdh99 Authors. All rights reserved.
// tzflash适配器
// Authors: jdh99 <jdh821@163.com>

#include "tzflashadapter.h"
#include "tzflash.h"

#include <string.h>

#include "esp_partition.h"
#include "esp_system.h"

#define PAGE_SIZE 4096
#define ALIGN_NUM 1

#define PARTITION_NAME_LEN_MAX 32

static char gPartitionName[PARTITION_NAME_LEN_MAX] = {0};

// eraseFlash 擦除flash
// addr:起始地址.size:擦除字节数
// 成功返回true,失败返回false
static bool eraseFlash(uint32_t addr, int size);

// writeFlash 写入flash
// addr:起始地址.bytes:待写入的字节流.size:写入字节数
// 成功返回true,失败返回false
static bool writeFlash(uint32_t addr, uint8_t* bytes, int size);

// readFlash 读取flash
// addr:起始地址.bytes:读取的字节流存放的缓存.size:读取的字节数
// 成功返回true,失败返回false
static bool readFlash(uint32_t addr, uint8_t* bytes, int size);

// TZFlashAdapterLoad 模块载入.partitionName是分区名
bool TZFlashAdapterLoad(char* partitionName) {
    if (strlen(partitionName) > PARTITION_NAME_LEN_MAX - 1) {
        return false;
    }
    strcpy(gPartitionName, partitionName);
    return TZFlashLoad(PAGE_SIZE, ALIGN_NUM, eraseFlash, writeFlash, readFlash);
}

// TZFlashEraseFlash 擦除flash
// addr:起始地址.size:擦除字节数
// 成功返回true,失败返回false
bool TZFlashEraseFlash(uint32_t addr, int size) {
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

// TZFlashWriteFlash 写入flash
// addr:起始地址.bytes:待写入的字节流.size:写入字节数
// 成功返回true,失败返回false
bool TZFlashWriteFlash(uint32_t addr, uint8_t* bytes, int size) {
    const esp_partition_t *partition = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, 
        ESP_PARTITION_SUBTYPE_ANY, gPartitionName);
    if (partition == NULL) {
        return false;
    }
    if (addr + size > partition->size) {
        return false;
    }

    return esp_partition_write(partition, addr, bytes, size) == ESP_OK;
}

// TZFlashReadFlash 读取flash
// addr:起始地址.bytes:读取的字节流存放的缓存.size:读取的字节数
// 成功返回true,失败返回false
bool TZFlashReadFlash(uint32_t addr, uint8_t* bytes, int size) {
    const esp_partition_t *partition = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, 
        ESP_PARTITION_SUBTYPE_ANY, gPartitionName);
    if (partition == NULL) {
        return false;
    }
    if (addr + size > partition->size) {
        return false;
    }

    return esp_partition_read(partition, addr, bytes, size) == ESP_OK;
}
