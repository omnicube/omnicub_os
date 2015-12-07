#ifndef SPDK_FILE_H
#define SPDK_FILE_H

#include <stdint.h>

uint64_t file_get_size(int fd);
uint32_t dev_get_blocklen(int fd);

#endif
