#ifndef SPDK_VTOPHYS_H
#define SPDK_VTOPHYS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VTOPHYS_ERROR	(0xFFFFFFFFFFFFFFFFULL)

uint64_t vtophys(void *buf);

#ifdef __cplusplus
}
#endif

#endif
