#ifndef SPDK_BARRIER_H
#define SPDK_BARRIER_H

#define wmb()	__asm volatile("sfence" ::: "memory")
#define mb()	__asm volatile("mfence" ::: "memory")

#endif
