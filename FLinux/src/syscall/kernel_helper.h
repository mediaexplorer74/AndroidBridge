/*TODO: license message*/

#pragma once

#include <common/types.h>


#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

extern int __kuser_cmpxchg(int32_t oldval, int32_t newval, volatile int32_t *ptr);
extern void __kuser_memory_barrier(void);
extern int __kuser_cmpxchg64(const int64_t *oldval,
	const int64_t *newval,
	volatile int64_t *ptr);