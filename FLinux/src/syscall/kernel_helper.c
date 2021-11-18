/*TODO: license message*/


#include <syscall/kernel_helper.h>

int __kuser_cmpxchg(int32_t oldval, int32_t newval, volatile int32_t *ptr)
{
	InterlockedCompareExchange(ptr, newval, oldval);

	return 0;
}

void __kuser_memory_barrier()
{
	//Nothing to do
}

int __kuser_cmpxchg64(const int64_t *oldval,
	const int64_t *newval,
	volatile int64_t *ptr)
{
	InterlockedCompareExchange64(ptr, *newval, *oldval);

	return 0;
}