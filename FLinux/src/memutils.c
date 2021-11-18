#include <stddef.h>
#include "syscall/mm.h"




int mm_check_read(const void *addr, size_t size)
{
	char* caddr = (char*)addr;
	char a = *caddr;

	caddr = (intptr_t)(caddr + PAGE_SIZE) & ~(PAGE_SIZE - 1);

	int count = size - PAGE_SIZE;

	while (count > 0)
	{
		a = *caddr;
		caddr += PAGE_SIZE;
		count -= PAGE_SIZE;
	}

	return 1;
}

int mm_check_read_string(const char *addr)
{
	strlen(addr);
	return 1;
}

int mm_check_write(void *addr, size_t size)
{
	char* caddr = (char*)addr;
	char a = *caddr;

	caddr = (intptr_t)(caddr + PAGE_SIZE) & ~(PAGE_SIZE - 1);

	int count = size - PAGE_SIZE ;

	while (count > 0)
	{
		a = *caddr;
		*caddr = a;
		caddr += PAGE_SIZE;
		count -= PAGE_SIZE;
	}


	return 1;
}

void signal_restorer()
{
	//TODO: call rt_sigreturn
}

void fpu_fxsave(void *save_area)
{

}

void fpu_fxrstor(void *save_area)
{

}