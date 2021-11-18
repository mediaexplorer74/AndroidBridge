#include "pch.h"

#define DLL_EXPORT
#include "BridgeApi.h"
#include "tools.h"
//#include "asm-generic/mman-common.h"
extern "C" {
#include "syscall/mm.h"
#include "syscall/vfs.h"
}

static HANDLE _heap = NULL;


static DWORD prot_linux2win(int prot)
{

	if ((prot & PROT_EXEC) && (prot & PROT_WRITE))
		return PAGE_EXECUTE_READWRITE;
	else if ((prot & PROT_EXEC) && (prot & PROT_READ))
		return PAGE_EXECUTE_READ;
	else if ((prot & PROT_EXEC))
		return PAGE_EXECUTE;
	else if (prot & PROT_WRITE)
		return PAGE_READWRITE;
	else if (prot & PROT_READ)
		return PAGE_READONLY;
	else
		return PAGE_NOACCESS;

}

intptr_t __mmap2(void *addr, size_t length, int prot,
	int flags, int fd, off_t pgoffset)
{
	DebugLog(__FUNCTION__"(0x%x, %d, %d, %d, %d, 0x%x)", addr, length, prot, flags, fd, pgoffset);

	struct file *f = vfs_get(fd);
	intptr_t r = (intptr_t)mm_mmap(addr, length, prot, flags, 0, f, pgoffset);
	if (f)
		vfs_release(f);

	DebugLog(" = 0x%x\n", r);

	return r;
	/*
	PVOID ptr = NULL;

	if ((addr == NULL) && (flags & MAP_ANONYMOUS) && (flags & MAP_PRIVATE))
	{
		//TODO: implement COW if it will be possible and we will have functional fork
		// Meantime HeapAlloc is enough fro anonymous & private blocks
		ptr = HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, length);
	}
	else
	{

		ptr = VirtualAlloc(
			addr,
			length,
			MEM_RESERVE,
			prot_linux2win(prot)
		);

	}

	if (ptr == NULL)
	{
		DebugLog(" = failed 0x%x\n", GetLastError());
		return ((void *)-1);
	}

	DebugLog(" = 0x%x\n", ptr);

	/*char c = *((char*)ptr);
	*((char*)ptr) = 'a';*/

//	return ptr;
}


int mprotect(void *addr, size_t len, int prot)
{
	DebugLog(__FUNCTION__"(0x%x, %d, %d)", addr, len, prot);



	DWORD oldProtect;
	if (!VirtualProtect(addr, len, prot_linux2win(prot), &oldProtect))
	{
		DebugLog(" = failed 0x%x\n", GetLastError());
		return -1;
	}

	DebugLog(" = %d\n", 0);

	return 0;
}

