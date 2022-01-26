#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

struct syscall_context
{
	/* DO NOT REORDER */
	/* Context for fork() */
	DWORD ebx;
	DWORD ecx;
	DWORD edx;
	DWORD esi;
	DWORD edi;
	DWORD ebp;
	union
	{
		DWORD sp;
		DWORD esp;
	};
	union
	{
		DWORD pc;
		DWORD eip;
	};

	/* The following are not used by fork() */
	union
	{
		DWORD r0;
		DWORD eax;
	};
	DWORD eflags;
};