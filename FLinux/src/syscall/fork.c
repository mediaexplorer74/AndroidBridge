/*
 * This file is part of Foreign Linux.
 *
 * Copyright (C) 2014, 2015 Xiangyan Sun <wishstudio@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <common/sched.h>
#include <common/types.h>
#include <common/ptrace.h>
//#include <dbt/x86.h>
#include <context.h>
#include <syscall/fork.h>
#include <syscall/mm.h>
#include <syscall/process.h>
#include <syscall/process_info.h>
#include <syscall/syscall.h>
#include <syscall/tls.h>
#include <flags.h>
#include <heap.h>
#include <log.h>
#include <shared.h>

#include <ntdll.h>
#include <onecore_types.h>
#include <common/winapi_missing.h>

/* Fork process
 *
 * 1. Create a process using CreateProcessW() and set command line to the special "/?/fork"
 * 2. Call mm_fork() to initialize memory mappings in the child process
 * 3. Set up fork_info
 * 4. Copy thread stack
 * 5. Wake up child process, it will use fork_info to restore context
 */

struct fork_info
{
	struct syscall_context context;
	int flags;
	void *stack_base;
	void *ctid;
	pid_t pid;
	int gs;
	struct user_desc tls_data;
}  _fork;

struct fork_info_experimental
{
	bool is_child;
	int flags;
	void *stack_base;
	void *ctid;
	pid_t pid;
	HANDLE parent_thread;
	struct user_desc tls_data;
};

struct __bionic_thread_info
{
	int(*fn)(void*);
	void* arg;
	void* tls;
	pid_t tid;
} _fork_new;

static struct fork_info *fork = &_fork;
static struct fork_info_experimental *fork_new = &_fork_new;

__declspec(noreturn) static void fork_child()
{
	install_syscall_handler();
	mm_afterfork_child();
	flags_afterfork_child();
	shared_afterfork_child();
	heap_afterfork_child();
	signal_afterfork_child();
	process_afterfork_child(fork->stack_base, fork->pid);
	tls_afterfork_child();
	vfs_afterfork_child();
	//dbt_init();
	if (fork->ctid)
		*(pid_t *)fork->ctid = fork->pid;
	//dbt_restore_fork_context(&fork->context);
}

void fork_init()
{
	if (!strcmp(GetCommandLineA(), "/?/fork"))
	{
		/* We're a fork child */
		log_info("We're a fork child.");
		fork_child();
	}
	else
	{
#ifdef _WIN64
		/* On Win64, the default base address for ET_EXEC executable is 0x400000
		 * which is problematic that sometimes win32 dlls will allocate memory there
		 * To workaround this issue, we first check if the address space there is
		 * occupied. If so, we create a suspended child process and pre-reserve
		 * the memory region, then transfer control to the child process.
		 * The child process detects such circumstances and release the preserved
		 * memory before use.
		 */
		size_t region_start = 0x400000;
		size_t region_size = 0x10000000; /* 256MB maximum executable size */
		MEMORY_BASIC_INFORMATION info;
		VirtualQuery(region_start, &info, sizeof(MEMORY_BASIC_INFORMATION));
		if (info.State == MEM_FREE && info.RegionSize >= region_size)
		{
			/* That's good, reserve the space now */
			VirtualAlloc(region_start, region_size, MEM_RESERVE, PAGE_NOACCESS);
		}
		else if (info.State == MEM_RESERVE && info.RegionSize == region_size)
		{
			/* We're a child who has the pages protected by the parent, nothing to do here */
		}
		else
		{
			/* Not good, create a child process and hope this time we can do it better */
			log_warning("The address %p is occupied, we have to create another process to proceed.", region_start);
			wchar_t filename[MAX_PATH];
			GetModuleFileNameW(NULL, filename, sizeof(filename) / sizeof(filename[0]));
			PROCESS_INFORMATION info;
			STARTUPINFOW si = { 0 };
			si.cb = sizeof(si);
			if (!CreateProcessW(filename, GetCommandLineW(), NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &si, &info))
			{
				log_error("CreateProcessW() failed, error code: %d", GetLastError());
				process_exit(1, 0);
			}
			/* Pre-reserve the memory */
			if (!VirtualAllocEx(info.hProcess, region_start, region_size, MEM_RESERVE, PAGE_NOACCESS))
			{
				log_error("VirtualAllocEx() failed, error code: %d", GetLastError());
				process_exit(1, 0);
			}
			/* All done */
			log_shutdown();
			ResumeThread(info.hThread);
			process_exit(1, 0);
		}
#endif
		/* Return control flow to main() */
	}
}

/* Currently supported flags (see sched.h):
 o CLONE_VM
 o CLONE_FS
 o CLONE_SIGHAND
 o CLONE_PTRACE
 o CLONE_VFORK
 o CLONE_PARENT
 o CLONE_THREAD
 o CLONE_NEWNS
 o CLONE_SYSVSEM
 * CLONE_SETTLS
 * CLONE_PARENT_SETTID
 * CLONE_CHILD_CLEARTID
 o CLONE_DETACHED
 o CLONE_UNTRACED
 * CLONE_CHILD_SETTID
 o CLONE_NEWUTS
 o CLONE_NEWIPC
 o CLONE_NEWUSER
 o CLONE_NEWPID
 o CLONE_NEWNET
 o CLONE_IO
*/
static pid_t fork_process(struct syscall_context *context, unsigned long flags, void *ptid, void *ctid)
{
	wchar_t filename[MAX_PATH];
	GetModuleFileNameW(NULL, filename, sizeof(filename) / sizeof(filename[0]));

	PROCESS_INFORMATION info;
	STARTUPINFOW si = { 0 };
	si.cb = sizeof(si);
	if (!CreateProcessW(filename, L"/?/fork", NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &si, &info))
	{
		log_warning("fork(): CreateProcessW() failed.");
		return -1;
	}

	if (!tls_fork(info.hProcess))
		goto fail;

	if (!vfs_fork(info.hProcess, info.dwProcessId))
		goto fail;

	if (!mm_fork(info.hProcess))
		goto fail;

	if (!shared_fork(info.hProcess))
		goto fail;

	if (!heap_fork(info.hProcess))
		goto fail;

	if (!signal_fork(info.hProcess))
		goto fail;

	if (!process_fork(info.hProcess))
		goto fail;

	if (!exec_fork(info.hProcess))
		goto fail;

	pid_t pid = process_init_child(info.dwProcessId, info.dwThreadId, info.hProcess);

	/* Set up fork_info in child process */
	void *stack_base = process_get_stack_base();
	NtWriteVirtualMemory(info.hProcess, &fork->context, context, sizeof(struct syscall_context), NULL);
	NtWriteVirtualMemory(info.hProcess, &fork->stack_base, &stack_base, sizeof(stack_base), NULL);
	NtWriteVirtualMemory(info.hProcess, &fork->pid, &pid, sizeof(pid_t), NULL);
	if (flags & CLONE_CHILD_SETTID)
		NtWriteVirtualMemory(info.hProcess, &fork->ctid, &ctid, sizeof(void*), NULL);
	if (flags & CLONE_PARENT_SETTID)
		*(pid_t*)ptid = pid;

	/* Copy stack */
	VirtualAllocEx(info.hProcess, stack_base, STACK_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE); //was execute, why?
	NtWriteVirtualMemory(info.hProcess, (PVOID)context->sp, (PVOID)context->sp,
		(SIZE_T)((char *)stack_base + STACK_SIZE - context->sp), NULL);
	ResumeThread(info.hThread);
	CloseHandle(info.hThread);

	/* Call afterfork routines */
	vfs_afterfork_parent();
	tls_afterfork_parent();
	process_afterfork_parent();
	signal_afterfork_parent();
	heap_afterfork_parent();
	shared_afterfork_parent();
	flags_afterfork_parent();
	mm_afterfork_parent();

	log_info("Child pid: %d, win_pid: %d", pid, info.dwProcessId);
	return pid;

fail:
	TerminateProcess(info.hProcess, 0);
	CloseHandle(info.hThread);
	CloseHandle(info.hProcess);
	return -1;
}


// this is not real fork, but its optimized for fork -> execve combination
// instead of forking process and then destroying it, it creates only new thread, which purpose is only running execve
// it can be used only in special cases

#pragma strict_gs_check(push, off) 

static pid_t fork_process_for_execve(struct syscall_context *context, unsigned long flags, void *ptid, void *ctid)
{
	bool child = false;
	CONTEXT ctx;
	RtlCaptureContext(&ctx);

	if (child)
	{
		return 0;
	}

	void *stack_base = process_get_stack_base();
	void *stack_limit = process_get_stack_limit();

	CONTEXT ThreadContext = { 0 };
	OBJECT_ATTRIBUTES ObjectAttributes;
	INITIAL_TEB InitialTeb;
	CLIENT_ID ThreadClientId;
	HANDLE newthread;
	memset(&InitialTeb, 0, sizeof(INITIAL_TEB));

	size_t stack_size = (char*)stack_base - (char*)stack_limit;

	InitialTeb.StackAllocationBase = mm_alloc_thread_stack(stack_size, false);
	InitialTeb.StackBase = (char*)InitialTeb.StackAllocationBase + stack_size;
	InitialTeb.StackLimit = InitialTeb.StackAllocationBase;


	int stack_diff = ((char*)InitialTeb.StackBase - (char*)stack_base);
#if defined(_M_ARM)
	ctx.Sp = ctx.Sp + stack_diff;
#elif defined(_M_IX86)
	ctx.Esp = ctx.Esp + stack_diff;
#endif
	memcpy(InitialTeb.StackLimit, stack_limit, stack_size);
	*(bool*)(&child + stack_diff) = true;

	InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);

	NTSTATUS status = NtCreateThread(&newthread, THREAD_ALL_ACCESS, NULL, GetCurrentProcess(), &ThreadClientId, &ctx, &InitialTeb, TRUE);
	if (!NT_SUCCESS(status))
	{
		log_error("fork_process_for_execve(): NtCreateThread failed, status: %x", status);
		return -1;
	}

	PROCESS_INFORMATION info;
	STARTUPINFOW si = { 0 };
	si.cb = sizeof(si);
	if (!CreateProcessW(L"ProcessHost.exe", L"", NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &si, &info))
	{
		log_warning("fork(): CreateProcessW() failed.");
		return -1;
	}

	pid_t pid = process_init_child(info.dwProcessId, info.dwThreadId, info.hProcess);
	CloseHandle(info.hThread);

	ResumeThread(newthread);
	CloseHandle(newthread);




	return pid;

}
#pragma strict_gs_check(pop) 


//Inspired by https://codereview.chromium.org/1456343002/patch/20001/30001
//currently child is not executed under UWP
static pid_t fork_process_experimental2(struct syscall_context *context, unsigned long flags, void *ptid, void *ctid)
{

	HMODULE mod;
	RTL_USER_PROCESS_INFORMATION process_info;
	NTSTATUS result;

	//GetSecurityInfo();

	result = RtlCloneUserProcess(RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED | RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES, NULL, NULL, NULL, &process_info);

	if (result == RTL_CLONE_PARENT)
	{
		HANDLE me = GetCurrentProcess();
		pid_t child_pid = GetProcessId(process_info.Process);
		pid_t child_tid = GetThreadId(process_info.Thread);

		pid_t pid = process_init_child(child_pid, child_tid, process_info.Process);

		mm_dump_windows_memory_mappings(process_info.Process);


		ResumeThread(process_info.Thread);
		//CloseHandle(process_info.Process);
		CloseHandle(process_info.Thread);

		return 0;
	}
	else if (result == RTL_CLONE_CHILD)
	{
		sys_mkdir("/ahoj", 0777);
		/* fix stdio */
		//AllocConsole();
		OutputDebugStringA("forked");
		return 0;
	}
	else
		return -1;
	OutputDebugStringA("fork error");
}

//currently createthread fails...
static pid_t fork_process_experimental(struct syscall_context *context, unsigned long flags, void *ptid, void *ctid)
{


	//wchar_t filename[MAX_PATH];
	//GetModuleFileNameW(NULL, filename, sizeof(filename) / sizeof(filename[0]));

	HANDLE newpid = NULL;
	HANDLE newthread = NULL;


	NTSTATUS status = NtCreateProcess(&newpid, PROCESS_ALL_ACCESS, NULL, GetCurrentProcess(), TRUE, NULL, NULL, NULL);

	//from https://github.com/Microwave89/createuserprocess/blob/master/createuserprocess/main.c
	//PS_CREATE_INFO procInfo;
	//procInfo.Size = sizeof(PS_CREATE_INFO);
	//NTSTATUS status = NtCreateUserProcess(&newpid, &newthread, MAXIMUM_ALLOWED, MAXIMUM_ALLOWED, NULL, NULL, PROCESS_CREATE_FLAGS_INHERIT_FROM_PARENT, THREAD_CREATE_FLAGS_CREATE_SUSPENDED, NULL, &procInfo, NULL);
	//0xc000000d

	if (!NT_SUCCESS(status))
	{
		log_error("fork_process_experimental(): NtCreateProcess failed, status: %x", status);
		return -1;
	}

	CONTEXT ctx;
	RtlCaptureContext(&ctx);
	/* Set up fork_info in child process */
	void *stack_base = process_get_stack_base();
	void *stack_limit = process_get_stack_limit();

	CONTEXT ThreadContext = { 0 };
	OBJECT_ATTRIBUTES ObjectAttributes;
	INITIAL_TEB InitialTeb;
	CLIENT_ID ThreadClientId;
	memset(&InitialTeb, 0, sizeof(INITIAL_TEB));
	InitialTeb.StackBase = stack_base;
	InitialTeb.StackLimit = stack_limit;
	InitialTeb.StackAllocationBase = stack_limit;
	InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);

	// this currently return 0xC000010A
	status = NtCreateThread(&newthread, THREAD_ALL_ACCESS, NULL, newpid, &ThreadClientId, &ctx, &InitialTeb, TRUE);
	if (!NT_SUCCESS(status))
	{
		log_error("mm_fork(): NtCreateThread failed, status: %x", status);
		return -1;
	}

	mm_dump_windows_memory_mappings(newpid);

	//SuspendThread(fi->parent_thread);*/

	PROCESS_INFORMATION info = {0};
	info.hProcess = newpid;
	info.dwProcessId = GetProcessId(newpid);
	/*STARTUPINFOW si = { 0 };
	si.cb = sizeof(si);
	if (!CreateProcessW(L"ProcessHost.exe", L"/?/fork", NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &si, &info))
	{
		log_warning("fork(): CreateProcessW() failed. %d", GetLastError());
		return -1;
	}*/

	if (fork_new->is_child)
		return 0;


	mm_dump_windows_memory_mappings(info.hProcess);

	if (!tls_fork(info.hProcess))
		goto fail;

	if (!vfs_fork(info.hProcess, info.dwProcessId))
		goto fail;

	if (!mm_fork(info.hProcess))
		goto fail;

	if (!shared_fork(info.hProcess))
		goto fail;

	if (!heap_fork(info.hProcess))
		goto fail;

	if (!signal_fork(info.hProcess))
		goto fail;

	if (!process_fork(info.hProcess))
		goto fail;

	if (!exec_fork(info.hProcess))
		goto fail;

	pid_t pid = process_init_child(info.dwProcessId, info.dwThreadId, info.hProcess);
	fork_new->pid = pid;

	bool is_child = true;
	//NtWriteVirtualMemory(info.hProcess, &fork->context, context, sizeof(struct syscall_context), NULL);
	//NtWriteVirtualMemory(info.hProcess, &fork->stack_base, &stack_base, sizeof(stack_base), NULL);
	mm_write_process_memory(info.hProcess, &fork_new->is_child, &is_child, sizeof(is_child));
	mm_write_process_memory(info.hProcess, &fork_new->pid, &pid, sizeof(pid_t));
	//NtWriteVirtualMemory(info.hProcess, &fi->pid, &pid, sizeof(pid_t), NULL);

	/*if (fi->flags & CLONE_CHILD_SETTID)
		NtWriteVirtualMemory(info.hProcess, &fork->ctid, &ctid, sizeof(void*), NULL);
	if (flags & CLONE_PARENT_SETTID)
		*(pid_t*)ptid = pid;*/

	/* Copy stack */
	VirtualAllocEx(info.hProcess, stack_base, (char *)stack_base - (char*)stack_limit, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE); //was execute, why?
#if defined(_M_ARM)
	mm_write_process_memory(info.hProcess, (PVOID)ctx.Sp, (PVOID)ctx.Sp, (SIZE_T)((char *)stack_base + ctx.Sp));
#elif defined(_M_IX86)
	mm_write_process_memory(info.hProcess, (PVOID)ctx.Esp, (PVOID)ctx.Esp, (SIZE_T)((char *)stack_base + ctx.Esp));
#endif


	SetThreadContext(info.hThread, &ctx);

	ResumeThread(info.hThread);
	CloseHandle(info.hThread);

	/* Call afterfork routines */
	vfs_afterfork_parent();
	tls_afterfork_parent();
	process_afterfork_parent();
	signal_afterfork_parent();
	heap_afterfork_parent();
	shared_afterfork_parent();
	flags_afterfork_parent();
	mm_afterfork_parent();

	log_info("Child pid: %d, win_pid: %d", pid, info.dwProcessId);
	return pid;

fail:
	TerminateProcess(info.hProcess, 0);
	CloseHandle(info.hThread);
	CloseHandle(info.hProcess);
	return -1;
}


static DWORD WINAPI fork_thread_callback(void *data)
{
	/* This function runs in child thread */
	struct fork_info *info = (struct fork_info *)data;
	log_init_thread();
//	dbt_init_thread();
	process_thread_entry(info->pid);
	if (info->flags & CLONE_SETTLS)
		tls_set_thread_area(&info->tls_data);
	if (info->flags & CLONE_CHILD_CLEARTID)
		current_thread->clear_tid = info->ctid;
	else
		current_thread->clear_tid = NULL;
//	dbt_update_tls(info->gs);
	struct syscall_context context = info->context;
	context.eax = 0;
	VirtualFree(info, 0, MEM_RELEASE);
//	dbt_restore_fork_context(&context);
	return 0;
}


static DWORD WINAPI __bionic_thread_callback(void *data)
{
	struct __bionic_thread_info *info = (struct __bionic_thread_info *)data;

	log_init_thread();
	process_thread_entry(info->tid);

	if(info->tls != NULL)
		__set_tls(info->tls);

	int(*fn)(void*) = info->fn;
	void* arg = info->arg;

	VirtualFree(info, 0, MEM_RELEASE);

	fn(arg);

	thread_exit(0, 0);

}

pid_t __bionic_clone(uint32_t flags, void* child_stack, int* parent_tid, void* tls, int* child_tid, int(*fn)(void*), void* arg)
{
	log_info("__bionic_clone(flags=%x, child_stack=%p, ptid=%p, ctid=%p)", flags, child_stack, parent_tid, child_tid);

	struct __bionic_thread_info *info = VirtualAlloc(NULL, sizeof(struct __bionic_thread_info), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);


	DWORD win_tid;
	//HANDLE newthread = CreateThread(NULL, 0, __bionic_thread_callback, info, CREATE_SUSPENDED, &win_tid);

	CONTEXT ThreadContext = { 0 };
	OBJECT_ATTRIBUTES ObjectAttributes;
	INITIAL_TEB InitialTeb;
	CLIENT_ID ThreadClientId;
	memset(&InitialTeb, 0, sizeof(INITIAL_TEB));
	InitialTeb.StackBase = child_stack;
	InitialTeb.StackLimit = (char*)child_stack - 0x20000; //how to get stack size? linux kernel does not need this param but windows kernel does
	InitialTeb.StackAllocationBase = InitialTeb.StackLimit;
	InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);

	DWORD ctx_size = sizeof(ThreadContext);


	/*HMODULE hModule = LoadPackagedLibrary(L"ntdll.dll", 0);
	RtlInitializeContext_t RtlInitializeContext = (RtlInitializeContext_t)GetProcAddress(hModule, "RtlInitializeContext");


	RtlInitializeContext(GetCurrentProcess(), &ThreadContext, info, __bionic_thread_callback, child_stack);

	InitializeContext(NULL, CONTEXT_ALL, &ThreadContext, &ctx_size);*/

	RtlCaptureContext(&ThreadContext);

#if defined(_M_ARM)
	ThreadContext.Sp = child_stack;
	ThreadContext.Pc = __bionic_thread_callback;
	ThreadContext.R0 = info;
#elif defined(_M_IX86)
	ThreadContext.Esp = child_stack;
	ThreadContext.Eip = __bionic_thread_callback;
	ThreadContext.Eax = info;
#endif

	mm_handle_page_fault(child_stack, true);
	mm_handle_page_fault((char*)child_stack - PAGE_SIZE, true);


	// this currently return 0xC000010A
	HANDLE newthread;
	NTSTATUS status = NtCreateThread(&newthread, THREAD_ALL_ACCESS, NULL, GetCurrentProcess(), &ThreadClientId, &ThreadContext, &InitialTeb, TRUE);
	if (!NT_SUCCESS(status))
	{
		log_error("mm_fork(): NtCreateThread failed, status: %x", status);
		return -1;
	}

	win_tid = GetThreadId(newthread);

	pid_t pid = process_create_thread(win_tid);
	if (flags & CLONE_CHILD_SETTID)
		*(pid_t *)child_tid = pid;
	if (flags & CLONE_PARENT_SETTID)
		*(pid_t *)parent_tid = pid;

	info->tid = pid;
	info->arg = arg;
	info->fn = fn;
	if (flags & CLONE_SETTLS)
		info->tls = tls;
	else
		info->tls = NULL;

#ifdef _M_X86
	if (flags & CLONE_SETTLS)
		info->tls_data = *(struct user_desc *)context->esi;
#endif


	ResumeThread(newthread);
	CloseHandle(newthread);
	return pid;
}


static pid_t fork_thread(struct syscall_context *context, void *child_stack, unsigned long flags, void *ptid, void *ctid)
{
	struct fork_info *info = VirtualAlloc(NULL, sizeof(struct fork_info), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	DWORD win_tid;
	HANDLE handle = CreateThread(NULL, 0, fork_thread_callback, info, CREATE_SUSPENDED, &win_tid);
	pid_t pid = process_create_thread(win_tid);
	info->context = *context;
	info->context.sp = (DWORD)child_stack;
	info->pid = pid;
	info->ctid = ctid;
	info->flags = flags;
	if (flags & CLONE_CHILD_SETTID)
		*(pid_t *)ctid = pid;
	if (flags & CLONE_PARENT_SETTID)
		*(pid_t *)ptid = pid;
//	info->gs = dbt_get_gs();
#ifdef _M_X86
	if (flags & CLONE_SETTLS)
		info->tls_data = *(struct user_desc *)context->esi;
#endif
	ResumeThread(handle);
	CloseHandle(handle);
	return pid;
}

int sys_fork_imp(struct syscall_context *context)
{
	log_info("fork()");
	return fork_process_experimental(context, 0, NULL, NULL);
}

int sys_vfork_imp(struct syscall_context *context)
{
	log_info("vfork()");
	return fork_process_experimental(context, CLONE_VFORK, NULL, NULL);
}

#ifdef _WIN64
int sys_clone_imp(struct syscall_context *context, unsigned long flags, void *child_stack, void *ptid, void *ctid)
#else
int sys_clone_imp(struct syscall_context *context, unsigned long flags, void *child_stack, void *ptid, int tls, void *ctid)
#endif
{
	log_info("sys_clone(flags=%x, child_stack=%p, ptid=%p, ctid=%p)", flags, child_stack, ptid, ctid);
	if (flags & CLONE_THREAD)
		return fork_thread(context, child_stack, flags, ptid, ctid);
	else
		return fork_process_experimental2(context, flags, ptid, ctid);
		//return fork_process_for_execve(context, child_stack, flags, ptid, ctid);

}
