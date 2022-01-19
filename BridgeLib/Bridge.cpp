#include "pch.h"

#define DLL_EXPORT
#include "BridgeApi.h"
#include "tools.h"
#include "dll_init.h"
#include "args.h"
#include "windefs.h"


extern "C" {
#include <common/reset_windef.h>
#include <syscall/vfs.h>
#include <syscall/syscall.h>
#include <syscall/mm.h>
#include <syscall/fork.h>
#include "linux/arm/unistd.h"
}

int __cxa_begin_cleanup = 0;
int __cxa_type_match = 0;
int __cxa_call_unexpected = 0;
int __cxa_end_cleanup = 0;
void* __data_start = (void*)0x20000000;
void* data_start = (void*)0x20000000;
const char* __progname = "app_process";
void* __google_potentially_blocking_region_begin = (void*)0x80000000;
void* __google_potentially_blocking_region_end = (void*)0xFFFFFFFF;

extern "C" int sys_futex(int * uaddr, int op, int val, const struct timespec * timeout, int * uaddr2, int val3);


#define __clang_va_arg(ap, t) (*(t*)((ap += _SLOTSIZEOF(t) + _APALIGN(t, ap)) - _SLOTSIZEOF(t)))

// some sycalls are called via universal function so we must handle them
long _bridge_syscall(long __number, ...)
{
	long ret = -1;

	va_list vl_firstarg;
	va_start(vl_firstarg, __number);

	if (__number == __NR_clone)
	{
		char* vl = va_arg(vl_firstarg, char *);

		unsigned long flags = va_arg(vl, unsigned long);
		void* child_stack = va_arg(vl, void*);
		void* ptid = va_arg(vl, void*);
		int tls = va_arg(vl, int);
		void* ctid = va_arg(vl, void*);
		ret = sys_clone_imp(NULL, flags, child_stack, ptid, tls, ctid);
	}
	else if (__number == __NR_futex)
	{
		char* vl = va_arg(vl_firstarg, char *);

		int * uaddr = va_arg(vl, int *);
		int op = va_arg(vl, int);
		int val = va_arg(vl, int);
		const struct timespec * timeout = va_arg(vl, const struct timespec *);
		int * uaddr2 = va_arg(vl, int *);
		int val3 = va_arg(vl, int);
		
		ret = sys_futex(uaddr, op, val, timeout, uaddr2, val3);
	}
	else
	{
		DebugLog(__FUNCTION__"(%d) - unknown syscall\n", __number);
	}
	va_end(vl_firstarg);
	return ret;
}



int _bridge_execve(const char * filename, char ** argv, char ** envp)
{

	int argc = 0;
	int i = 0;
	size_t arg_size = arg_num_length(argc, argv);

	int envc = 0;
	arg_size += arg_num_length(envc, envp);

	arg_size += strlen(filename) + 1;

	struct mount_point mp;
	vfs_get_root_mountpoint(&mp);

	arg_size += mp.win_path_len / 2 + 8;// --root=

	arg_size += 14;//"--params=9999"


	char* argline = new char[arg_size];
	
	strcpy_s(argline, arg_size, "--root=");
	i += 7;

	int j = 0;

	for (; j < mp.win_path_len; j++)
	{
		argline[i++] = (char)mp.win_path[j];
	}

	argline[i++] = ' ';

	strcpy_s(argline + i, arg_size - i, "--params=");
	i += 9;
	
	_itoa_s(argc, argline + i, arg_size - i, 10);
	
	while (argline[i] != 0)
		i++;

	j = 0;
	while (argv[j] != NULL)
	{
		argline[i++] = ' ';
		strcpy_s(argline + i, arg_size - i, argv[j]);
		i += strlen(argv[j]);
		j++;
	}

	
	argline[i++] = 0;

	STARTUPINFO si;
	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);


	PROCESS_INFORMATION pi;

	BOOL ok = CreateProcessA("ProcessHost.exe", argline, 0, 0, FALSE, 0, 0, 0, &si, &pi);

	delete[] argline;

	if (ok)
	{
		DebugLog("Process started, pid: %d\n", pi.dwProcessId);

		WaitForSingleObject(pi.hProcess, INFINITE);

		DWORD exit_code;

		GetExitCodeProcess(pi.hProcess, &exit_code);

		DebugLog("Process finished 0x%x\n", exit_code);

	}

	return 0;
}

long _bridge_vfork(void)
{
	DebugLog(__FUNCTION__"\n");
	return 0;
}


void __cxa_finalize()
{
	DebugLog(__FUNCTION__"\n");
}

void __cxa_atexit()
{
	DebugLog(__FUNCTION__"\n");
}

void __stack_chk_fail()
{
	DebugLog(__FUNCTION__"\n");
}

void __register_atfork()
{
	DebugLog(__FUNCTION__"\n");
}



void __android_log_print()
{
	DebugLog(__FUNCTION__"\n");
}

void removeAllProcessGroups()
{
	DebugLog(__FUNCTION__"\n");
}
void createProcessGroup()
{
	DebugLog(__FUNCTION__"\n");
}
void killProcessGroup()
{
	DebugLog(__FUNCTION__"\n");
}


int adjtimex(struct timex *buf)
{
	DebugLog(__FUNCTION__"\n");
	return 0;
}

int cacheflush()
{
	DebugLog(__FUNCTION__"\n");
	return 0;
}

int getitimer() { DebugLog(__FUNCTION__"\n"); return 0; }
int clock_adjtime() { DebugLog(__FUNCTION__"\n"); return 0; }
int clock_settime() { DebugLog(__FUNCTION__"\n"); return 0; }
int delete_module() { DebugLog(__FUNCTION__"\n"); return 0; }
int sync() { DebugLog(__FUNCTION__"\n"); return 0; }
void* clock_getres() { DebugLog(__FUNCTION__"\n"); return 0; }
void* getrlimit() { DebugLog(__FUNCTION__"\n"); return 0; }
void* read() { DebugLog(__FUNCTION__"\n"); return 0; }
void* clock_gettime() { DebugLog(__FUNCTION__"\n"); return 0; }
void* write() { DebugLog(__FUNCTION__"\n"); return 0; }
void* __brk() { DebugLog(__FUNCTION__"\n"); return 0; }
void* fchownat() { DebugLog(__FUNCTION__"\n"); return 0; }
void* __getdents64() { DebugLog(__FUNCTION__"\n"); return 0; }
void* ___clock_nanosleep() { DebugLog(__FUNCTION__"\n"); return 0; }
void* __exit() { DebugLog(__FUNCTION__"\n"); return 0; }
void* ___close() { DebugLog(__FUNCTION__"\n"); return 0; }
void* lseek() { DebugLog(__FUNCTION__"\n"); return 0; }
void* dup3() { DebugLog(__FUNCTION__"\n"); return 0; }
void* getxattr() { DebugLog(__FUNCTION__"\n"); return 0; }
void* ___fgetxattr() { DebugLog(__FUNCTION__"\n"); return 0; }
void* epoll_create1() { DebugLog(__FUNCTION__"\n"); return 0; }
void* __epoll_pwait() { DebugLog(__FUNCTION__"\n"); return 0; }
void* ___faccessat() { DebugLog(__FUNCTION__"\n"); return 0; }
void* ___fchmod() { DebugLog(__FUNCTION__"\n"); return 0; }
long __set_tid_address(int *tidptr)
{
	DebugLog(__FUNCTION__"(0x%x)\n", tidptr);
	return GetCurrentThreadId();
}
void* ___fsetxattr() { DebugLog(__FUNCTION__"\n"); return 0; }
void* setxattr() { DebugLog(__FUNCTION__"\n"); return 0; }
void* ftruncate64() { DebugLog(__FUNCTION__"\n"); return 0; }
int flistxattr() { DebugLog(__FUNCTION__"\n"); return 0; }
void* utimensat() { DebugLog(__FUNCTION__"\n"); return 0; }
void* __getcwd() { DebugLog(__FUNCTION__"\n"); return 0; }
void* uname() { DebugLog(__FUNCTION__"\n"); return 0; }
void* getuid() { DebugLog(__FUNCTION__"\n"); return 0; }
void* getpgid() { DebugLog(__FUNCTION__"\n"); return 0; }
void* __getpid() { DebugLog(__FUNCTION__"\n"); return 0; }
void* inotify_init1() { DebugLog(__FUNCTION__"\n"); return 0; }
void* munmap() { DebugLog(__FUNCTION__"\n"); return 0; }
void* linkat() { DebugLog(__FUNCTION__"\n"); return 0; }
void* mknodat() { DebugLog(__FUNCTION__"\n"); return 0; }
void* mkdirat() { DebugLog(__FUNCTION__"\n"); return 0; }
void* __rt_sigtimedwait() { DebugLog(__FUNCTION__"\n"); return 0; }
int madvise(void *addr, size_t length, int advice)
{
	DebugLog(__FUNCTION__"(0x%x, %d, %d)\n", addr, length, advice);
	return 0;
}
void* __timer_create() { DebugLog(__FUNCTION__"\n"); return 0; }
void* timerfd_create() { DebugLog(__FUNCTION__"\n"); return 0; }
void* timerfd_gettime() { DebugLog(__FUNCTION__"\n"); return 0; }
void* timerfd_settime() { DebugLog(__FUNCTION__"\n"); return 0; }
void* __accept4() { DebugLog(__FUNCTION__"\n"); return 0; }
void* __arm_fadvise64_64() { DebugLog(__FUNCTION__"\n"); return 0; }
void* __connect() { DebugLog(__FUNCTION__"\n"); return 0; }
void* __socket() { DebugLog(__FUNCTION__"\n"); return 0; }
void* fallocate64() { DebugLog(__FUNCTION__"\n"); return 0; }
int __openat(int dirfd, const char *pathname, int flags, int mode)
{
	DebugLog(__FUNCTION__"(%d, \"%s\", %d, %d)\n", dirfd, pathname, flags, mode);
	return 0;
}
void* init_module() { DebugLog(__FUNCTION__"\n"); return 0; }
void* klogctl() { DebugLog(__FUNCTION__"\n"); return 0; }
void* mincore() { DebugLog(__FUNCTION__"\n"); return 0; }

void* __timer_getoverrun() { DebugLog(__FUNCTION__"\n"); return 0; }
void* __timer_settime() { DebugLog(__FUNCTION__"\n"); return 0; }
void* __ptrace() { DebugLog(__FUNCTION__"\n"); return 0; }
void* __rt_sigprocmask() { DebugLog(__FUNCTION__"\n"); return 0; }
void* __rt_sigsuspend() { DebugLog(__FUNCTION__"\n"); return 0; }
void* pipe2() { DebugLog(__FUNCTION__"\n"); return 0; }
void* __timer_gettime() { DebugLog(__FUNCTION__"\n"); return 0; }
void* __ppoll() { DebugLog(__FUNCTION__"\n"); return 0; }
void* __timer_delete() { DebugLog(__FUNCTION__"\n"); return 0; }
void* __pselect6() { DebugLog(__FUNCTION__"\n"); return 0; }
void* setregid() { DebugLog(__FUNCTION__"\n"); return 0; }
void* setreuid() { DebugLog(__FUNCTION__"\n"); return 0; }
void* setresgid() { DebugLog(__FUNCTION__"\n"); return 0; }
void* settimeofday() { DebugLog(__FUNCTION__"\n"); return 0; }
void* splice() { DebugLog(__FUNCTION__"\n"); return 0; }
void* swapon() { DebugLog(__FUNCTION__"\n"); return 0; }
void* swapoff() { DebugLog(__FUNCTION__"\n"); return 0; }
void* tee() { DebugLog(__FUNCTION__"\n"); return 0; }
void* getresgid() { DebugLog(__FUNCTION__"\n"); return 0; }
void* _bridge_sendto() { DebugLog(__FUNCTION__"\n"); return 0; }
void* __getcpu() { DebugLog(__FUNCTION__"\n"); return 0; }
void* setsid() { DebugLog(__FUNCTION__"\n"); return 0; }
void* __rt_sigpending() { DebugLog(__FUNCTION__"\n"); return 0; }
void* __signalfd4() { DebugLog(__FUNCTION__"\n"); return 0; }
void* __reboot() { DebugLog(__FUNCTION__"\n"); return 0; }
void* ___rt_sigqueueinfo() { DebugLog(__FUNCTION__"\n"); return 0; }
void* _bridge_recvfrom() { DebugLog(__FUNCTION__"\n"); return 0; }
void* setpgid() { DebugLog(__FUNCTION__"\n"); return 0; }
void* renameat() { DebugLog(__FUNCTION__"\n"); return 0; }
void* setresuid() { DebugLog(__FUNCTION__"\n"); return 0; }
void* unlinkat() { DebugLog(__FUNCTION__"\n"); return 0; }
void* __sched_getaffinity() { DebugLog(__FUNCTION__"\n"); return 0; }
void* sched_get_priority_max() { DebugLog(__FUNCTION__"\n"); return 0; }
void* sched_get_priority_min() { DebugLog(__FUNCTION__"\n"); return 0; }
void* sched_rr_get_interval() { DebugLog(__FUNCTION__"\n"); return 0; }
void* sched_setaffinity() { DebugLog(__FUNCTION__"\n"); return 0; }
void* sched_setparam() { 
	DebugLog(__FUNCTION__"\n");
	return 0; 
}
void* __sigaction() { DebugLog(__FUNCTION__"\n"); return 0; }
void* __fstatfs64() { DebugLog(__FUNCTION__"\n"); return 0; }
void* symlinkat() { DebugLog(__FUNCTION__"\n"); return 0; }
void* __statfs64() { DebugLog(__FUNCTION__"\n"); return 0; }
void* umount2() { DebugLog(__FUNCTION__"\n"); return 0; }
void* wait4() { DebugLog(__FUNCTION__"\n"); return 0; }
void* __waitid() { DebugLog(__FUNCTION__"\n"); return 0; }
void* _bridge_setsockopt() { DebugLog(__FUNCTION__"\n"); return 0; }
void* fchown() { DebugLog(__FUNCTION__"\n"); return 0; }
void* _bridge_getsockname() { DebugLog(__FUNCTION__"\n"); return 0; }
void* gettimeofday() { DebugLog(__FUNCTION__"\n"); return 0; }
void* nanosleep() { DebugLog(__FUNCTION__"\n"); return 0; }
void* sys_Exit() { DebugLog(__FUNCTION__"\n"); return 0; }
void* _bridge_getsockopt() { DebugLog(__FUNCTION__"\n"); return 0; }
void* _bridge_bind() { DebugLog(__FUNCTION__"\n"); return 0; }
void* _bridge_getpeername() { DebugLog(__FUNCTION__"\n"); return 0; }
void* setpriority() { DebugLog(__FUNCTION__"\n"); return 0; }
void* socketpair() { DebugLog(__FUNCTION__"\n"); return 0; }
void* vfork() { DebugLog(__FUNCTION__"\n"); return 0; }
void* kill() { DebugLog(__FUNCTION__"\n"); return 0; }
void* setitimer() { DebugLog(__FUNCTION__"\n"); return 0; }
void* chdir() { DebugLog(__FUNCTION__"\n"); return 0; }
void* execve() { DebugLog(__FUNCTION__"\n"); return 0; }
void* tgkill() { DebugLog(__FUNCTION__"\n"); return 0; }
void* _bridge_clock_gettime_x86() { DebugLog(__FUNCTION__"\n"); return 0; }
void* _bridge_gettimeofday_x86() { DebugLog(__FUNCTION__"\n"); return 0; }
void* sched_getscheduler() { 
	//mm_dump_memory_mappings();
	//mm_dump_windows_memory_mappings(GetCurrentProcess());
	DebugLog(__FUNCTION__"\n");
	return 0;
}
void* sched_getparam() { DebugLog(__FUNCTION__"\n"); return 0; }
void* sigaltstack() { DebugLog(__FUNCTION__"\n"); return 0; }
void* prctl() { DebugLog(__FUNCTION__"\n"); return 0; }
void* sched_setscheduler() { DebugLog(__FUNCTION__"\n"); return 0; }
void* preadv64() { DebugLog(__FUNCTION__"\n"); return 0; }
void* pwritev64() { DebugLog(__FUNCTION__"\n"); return 0; }
void* process_vm_readv() { DebugLog(__FUNCTION__"\n"); return 0; }
void* process_vm_writev() { DebugLog(__FUNCTION__"\n"); return 0; }
void* readahead() { DebugLog(__FUNCTION__"\n"); return 0; }
void* readv() { DebugLog(__FUNCTION__"\n"); return 0; }
void* umask() { DebugLog(__FUNCTION__"\n"); return 0; }
void* __getpriority() { DebugLog(__FUNCTION__"\n"); return 0; }
void* fchdir() { DebugLog(__FUNCTION__"\n"); return 0; }
void* pwrite64() { DebugLog(__FUNCTION__"\n"); return 0; }
void* __llseek() { DebugLog(__FUNCTION__"\n"); return 0; }
void* prlimit64() { DebugLog(__FUNCTION__"\n"); return 0; }
void* __ioctl() { DebugLog(__FUNCTION__"\n"); return 0; }
void* setgroups() { DebugLog(__FUNCTION__"\n"); return 0; }
void* __fcntl64() { DebugLog(__FUNCTION__"\n"); return 0; }
void* fsync() { DebugLog(__FUNCTION__"\n"); return 0; }
void* _bridge_listen() { DebugLog(__FUNCTION__"\n"); return 0; }
void* recvmsg() { DebugLog(__FUNCTION__"\n"); return 0; }
void* recvmmsg() { DebugLog(__FUNCTION__"\n"); return 0; }
void* _bridge_shutdown() { DebugLog(__FUNCTION__"\n"); return 0; }
void* sched_yield() 
{ 
	//https://msdn.microsoft.com/en-us/library/dd627187(VS.85).aspx
	DebugLog(__FUNCTION__"\n");
	return 0;
}
void* ___fchmodat() { DebugLog(__FUNCTION__"\n"); return 0; }
void* sendfile() { DebugLog(__FUNCTION__"\n"); return 0; }
void* sendfile64() { DebugLog(__FUNCTION__"\n"); return 0; }
void* setfsgid() { DebugLog(__FUNCTION__"\n"); return 0; }
void* setfsuid() { DebugLog(__FUNCTION__"\n"); return 0; }
void* sethostname() { DebugLog(__FUNCTION__"\n"); return 0; }
void* setns() { DebugLog(__FUNCTION__"\n"); return 0; }
void* times() { DebugLog(__FUNCTION__"\n"); return 0; }
void* vmsplice() { DebugLog(__FUNCTION__"\n"); return 0; }
