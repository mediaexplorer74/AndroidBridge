#pragma once

//#include "asm-generic\posix_types.h"
#include <common/statfs.h>


#include "BridgeApiDef.h"


BRIDGE_API void __cxa_finalize();
BRIDGE_API void __cxa_atexit();
BRIDGE_API void __stack_chk_fail();
BRIDGE_API void __register_atfork();

BRIDGE_API int __cxa_begin_cleanup;
BRIDGE_API int __cxa_type_match;
BRIDGE_API int __cxa_call_unexpected;
BRIDGE_API int __cxa_end_cleanup;
BRIDGE_API void* __data_start;
BRIDGE_API void* data_start;
BRIDGE_API void* __google_potentially_blocking_region_begin;
BRIDGE_API void* __google_potentially_blocking_region_end;
BRIDGE_API const char* __progname;

BRIDGE_API long _bridge_syscall(long __number, ...);

//libc
BRIDGE_API void* __gnu_Unwind_Find_exidx(void* pc, int* pcount);


// bionic
BRIDGE_API pid_t __bionic_clone(uint32_t flags, void* child_stack, int* parent_tid, void* tls, int* child_tid, int(*fn)(void*), void* arg);

// libandroid
BRIDGE_API void __android_log_print();

// libprocessgroup - temporary here because wrong DLL after conversion
BRIDGE_API void removeAllProcessGroups();
BRIDGE_API void createProcessGroup();
BRIDGE_API void killProcessGroup();

//libc
BRIDGE_API  int adjtimex(struct timex *buf);
BRIDGE_API  int cacheflush();
BRIDGE_API  int clock_adjtime();
BRIDGE_API  int clock_settime();
BRIDGE_API  int delete_module();
BRIDGE_API  int flistxattr();
BRIDGE_API  int getitimer();
BRIDGE_API  int sync();
BRIDGE_API  void** __get_tls();
BRIDGE_API  int __set_tls(void* ptr);
BRIDGE_API  void* clock_getres();
BRIDGE_API  void* getrlimit();
BRIDGE_API  void* read();
BRIDGE_API  void* clock_gettime();
BRIDGE_API  void* write();
BRIDGE_API  void* __brk();
BRIDGE_API  void* fchownat();
BRIDGE_API  void* __getdents64();
BRIDGE_API  void* ___clock_nanosleep();
BRIDGE_API  void* __exit();
BRIDGE_API  void* ___close();
BRIDGE_API  void* lseek();
BRIDGE_API  void* dup3();
BRIDGE_API  void* getxattr();
BRIDGE_API  void* ___fgetxattr();
BRIDGE_API  void* epoll_create1();
BRIDGE_API  void* __epoll_pwait();
BRIDGE_API  void* ___faccessat();
BRIDGE_API  void* ___fchmod();
BRIDGE_API  long __set_tid_address(int *tidptr);
BRIDGE_API  void* ___fsetxattr();
BRIDGE_API  void* setxattr();
BRIDGE_API  void* ftruncate64();
BRIDGE_API  void* utimensat();
BRIDGE_API  void* __getcwd();
BRIDGE_API  void* uname();
BRIDGE_API  void* getuid();
BRIDGE_API  void* getpgid();
BRIDGE_API  void* __getpid();
BRIDGE_API  void* inotify_init1();
BRIDGE_API  void* munmap();
BRIDGE_API  void* linkat();
BRIDGE_API  void* mknodat();
BRIDGE_API  void* mkdirat();
BRIDGE_API  void* __rt_sigtimedwait();
BRIDGE_API  int madvise(void *addr, size_t length, int advice);
BRIDGE_API  void* __timer_create();
BRIDGE_API  void* timerfd_create();
BRIDGE_API  void* timerfd_gettime();
BRIDGE_API  void* timerfd_settime();
BRIDGE_API  void* __accept4();
BRIDGE_API  void* __arm_fadvise64_64();
BRIDGE_API  void* __connect();
BRIDGE_API  void* __socket();
BRIDGE_API  void* fallocate64();
BRIDGE_API  int __openat(int dirfd, const char *pathname, int flags, int mode);
BRIDGE_API  void* __timer_getoverrun();
BRIDGE_API  void* __timer_settime();
BRIDGE_API  void* __ptrace();
BRIDGE_API  void* __rt_sigprocmask();
BRIDGE_API  void* __rt_sigsuspend();
BRIDGE_API  void* pipe2();
BRIDGE_API  void* __timer_gettime();
BRIDGE_API  void* __ppoll();
BRIDGE_API  void* __timer_delete();
BRIDGE_API  void* __pselect6();
BRIDGE_API  void* setregid();
BRIDGE_API  void* setreuid();
BRIDGE_API  void* setresgid();
BRIDGE_API  void* settimeofday();
BRIDGE_API  void* splice();
BRIDGE_API  void* swapon();
BRIDGE_API  void* tee();
BRIDGE_API  void* swapoff();
BRIDGE_API  void* getresgid();
BRIDGE_API  void* init_module();
BRIDGE_API  void* klogctl();
BRIDGE_API  void* mincore();
BRIDGE_API  void* _bridge_sendto(); 
BRIDGE_API  void* sendfile();
BRIDGE_API  void* sendfile64();
BRIDGE_API  void* setfsgid();
BRIDGE_API  void* setfsuid();
BRIDGE_API  void* sethostname();
BRIDGE_API  void* setns();
BRIDGE_API  void* __getcpu();
BRIDGE_API  void* setsid();
BRIDGE_API  void* __rt_sigpending();
BRIDGE_API  void* __signalfd4();
BRIDGE_API  void* __reboot();
BRIDGE_API  void* ___rt_sigqueueinfo();
BRIDGE_API  void* _bridge_recvfrom();
BRIDGE_API  void* setpgid();
BRIDGE_API  void* renameat();
BRIDGE_API  void* setresuid();
BRIDGE_API  void* unlinkat();
BRIDGE_API  void* __sched_getaffinity();
BRIDGE_API  void* sched_get_priority_max();
BRIDGE_API  void* sched_get_priority_min();
BRIDGE_API  void* sched_rr_get_interval();
BRIDGE_API  void* sched_setaffinity();
BRIDGE_API  void* sched_setparam();
BRIDGE_API  void* __sigaction();
BRIDGE_API  void* __fstatfs64();
BRIDGE_API  void* symlinkat();
BRIDGE_API  void* __statfs64();
BRIDGE_API  void* umount2();
BRIDGE_API  void* wait4();
BRIDGE_API  void* __waitid();
BRIDGE_API  intptr_t __mmap2(void *addr, size_t length, int prot, int flags, int fd, lx_off_t pgoffset);
BRIDGE_API  void* _bridge_setsockopt();
BRIDGE_API  void* fchown();
BRIDGE_API  void* _bridge_getsockname();
BRIDGE_API  void* gettimeofday();
BRIDGE_API  void* nanosleep();
BRIDGE_API  void* sys_Exit();
BRIDGE_API  void* _bridge_getsockopt();
BRIDGE_API  void* _bridge_bind();
BRIDGE_API  void* _bridge_getpeername();
BRIDGE_API  void* setpriority();
BRIDGE_API  void* socketpair();
BRIDGE_API  void* vfork();
BRIDGE_API  void* kill();
BRIDGE_API  void* setitimer();
BRIDGE_API  void* chdir();
BRIDGE_API  void* execve();
BRIDGE_API  void* tgkill();
BRIDGE_API  void* sched_getscheduler();
BRIDGE_API  void* sched_getparam();
BRIDGE_API  int mprotect(void *addr, size_t len, int prot);
BRIDGE_API  void* sigaltstack();
BRIDGE_API  void* prctl();
BRIDGE_API  void* sched_setscheduler();
BRIDGE_API  void* preadv64();
BRIDGE_API  void* pwritev64();
BRIDGE_API  void* process_vm_readv();
BRIDGE_API  void* process_vm_writev();
BRIDGE_API  void* readahead();
BRIDGE_API  void* readv();
BRIDGE_API  void* umask();
BRIDGE_API  void* __getpriority();
BRIDGE_API  void* fchdir();
BRIDGE_API  void* pwrite64();
BRIDGE_API  void* __llseek();
BRIDGE_API  void* prlimit64();
BRIDGE_API  void* __ioctl();
BRIDGE_API  void* setgroups();
BRIDGE_API  void* __fcntl64();
BRIDGE_API  void* fsync();
BRIDGE_API  void* _bridge_listen();
BRIDGE_API  void* recvmsg();
BRIDGE_API  void* recvmmsg();
BRIDGE_API  void* _bridge_shutdown();
BRIDGE_API  void* sched_yield();
BRIDGE_API  void* ___fchmodat();
BRIDGE_API  void* times();
BRIDGE_API  void* vmsplice();

BRIDGE_API  void* _bridge_clock_gettime_x86();
BRIDGE_API  void* _bridge_gettimeofday_x86();