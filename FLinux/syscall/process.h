
#pragma once

#include <common/types.h>
#include <common/utsname.h>
#include <lib/slist.h>

#include <stdbool.h>
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#define STACK_SIZE	1048576

void process_init();
int process_fork(HANDLE process);
void process_afterfork_parent();
void process_afterfork_child(void *stack_base, pid_t pid);
void process_shutdown();
void *process_get_stack_base();
void *process_get_stack_limit();
pid_t process_init_child(DWORD win_pid, DWORD win_tid, HANDLE process_handle);
void process_thread_entry(pid_t tid);
pid_t process_create_thread(DWORD win_tid);

__declspec(noreturn) void process_exit(int exit_code, int exit_signal);
__declspec(noreturn) void thread_exit(int exit_code, int exit_signal);
bool process_pid_exist(pid_t pid);
pid_t process_get_pid();
pid_t process_get_ppid();
pid_t process_get_tgid(pid_t pid);
pid_t process_get_pgid(pid_t pid);
pid_t process_get_sid();

enum
{
	PROCESS_QUERY_STAT,		/* /proc/[pid]/stat */
	PROCESS_QUERY_MAPS,		/* /proc/[pid]/maps */
};
int process_query(int query_type, char *buf);
int process_query_pid(pid_t pid, int query_type, char *buf);
