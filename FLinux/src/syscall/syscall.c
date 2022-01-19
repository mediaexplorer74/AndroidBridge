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

#include <syscall/mm.h>
#include <syscall/process.h>
#include <syscall/syscall.h>
#include <syscall/syscall_dispatch.h>
#include <syscall/tls.h>
#include <log.h>
#include <platform.h>


#include <stdint.h>
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <onecore_types.h>

extern void *mm_check_read_begin, *mm_check_read_end, *mm_check_read_fail;
extern void *mm_check_read_string_begin, *mm_check_read_string_end, *mm_check_read_string_fail;
extern void *mm_check_write_begin, *mm_check_write_end, *mm_check_write_fail;

extern int sys_gettimeofday(struct timeval *tv, struct timezone *tz);
extern intptr_t sys_time(intptr_t *t);
extern int get_module_name(void* ptr, char* name, int size);

void print_debug_info(PCONTEXT context)
{
	mm_dump_memory_mappings();
	mm_dump_windows_memory_mappings(GetCurrentProcess());
	mm_dump_stack_trace(context);
#ifdef defined(_M_X64)
	log_info("RAX: 0x%p", context->Rax);
	log_info("RCX: 0x%p", context->Rcx);
	log_info("RDX: 0x%p", context->Rdx);
	log_info("RBX: 0x%p", context->Rbx);
	log_info("RSP: 0x%p", context->Rsp);
	log_info("RBP: 0x%p", context->Rbp);
	log_info("RSI: 0x%p", context->Rsi);
	log_info("RDI: 0x%p", context->Rdi);
	log_info("R8:  0x%p", context->R8);
	log_info("R9:  0x%p", context->R9);
	log_info("R10: 0x%p", context->R10);
	log_info("R11: 0x%p", context->R11);
	log_info("R12: 0x%p", context->R12);
	log_info("R13: 0x%p", context->R13);
	log_info("R14: 0x%p", context->R14);
	log_info("R15: 0x%p", context->R15);
#elif defined(_M_IX86)
	log_info("EAX: 0x%p", context->Eax);
	log_info("ECX: 0x%p", context->Ecx);
	log_info("EDX: 0x%p", context->Edx);
	log_info("EBX: 0x%p", context->Ebx);
	log_info("ESP: 0x%p", context->Esp);
	log_info("EBP: 0x%p", context->Ebp);
	log_info("ESI: 0x%p", context->Esi);
	log_info("EDI: 0x%p", context->Edi);
#elif defined(_M_ARM)
	log_info("R0: 0x%p", context->R0);
	log_info("R1: 0x%p", context->R1);
	log_info("R2: 0x%p", context->R2);
	log_info("R3: 0x%p", context->R3);
	log_info("R4: 0x%p", context->R4);
	log_info("R5: 0x%p", context->R5);
	log_info("R6: 0x%p", context->R6);
	log_info("R7: 0x%p", context->R7);
	log_info("R8: 0x%p", context->R8);
	log_info("R9: 0x%p", context->R9);
	log_info("R10: 0x%p", context->R10);
	log_info("R11: 0x%p", context->R11);
	log_info("R12: 0x%p", context->R12);
	log_info("LR: 0x%p", context->Lr);
	log_info("SP: 0x%p", context->Sp);
	log_info("PC: 0x%p", context->Pc);
	print_stack_trace(context->Sp, 200);
#endif


}

void print_stack_trace(void* sp, int max_records)
{
	char module_name[260];
	//TPDP: get real stack size
	int max_iter = max_records;

	void* stack_base = process_get_stack_base();
	void* stack_limit = process_get_stack_limit();

	if (sp > stack_limit && sp < stack_base)
	{
		max_iter = (uintptr_t*)stack_base - (uintptr_t*)sp;
	}

	for (uint32_t i = 0; i < max_iter; i++)
	{
		void* ptr = *((uint32_t*)sp + i);
		if (get_module_name(ptr, module_name, 260))
		{
			MEMORY_BASIC_INFORMATION info;
			VirtualQueryEx(GetCurrentProcess(), ptr, &info, sizeof(info));
			if (info.State != MEM_FREE)
			{
				char filename[1024];
				char *access;
				switch (info.Protect & 0xFF)
				{
				case PAGE_EXECUTE:
				case PAGE_EXECUTE_READ:
				case PAGE_EXECUTE_READWRITE:
				case PAGE_EXECUTE_WRITECOPY:
					log_info("0x%p: %s", ptr, module_name);
					break;
				}
			}
					
		}
	}
}


static LONG CALLBACK exception_handler(PEXCEPTION_POINTERS ep)
{
	if (ep->ExceptionRecord->ExceptionCode == DBG_CONTROL_BREAK 
		|| ep->ExceptionRecord->ExceptionCode == DBG_CONTROL_C 
		|| ep->ExceptionRecord->ExceptionCode == STATUS_BREAKPOINT
		|| ep->ExceptionRecord->ExceptionCode == STATUS_ILLEGAL_INSTRUCTION)
	{
		log_info("debugger breakpoint");
		print_debug_info(ep->ContextRecord);
		return EXCEPTION_CONTINUE_SEARCH;
	}
	if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT)
		return EXCEPTION_CONTINUE_SEARCH;
	if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_INVALID_HANDLE)
		return EXCEPTION_CONTINUE_SEARCH;
	if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
	{
#if defined(_M_X64) || defined(_M_IX86)
		uint8_t* code = (uint8_t *)ep->ContextRecord->Xip;
#elif  defined(_M_ARM)
		uint8_t* code = (uint8_t *)ep->ContextRecord->Pc;
#endif
		if (ep->ExceptionRecord->ExceptionInformation[0] == 8)
		{
#if  defined(_M_ARM)
			//check if app is calling any kernel user helper - https://www.kernel.org/doc/Documentation/arm/kernel_user_helpers.txt
			if (code == 0xffff0fe0) //void * __kuser_get_tls(void);
			{
				ep->ContextRecord->R0 = __get_tls();
				ep->ContextRecord->Pc = ep->ContextRecord->Lr;

				return EXCEPTION_CONTINUE_EXECUTION;
			}

			if (code == 0xffff0fc0) //int __kuser_cmpxchg(int32_t oldval, int32_t newval, volatile int32_t *ptr);
			{
				ep->ContextRecord->R0 = __kuser_cmpxchg(ep->ContextRecord->R0, ep->ContextRecord->R1, ep->ContextRecord->R2);
				ep->ContextRecord->Pc = ep->ContextRecord->Lr;

				return EXCEPTION_CONTINUE_EXECUTION;
			}


			if (code == 0xffff0fa0) //void __kuser_memory_barrier(void);
			{
				__kuser_memory_barrier();
				ep->ContextRecord->Pc = ep->ContextRecord->Lr;

				return EXCEPTION_CONTINUE_EXECUTION;
			}

			if (code == 0xffff0f60) //int __kuser_cmpxchg64(const int64_t *oldval, const int64_t *newval, volatile int64_t *ptr);
			{
				ep->ContextRecord->R0 = __kuser_cmpxchg64(ep->ContextRecord->R0, ep->ContextRecord->R1, ep->ContextRecord->R2);
				ep->ContextRecord->Pc = ep->ContextRecord->Lr;

				return EXCEPTION_CONTINUE_EXECUTION;
			}
			
#endif
			/* DEP problem */
			if (mm_handle_page_fault(code, false))
				return EXCEPTION_CONTINUE_EXECUTION;
			else
			{
				/* The problem may be actually in the next page */
				if (mm_handle_page_fault(code + PAGE_SIZE, false))
					return EXCEPTION_CONTINUE_EXECUTION;
			}
		}
		else
		{
#if  defined(_M_ARM)
			if (ep->ExceptionRecord->ExceptionInformation[1] == 0xffff0ffc)
			{
				log_warning("__kuser_helper_version not supported yet");
			}

#elif defined(_M_IX86)
			//test for reading TLS
			if (*code == 0x65)
			{
				uint8_t* code1 = code + 1;

				if (*code1 == 0xa1) //eax
				{
					 ep->ContextRecord->Eax = ((char*)__get_tls())[ep->ExceptionRecord->ExceptionInformation[1]];
					 return EXCEPTION_CONTINUE_EXECUTION;
				}
				else if (*code1 == 0x8b) //others
				{
					uint8_t* code2 = code + 2;
					switch (*code2)
					{
					case 0x0d:
						ep->ContextRecord->Ecx = ((char*)__get_tls())[ep->ExceptionRecord->ExceptionInformation[1]];
						return EXCEPTION_CONTINUE_EXECUTION;
					case 0x15:
						ep->ContextRecord->Edx = ((char*)__get_tls())[ep->ExceptionRecord->ExceptionInformation[1]];
						return EXCEPTION_CONTINUE_EXECUTION;
					case 0x35:
						ep->ContextRecord->Esi = ((char*)__get_tls())[ep->ExceptionRecord->ExceptionInformation[1]];
						return EXCEPTION_CONTINUE_EXECUTION;
					case 0x3d:
						ep->ContextRecord->Edi = ((char*)__get_tls())[ep->ExceptionRecord->ExceptionInformation[1]];
						return EXCEPTION_CONTINUE_EXECUTION;
					default:
						break;
					}

				}
			}
#endif

			/* Read/write problem */
			log_info("IP: 0x%p", code);
			bool is_write = (ep->ExceptionRecord->ExceptionInformation[0] == 1);
			if (mm_handle_page_fault((void *)ep->ExceptionRecord->ExceptionInformation[1], is_write))
				return EXCEPTION_CONTINUE_EXECUTION;
			void *ip = (void *)code;

			//char buf[65536];
			//mm_get_maps(buf);
			//log_error("/proc/self/maps:\n %s", buf);
/*			if (ip >= &mm_check_read_begin && ip <= &mm_check_read_end)
			{
				ep->ContextRecord->Xip = (XWORD)&mm_check_read_fail;
				log_warning("mm_check_read() failed at location 0x%x", ep->ExceptionRecord->ExceptionInformation[1]);
				return EXCEPTION_CONTINUE_EXECUTION;
			}
			if (ip >= &mm_check_read_string_begin && ip <= &mm_check_read_string_end)
			{
				ep->ContextRecord->Xip = (XWORD)&mm_check_read_string_fail;
				log_warning("mm_check_read_string() failed at location 0x%x", ep->ExceptionRecord->ExceptionInformation[1]);
				return EXCEPTION_CONTINUE_EXECUTION;
			}
			if (ip >= &mm_check_write_begin && ip <= &mm_check_write_end)
			{
				ep->ContextRecord->Xip = (XWORD)&mm_check_write_fail;
				log_warning("mm_check_write() failed at location 0x%x", ep->ExceptionRecord->ExceptionInformation[1]);
				return EXCEPTION_CONTINUE_EXECUTION;
			}
*/		}
		if (ep->ExceptionRecord->ExceptionInformation[0] == 0)
			log_error("Page fault(read): %p at %p", ep->ExceptionRecord->ExceptionInformation[1], code);
		else if (ep->ExceptionRecord->ExceptionInformation[0] == 1)
			log_error("Page fault(write): %p at %p", ep->ExceptionRecord->ExceptionInformation[1], code);
		else if (ep->ExceptionRecord->ExceptionInformation[0] == 8)
			log_error("Page fault(DEP): %p at %p", ep->ExceptionRecord->ExceptionInformation[1], code);

	}
	log_info("Application crashed, dumping debug information...");
	print_debug_info(ep->ContextRecord);
	RemoveVectoredExceptionHandler(exception_handler);
	/* If we come here we're sure to crash, so gracefully close logging */
	log_shutdown();
	return EXCEPTION_CONTINUE_SEARCH;
}



void install_syscall_handler()
{
	if (!AddVectoredExceptionHandler(TRUE, exception_handler))
		log_error("AddVectoredExceptionHandler() failed.");
}
