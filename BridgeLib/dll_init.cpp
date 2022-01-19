#include "pch.h"

#define DLL_EXPORT
#include "dll_init.h"
#include "kernel_helpers.h"
#include "tools.h"
#include "bionic/bionic_tls.h"
#include <vector>
#include <Psapi.h>


static bool s_libc_initialized = false;
typedef void(*__libc_init_tls_bridge_func)(void* args_raw);
extern "C" void** __get_tls();


int libil_offset = -0x22a038;
int libcxx_offset = -0x2e824;
int libart_offset = -0x956b8;

std::vector<ModuleRuntimeInfo> _modules;

void install_breakpoint(void* pcode)
{
	DWORD oldProtect;
	if (VirtualProtectFromApp(pcode, 8, PAGE_READWRITE, &oldProtect) != 0)
	{

		*(int*)pcode = 0xE1200070;

		/*FlushInstructionCache(
		GetCurrentProcess(),
		pcode,
		8
		);*/

		DWORD prevProt;

		if (!VirtualProtectFromApp(pcode, 8, oldProtect, &prevProt))
		{
			DWORD err = GetLastError();
		}
	}
}

int __dll_init(ModuleInfo32* moduleInfo, uint32_t ul_reason_for_call)
{
	LPVOID lpvData;
	BOOL fIgnore;

	char tmp[260];
	GetModuleFileNameA((HMODULE)moduleInfo->moduleBase, tmp, sizeof(tmp));

	DebugLog("__dll_init %s\n", tmp);


	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
		// copy import functions pointers to GOT
		uint32_t* ptr = moduleInfo->mapTableOffset;
		int32_t c = moduleInfo->mapTableCount * 2 - 1;
		while (c > 0)
		{
			uintptr_t* symbol = (uintptr_t*)(((uint8_t*)ptr[c--]) + moduleInfo->moduleBase);
			uintptr_t* dest = (uintptr_t*)(((uint8_t*)ptr[c--]) + moduleInfo->moduleBase);
			*dest = *symbol;
		}

		// libc should be always first
		if (!s_libc_initialized)
		{
			HMODULE libc_handle = (HMODULE)moduleInfo->moduleBase;

			__libc_init_tls_bridge_func __libc_init_tls_bridge = (__libc_init_tls_bridge_func)GetProcAddress(libc_handle, "__libc_init_tls_bridge");
			if (__libc_init_tls_bridge != NULL)
			{
				__libc_init_tls_bridge(build_kernel_args());
			}
			else
			{
				__debugbreak();
			}
			s_libc_initialized = true;

			SYSTEM_INFO si;
			GetSystemInfo(&si);

			/*CreateProcess()*/
		}

		// RnD start
		if (strstr(tmp, "libc++.dll") != NULL)
		{
			//install_breakpoint((void*)(moduleInfo->moduleBase + 0x0068640 + libcxx_offset));
			int addr = moduleInfo->moduleBase + 0x0068640 + libcxx_offset;
			DebugLog("libc++: 0x%x\n", addr);
		}


		if (strstr(tmp, "libart.dll") != NULL)
		{
			//install_breakpoint((void*)(moduleInfo->moduleBase + 0x0068640 + libcxx_offset));
			int addr = moduleInfo->moduleBase + 0x00EBCA0 + libart_offset;
			DebugLog("libart: 0x%x\n", addr);
		}
		// RnD end 

		typedef void(*InitFunction)();

		uintptr_t* preInitArray = 
			(uintptr_t*)(moduleInfo->preInitArrayOffset + moduleInfo->moduleBase);

		for (int i = 0; i < moduleInfo->preInitArrayCount; i++)
		{

			InitFunction fn = (InitFunction)(preInitArray[i] + moduleInfo->moduleBase);
			DebugLog("Calling module preinit constructor 0x%x\n", fn);

			fn();
		}

		//RnD
		
		uintptr_t* initArray = 
			(uintptr_t*)(moduleInfo->initArrayOffset + moduleInfo->moduleBase);

		for (int i = 0; i < moduleInfo->initArrayCount; i++)
		{
			
			InitFunction fn = (InitFunction)(initArray[i] + moduleInfo->moduleBase);
			DebugLog("Calling module constructor 0x%x\n", fn);

			fn();
		}
		

		ModuleRuntimeInfo mi;
		mi.handle = moduleInfo->moduleBase;
		MODULEINFO win_mi;
		if 
		(
			GetModuleInformation
		    (
				GetCurrentProcess(),
				(HMODULE)mi.handle,
				&win_mi,
				sizeof(win_mi)
			)
		)
		{
			mi.moduleStart = win_mi.lpBaseOfDll;
			mi.moduleEnd = (char*)win_mi.lpBaseOfDll + win_mi.SizeOfImage;
		}
		else
		{
			mi.moduleStart = 0;
			mi.moduleEnd = 0;
		}


		mi.unwindIdxPtr = (void*)(moduleInfo->moduleBase + moduleInfo->unwindIdxOffset);
		mi.unwindIdxSize = moduleInfo->unwindIdxSize;

		_modules.push_back(mi);

	}//if ...DLL_PROCESS_ATTACH


	return TRUE;

}//__dll_init


int get_module_name(void* ptr, char* name, int size)
{
	for (auto &i : _modules)
	{
		if (ptr > i.moduleStart && ptr < i.moduleEnd)
		{
			GetModuleFileNameA((HMODULE)i.moduleStart, name, size);
			const char* namestart = strrchr(name, '\\');
			if (namestart != NULL)
			{
				strcpy_s(name, size, namestart+1);
			}
			return 1;
		}
	}

	return 0;
}



