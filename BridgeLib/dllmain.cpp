#include "pch.h"
#include "dll_init.h"
#include "bionic/bionic_tls.h"
#include "kernel_helpers.h"
#include "tools.h"
#include "ProcessHost.h"
#include <Objbase.h>

DWORD g_dwBionicTlsIndex; // TLS mapping table

LONG WINAPI MyUnhandledExceptionFilter(PEXCEPTION_POINTERS p)
{
	DebugLog("Exception %d", p->ExceptionRecord->ExceptionCode);
	return EXCEPTION_CONTINUE_SEARCH;
}

BOOL APIENTRY DllMain(HMODULE /* hModule */, DWORD ul_reason_for_call, LPVOID /* lpReserved */)
{
	LPVOID lpvData;
	BOOL fIgnore;

	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{

		LPTOP_LEVEL_EXCEPTION_FILTER pOriginalFilter = SetUnhandledExceptionFilter(MyUnhandledExceptionFilter);
		// Allocate TLS slot
		if ((g_dwBionicTlsIndex = TlsAlloc()) == TLS_OUT_OF_INDEXES)
		{
			OutputDebugStringA("DllMain: TlsAlloc failed\n");
			//TODO: free previous slots
			return FALSE;
		}

		//RunHost();
	}


	if (ul_reason_for_call == DLL_PROCESS_ATTACH || ul_reason_for_call == DLL_THREAD_ATTACH)
	{
		// Initialize TLS slot for this thread
		lpvData = (LPVOID)LocalAlloc(LPTR, 256);
		if (lpvData != NULL)
		{
			fIgnore = TlsSetValue(g_dwBionicTlsIndex, lpvData);

			//((DWORD*)lpvData)[TLS_SLOT_THREAD_ID] = GetCurrentThreadId();
		}
	}

	if (ul_reason_for_call == DLL_PROCESS_DETACH || ul_reason_for_call == DLL_THREAD_DETACH)
	{
		// Release allocated memory
		lpvData = TlsGetValue(g_dwBionicTlsIndex);
		if (lpvData != NULL)
			LocalFree((HLOCAL)lpvData);

	}


	if (ul_reason_for_call == DLL_PROCESS_DETACH)
	{
		// Free TLS slots
		TlsFree(g_dwBionicTlsIndex);
	}

    return TRUE;
}
