#include "pch.h"

#define DLL_EXPORT
#include "bridgeapi.h"
#include "bionic/bionic_tls.h"
#include "tools.h"

extern "C" int __set_tls(void* tls);

extern DWORD g_dwBionicTlsIndex; // TLS mapping table

void** __get_tls() {
	
	//OutputDebugStringA(__FUNCTION__"\n");
	//TODO: improve performance
	return reinterpret_cast<void**> (TlsGetValue(g_dwBionicTlsIndex));
}

int __set_tls(void* tls)
{
	DebugLog(__FUNCTION__" (0x%x)\n", tls);

	return !TlsSetValue(g_dwBionicTlsIndex, tls) ? -1 : 1;

}

