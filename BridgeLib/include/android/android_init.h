#pragma once


#include "../BridgeApiDef.h"


BRIDGE_API void flinit(const wchar_t* rootDir, const wchar_t* dataDir);
BRIDGE_API void call_main(const wchar_t* moduleName);

BRIDGE_API int __system_property_get_hook(const char *name, char *value);
BRIDGE_API const void* __system_property_find_hook(const char *name);
BRIDGE_API int __system_property_add_hook(const char *name, unsigned int namelen, const char *value, unsigned int valuelen);
BRIDGE_API char* getenv_hook(const char *name);


BRIDGE_API void ClaimSignalChain(int signal ,
	void* oldaction );

BRIDGE_API void UnclaimSignalChain(int signal );

BRIDGE_API void InvokeUserSignalHandler(int sig ,
	void* info ,
	void* context );

BRIDGE_API void InitializeSignalChain();

BRIDGE_API void EnsureFrontOfChain(int signal ,
	void* expected_action );

BRIDGE_API void SetSpecialSignalHandlerFn(int signal ,
	void* fn );


