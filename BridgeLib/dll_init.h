#pragma once
#include <cstdint>
#include <vector>
#include "BridgeApiDef.h"


typedef void (*entrypoint_t)(...);

struct ModuleInfo32
{
	uint32_t	moduleBase;
	uint32_t*	mapTableOffset;
	uint32_t	mapTableCount;
	uint8_t*	preInitArrayOffset;
	uint32_t	preInitArrayCount;
	uint8_t*	initArrayOffset;
	uint32_t	initArrayCount;
	uint8_t*	finiArrayOffset;
	uint32_t	finiArrayCount;
	uint32_t    unwindIdxOffset;
	uint32_t    unwindIdxSize;

};

struct ModuleRuntimeInfo
{
	uint32_t	handle;
	void*    unwindIdxPtr;
	uint32_t    unwindIdxSize;
	void* moduleStart;
	void* moduleEnd;

};

extern std::vector<ModuleRuntimeInfo> _modules;
extern "C" int get_module_name(void* ptr, char* name, int size);

BRIDGE_API int __dll_init(ModuleInfo32* moduleInfo, uint32_t ul_reason_for_call);

