#pragma once
#include <stdint.h>
#include "BridgeApiDef.h"
typedef struct {
	uint64_t flags;
	void*   reserved_addr;
	size_t  reserved_size;
	int     relro_fd;
	int     library_fd;
	uint64_t library_fd_offset;
} android_dlextinfo;

BRIDGE_API void dladdr();
BRIDGE_API const char* dlerror();
BRIDGE_API void dlclose();
BRIDGE_API void android_dlwarning();
BRIDGE_API void *dlsym(void *handle, const char *symbol);
BRIDGE_API void *dlopen(const char *filename, int flags);
BRIDGE_API void* dl_unwind_find_exidx(void* pc, int* pcount);
BRIDGE_API void android_get_LD_LIBRARY_PATH(char* buffer, size_t buffer_size);
BRIDGE_API void android_update_LD_LIBRARY_PATH(const char* ld_library_path);
BRIDGE_API void* android_dlopen_ext(const char* filename, int flag, const android_dlextinfo* extinfo);
BRIDGE_API void android_set_application_target_sdk_version(uint32_t target);
BRIDGE_API  /*struct android_namespace_t* */ void* android_create_namespace(const char* name, const char* ld_library_path, const char* default_library_path, uint64_t type,
	const char* permitted_when_isolated_path, /*android_namespace_t* */ void* parent);
BRIDGE_API bool android_init_namespaces(const char* public_ns_sonames, const char* anon_ns_library_path);


