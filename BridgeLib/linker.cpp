#include "pch.h"

#define DLL_EXPORT
#include "linker.h"
#include "dll_init.h"
#include "tools.h"



HMODULE get_linker_handle()
{
	static HMODULE linker = NULL;

	if (linker == NULL)
	{
		linker = LoadPackagedLibrary(L"linker.dll", 0);

		entrypoint_t __linker_bridge_init = (entrypoint_t)::GetProcAddress(linker, "__linker_bridge_init");
		__linker_bridge_init();
	}

	return linker;
}


void dladdr()
{
	DebugLog(__FUNCTION__"\n");
}


typedef const char*(*dlerror_t)();

const char* dlerror()
{
	DebugLog(__FUNCTION__"\n");
	dlerror_t dlerror_orig = (dlerror_t)::GetProcAddress(get_linker_handle(), "dlerror");
	return dlerror_orig();
}

void *dlopen(const char *filename, int flags)
{
	DebugLog(__FUNCTION__"(\"%s\", %d)\n", filename, flags);

	if (!strcmp(filename, "NianticLabsPlugin"))
		filename = "libpogo.dll";


	wchar_t filenamew[256];

	if (MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, filename, -1, filenamew, sizeof(filenamew) / sizeof(wchar_t)) == 0)
	{
		return NULL;
	}


	HMODULE ret = LoadPackagedLibrary(filenamew, 0);

	if (ret == NULL)
	{
		size_t len = wcslen(filenamew);
		if (len > 3 && len < 254 && filenamew[len - 3] == '.')
		{
			filenamew[len - 2] = 'd';
			filenamew[len - 1] = 'l';
			filenamew[len + 0] = 'l';
			filenamew[len + 1] = 0;

			ret = LoadPackagedLibrary(filenamew, 0);
		}
	}

	return ret;
}

typedef void *(*dlsym_t)(void *handle, const char *symbol);

void *dlsym(void *handle, const char *symbol)
{
	DebugLog(__FUNCTION__"(0x%x, \"%s\")\n", handle, symbol);

	void* fn = GetProcAddress((HMODULE)handle, symbol);
	if (fn == NULL && GetLastError() == ERROR_MOD_NOT_FOUND)
	{
		dlsym_t dlsym_orig = (dlsym_t)::GetProcAddress(get_linker_handle(), "dlsym");
		fn = dlsym_orig(handle, symbol);
	}

	return fn;
}

void dlclose()
{
	DebugLog(__FUNCTION__"\n");
}



void* dl_unwind_find_exidx(void* pc, int* pcount)
{
	int Frame = 0;
	DebugLog(__FUNCTION__"(0x%x, %d)\n", pc, pcount);

	for (auto &i : _modules)
	{
		if (pc > i.moduleStart && pc < i.moduleEnd)
		{
			DebugLog("Unwind idx found at 0x%x, size %d", i.unwindIdxPtr, i.unwindIdxSize);
			//print_stack_trace(&Frame, 200);
			*pcount = i.unwindIdxSize / 8;
			return i.unwindIdxPtr;
		}
	}
	*pcount = 0;
	return NULL;
}

void* __gnu_Unwind_Find_exidx(void* pc, int* pcount)
{
	return dl_unwind_find_exidx(pc, pcount);
}


typedef int(*dl_iterate_phdr_t)(void* callback, void* data);

int dl_iterate_phdr(void* callback, void* data)
{
	DebugLog(__FUNCTION__"\n");

	dl_iterate_phdr_t dl_iterate_phdr_orig = (dl_iterate_phdr_t)::GetProcAddress(get_linker_handle(), "dl_iterate_phdr");
	return dl_iterate_phdr_orig(callback, data);
}

typedef void(*android_get_LD_LIBRARY_PATH_t)(char* buffer, size_t buffer_size);

void android_get_LD_LIBRARY_PATH(char* buffer, size_t buffer_size)
{
	DebugLog(__FUNCTION__"\n");
	//android_get_LD_LIBRARY_PATH_t android_get_LD_LIBRARY_PATH_orig = (android_get_LD_LIBRARY_PATH_t)::GetProcAddress(get_linker_handle(), "_Z27android_get_LD_LIBRARY_PATHPcj");
	// crashes android_get_LD_LIBRARY_PATH_orig(buffer, buffer_size);

}
void android_update_LD_LIBRARY_PATH(const char* ld_library_path)
{
	DebugLog(__FUNCTION__"\n");
}

typedef void* (*android_dlopen_ext_t)(const char* filename, int flag, const android_dlextinfo* extinfo);

void* android_dlopen_ext(const char* filename, int flag, const android_dlextinfo* extinfo)
{
	DebugLog(__FUNCTION__"\n");

	android_dlopen_ext_t android_dlopen_ext_orig = (android_dlopen_ext_t)::GetProcAddress(get_linker_handle(), "android_dlopen_ext");

	return android_dlopen_ext_orig(filename, flag, extinfo);
}

void android_dlwarning()
{
	DebugLog(__FUNCTION__"\n");
}

static uint32_t target_android_sdk_version = 0;

void android_set_application_target_sdk_version(uint32_t target)
{
	DebugLog(__FUNCTION__"(%d)\n", target);
	target_android_sdk_version = target;
}

uint32_t android_get_application_target_sdk_version()
{
	DebugLog(__FUNCTION__"\n");
	return target_android_sdk_version;
}

/*struct android_namespace_t* */ void* android_create_namespace(const char* name, const char* ld_library_path, const char* default_library_path, uint64_t type,
	const char* permitted_when_isolated_path, /*android_namespace_t* */ void* parent)
{
	DebugLog(__FUNCTION__"(%s, %s, %s)\n", name, ld_library_path, default_library_path);
	return NULL;
}

bool android_init_namespaces(const char* public_ns_sonames, const char* anon_ns_library_path)
{
	DebugLog(__FUNCTION__"(%s, %s)\n", public_ns_sonames, anon_ns_library_path);
	return NULL;
}
