#include "pch.h"
#include <cstdint>
#include "linux/auxvec.h"
#include "args.h"


#define BRIDGE_KERNEL_MAX_ARGS 256
#define BRIDGE_KERNEL_RANDOM_BYTES 16


#define BRIDGE_KERNEL_ARG_TYPE uint32_t

BRIDGE_KERNEL_ARG_TYPE g_kernel_args[BRIDGE_KERNEL_MAX_ARGS];
uint8_t g_kernel_random[BRIDGE_KERNEL_RANDOM_BYTES];



#define ADD_ARG(a) \
  g_kernel_args[_arg_counter++] = a

#define ADD_AUXVAL(key, val) \
	ADD_ARG(key); \
	ADD_ARG(val)


void bridge_start()
{
	OutputDebugStringA(__FUNCTION__"\n");
}


size_t arg_num_length(int& argc, char** argv)
{
	if (argc > 0)
		return arg_size(argc, argv);

	int i = 0;
	size_t argsize = 0;
	while(argv[i] != NULL)
	{
		argsize += strlen(argv[i]) + 1;
		i++;
	}

	argc = i;
	return argsize;
}


size_t arg_size(int argc, char** argv)
{
	size_t argsize = 0;
	for (int i = 0; i < argc; i++)
	{
		argsize += strlen(argv[i]) + 1;
	}
	return argsize;
}

/*
 Build kernel args for userspace
*/
void* build_kernel_args()
{
	uint32_t _arg_counter = 0;

	const char *args[] = { "/bin/app_process32",
		//"-XZygote",
		"/system/bin",
		"--zygote",
		"--start-system-server" };

	int argc = sizeof(args) / sizeof(args[0]);



	// argc
	ADD_ARG(argc);
	// argv
	for (int i = 0; i < argc; i++)
	{
		ADD_ARG(reinterpret_cast<BRIDGE_KERNEL_ARG_TYPE>(args[i]));
	}
	ADD_ARG(NULL);

	// envp
	ADD_ARG(reinterpret_cast<BRIDGE_KERNEL_ARG_TYPE>("ANDROID_DATA=/data"));
	ADD_ARG(reinterpret_cast<BRIDGE_KERNEL_ARG_TYPE>("ANDROID_ROOT=/system"));
	
	ADD_ARG(reinterpret_cast<BRIDGE_KERNEL_ARG_TYPE>("BOOTCLASSPATH=/system/framework/core-oj.jar:/system/framework/core-libart.jar:/system/framework/conscrypt.jar:/system/framework/okhttp.jar:/system/framework/core-junit.jar:/system/framework/bouncycastle.jar:/system/framework/ext.jar:/system/framework/framework.jar:/system/framework/telephony-common.jar:/system/framework/voip-common.jar:/system/framework/ims-common.jar:/system/framework/apache-xml.jar:/system/framework/org.apache.http.legacy.boot.jar"));
	ADD_ARG(reinterpret_cast<BRIDGE_KERNEL_ARG_TYPE>("CLASSPATH=/system/framework/am.jar"));

	//ADD_ARG(reinterpret_cast<BRIDGE_KERNEL_ARG_TYPE>("ANDROID_SOCKET_zygote="));

	//ADD_ARG(reinterpret_cast<BRIDGE_KERNEL_ARG_TYPE>("GC_PRINT_ADDRESS_MAP=1"));
	//ADD_ARG(reinterpret_cast<BRIDGE_KERNEL_ARG_TYPE>("GC_PRINT_VERBOSE_STATS=1"));
	//ADD_ARG(reinterpret_cast<BRIDGE_KERNEL_ARG_TYPE>("GC_DUMP_REGULARLY=1"));
	//ADD_ARG(reinterpret_cast<BRIDGE_KERNEL_ARG_TYPE>("GC_BACKTRACES=1"));
	//ADD_ARG(reinterpret_cast<BRIDGE_KERNEL_ARG_TYPE>("GC_FIND_LEAK=1"));
	//ADD_ARG(reinterpret_cast<BRIDGE_KERNEL_ARG_TYPE>("GC_MARKERS=1"));
	//ADD_ARG(reinterpret_cast<BRIDGE_KERNEL_ARG_TYPE>("GC_INITIAL_HEAP_SIZE=65536"));
	
	
	
	
	
	
	
	ADD_ARG(NULL);

	//auxvec
	ADD_AUXVAL(AT_FLAGS, 0);

	ADD_AUXVAL(AT_ENTRY, reinterpret_cast<BRIDGE_KERNEL_ARG_TYPE>(bridge_start));
	ADD_AUXVAL(AT_PAGESZ, 4096);
	ADD_AUXVAL(AT_SECURE, 0);
	ADD_AUXVAL(AT_RANDOM, reinterpret_cast<BRIDGE_KERNEL_ARG_TYPE>(g_kernel_random)); // TODO: fill with random 16 bytes




	ADD_AUXVAL(AT_NULL, 0);

	return g_kernel_args;
}