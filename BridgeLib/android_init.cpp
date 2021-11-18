#define DLL_EXPORT
#include "android/android_init.h"
#include "dll_init.h"
#include "kernel_helpers.h"
#include "tools.h"
#include <ppltasks.h>
#include "args.h"
#include <WinSock.h>

//namespace lx_kernel {
	extern "C" {
#include "log.h"
#include "flags.h"
#include "shared.h"
#include "heap.h"
#include "syscall/fork.h"
#include "syscall/mm.h"
#include "syscall/sig.h"
#include "syscall/syscall.h"
#include "syscall/process.h"
#include "syscall/tls.h"
#include "syscall/vfs.h"
#include "common/socket.h"
#include "linux/auxvec.h"
	}
//}

using namespace Concurrency;
using namespace Windows::Storage;
using namespace Windows::ApplicationModel;

extern "C" {
	char *startup;
}


//flinit(const wchar_t* rootDir, const wchar_t* dataDir)
void flinit(const wchar_t* rootDir, const wchar_t* dataDir)
{
	log_init();
	fork_init();
	/* fork_init() will directly jump to restored thread context if we are a fork child */

	mm_init();
	flags_init();


	shared_init();
	heap_init();
	signal_init();
	process_init();
	tls_init();

	mm_update_brk((void*)0x10000000);

	if (rootDir == NULL)
	{
		StorageFolder^ packageFolder = Package::Current->InstalledLocation;
		Platform::String^ packageFolderPath = Platform::String::Concat(L"\\\\?\\", packageFolder->Path);
		rootDir = packageFolderPath->Data();

	}

	if (dataDir == NULL)
	{
		StorageFolder^ localFolder = ApplicationData::Current->LocalFolder;
		Platform::String^ localFolderPath = Platform::String::Concat(L"\\\\?\\", localFolder->Path);
		dataDir = localFolderPath->Data();
	}

	DebugLog("[DebugLog] root: %S\n", rootDir);
	DebugLog("[DebugLog] data: %S\n", dataDir);

	vfs_init(rootDir, dataDir);// L"\\\\?\\.");// C:\\Logs\\archlinux");

	// install system call handler
	install_syscall_handler();

	DebugLog("DebugLog: handler installed\n");

	sys_mkdir("/data/dalvik-cache", 0777);
	sys_mkdir("/data/dalvik-cache/arm", 0777);

	//"/etc/localtime -> ../usr/share/zoneinfo/UTC";



}//flinit


#define BRIDGE_KERNEL_MAX_ARGS 256
#define BRIDGE_KERNEL_RANDOM_BYTES 16


#define BRIDGE_KERNEL_ARG_TYPE uint32_t
uint8_t g_kernel_rando2m[BRIDGE_KERNEL_RANDOM_BYTES];

typedef int(*__system_property_area_init_type)();
typedef int(*__system_property_add_type)(const char *name, unsigned int namelen,
	const char *value, unsigned int valuelen);
typedef const void *(*__system_property_find_type)(const char *name);
typedef int(*__system_property_get_type)(const char *name, char *value);
typedef int(*__system_property_read_type)(const void *pi, char *name, char *value);
typedef int(*__system_property_set_type)(const char *key, const char *value);
typedef char * (*getenv_type)(const char *name);
typedef int(*setenv_type)(const char *name, const char *value, int rewrite);


__system_property_add_type __system_property_add_original;
__system_property_find_type __system_property_find_original;
__system_property_get_type __system_property_get_original;
__system_property_read_type __system_property_read_original;
__system_property_set_type __system_property_set_original;
getenv_type getenv_type_original;
setenv_type setenv_;

typedef void (*InvokeUserSignalHandlerType)(int sig,
	void* info, void* context);
typedef void (*ClaimSignalChainType)(int signal,
	void* oldaction);
typedef void (*UnclaimSignalChainType)(int signal);
typedef void (*InitializeSignalChainType)();
typedef void (*EnsureFrontOfChainType)(int signal,
	void* expected_action);
typedef void (*SetSpecialSignalHandlerFnType)(int signal,
	void* fn);

InvokeUserSignalHandlerType InvokeUserSignalHandlerOriginal;
ClaimSignalChainType ClaimSignalChainOriginal;
UnclaimSignalChainType UnclaimSignalChainOriginal;
InitializeSignalChainType InitializeSignalChainOriginal;
EnsureFrontOfChainType EnsureFrontOfChainOriginal;
SetSpecialSignalHandlerFnType SetSpecialSignalHandlerFnOriginal;


void ClaimSignalChain(int signal ,
	void* oldaction ) {
	ClaimSignalChainOriginal(signal, oldaction);
}

void UnclaimSignalChain(int signal ) {
	UnclaimSignalChainOriginal(signal);
}

void InvokeUserSignalHandler(int sig ,
	void* info ,
	void* context ) {
	InvokeUserSignalHandlerOriginal(sig, info, context);
}

void InitializeSignalChain() {
	InitializeSignalChainOriginal();
}

void EnsureFrontOfChain(int signal ,
	void* expected_action ) {
	EnsureFrontOfChainOriginal(signal, expected_action);
}

void SetSpecialSignalHandlerFn(int signal ,
	void* fn ) {
	SetSpecialSignalHandlerFnOriginal(signal, fn);
}


char * getenv_hook(const char *name)
{
	char* ret = getenv_type_original(name);
	if(ret)
		DebugLog("getenv(\"%s\") = \"%s\"\n", name, ret);
	else
		DebugLog("getenv(\"%s\") = NULL\n", name);

	return ret;
}

int __system_property_add_hook(const char *name, unsigned int namelen,
	const char *value, unsigned int valuelen)
{
	DebugLog("system_property_add(\"%s\", \"%s\")\n", name, value);
	return __system_property_add_original(name, namelen, value, valuelen);
}

const void* __system_property_find_hook(const char *name)
{
	DebugLog("system_property_find(\"%s\")\n",name);
	return __system_property_find_original(name);
}

int __system_property_get_hook(const char *name, char *value)
{
	int ret = __system_property_get_original(name, value);
	if(ret)
		DebugLog("system_property_get(\"%s, \"%s\")\n", name, value);
	else
		DebugLog("system_property_get(\"%s\")\n", name, ret);
	return ret;
}

int __system_property_read_hook(const void *pi, char *name, char *value)
{
	DebugLog("__system_property_read(\"%s\", \"%s\")\n", name, value);
	return __system_property_read_original(pi, name, value);
}

int __system_property_set_hook(const char *key, const char *value)
{
	DebugLog("__system_property_set(\"%s\", \"%s\")\n", key, value);
	return __system_property_set_original(key, value);
}


int add_property(const char* name, const char* value)
{
	return __system_property_add_hook(name, strlen(name), value, strlen(value));
}


extern "C" int sys_socket(int domain, int type, int protocol);

extern "C" int sys_bind(int sockfd, const struct sockaddr * addr, int addrlen);

extern "C" int sys_unlink(const char * pathname);

// call_main(const wchar_t* moduleName)
void call_main(const wchar_t* moduleName)
{
	// initialize property area at first
	// use write permission (as priviledged init process), because we dont have init process yet
	HMODULE libc = ::LoadPackagedLibrary(L"libc.dll", 0);
	
	if (libc != 0)
	{
		__system_property_area_init_type __system_property_area_init = (__system_property_area_init_type)GetProcAddress(libc, "__system_property_area_init"); 
		__system_property_area_init();
		__system_property_add_original = (__system_property_add_type)GetProcAddress(libc, "__system_property_add");
		__system_property_find_original = (__system_property_find_type)GetProcAddress(libc, "__system_property_find");
		__system_property_get_original = (__system_property_get_type)GetProcAddress(libc, "__system_property_get");
		__system_property_read_original = (__system_property_read_type)GetProcAddress(libc, "__system_property_read");
		__system_property_set_original = (__system_property_set_type)GetProcAddress(libc, "__system_property_set");
		getenv_type_original = (getenv_type)GetProcAddress(libc, "getenv");
		setenv_ = (setenv_type)GetProcAddress(libc, "setenv");

		int sock = sys_socket(PF_UNIX, SOCK_STREAM, 0);

		if (sock < 0)
		{
			__debugbreak();
		}

		struct sockaddr_un addr;
		memset(&addr, 0, sizeof(addr));
		addr.sun_family = AF_UNIX;
		strcpy_s(addr.sun_path, "/data/dev_socket_zygote");

		sys_unlink(addr.sun_path);

		if (sys_bind(sock, (struct sockaddr*) &addr, sizeof(addr)) < 0)
			__debugbreak();

		char buf[20];
		_itoa_s(sock, buf, 10);
		setenv_("ANDROID_SOCKET_zygote", buf, 1);

		
		/*
#
		# ADDITIONAL_DEFAULT_PROPERTIES
#
			ro.secure = 0
			ro.allow.mock.location = 1
			ro.debuggable = 1
			ro.zygote = zygote32
			pm.dexopt.first - boot = verify - at - runtime
			pm.dexopt.boot = verify - at - runtime
			pm.dexopt.install = interpret - only
			pm.dexopt.bg - dexopt = speed - profile
			pm.dexopt.ab - ota = speed - profile
			pm.dexopt.nsys - library = speed
			pm.dexopt.shared - apk = speed
			pm.dexopt.forced - dexopt = speed
			pm.dexopt.core - app = speed
			dalvik.vm.image - dex2oat - Xms = 64m
			dalvik.vm.image - dex2oat - Xmx = 64m
			dalvik.vm.dex2oat - Xms = 64m
			dalvik.vm.dex2oat - Xmx = 512m
			ro.dalvik.vm.native.bridge = 0
			dalvik.vm.usejit = true
			dalvik.vm.usejitprofiles = true
			dalvik.vm.appimageformat = lz4
			debug.atrace.tags.enableflags = 0
#
			# BOOTIMAGE_BUILD_PROPERTIES
#
			ro.bootimage.build.date = Tue Jan 17 14:47 : 23 CET 2017
			ro.bootimage.build.date.utc = 1484660843
			ro.bootimage.build.fingerprint = Android / bridge_arm / generic : 7.1.1 / N6F26Q / wally01171447 : eng / test - keys
			persist.sys.usb.config = adb*/


		/*# begin build properties
# autogenerated by buildinfo.sh
ro.build.id=N6F26Q
ro.build.display.id=bridge_arm-eng 7.1.1 N6F26Q eng.wally.20170117.144723 test-keys
ro.build.version.incremental=eng.wally.20170117.144723
ro.build.version.sdk=25
ro.build.version.preview_sdk=0
ro.build.version.codename=REL
ro.build.version.all_codenames=REL
ro.build.version.release=7.1.1
ro.build.version.security_patch=2017-01-05
ro.build.version.base_os=
ro.build.date=Tue Jan 17 14:47:23 CET 2017
ro.build.date.utc=1484660843
ro.build.type=eng
ro.build.user=wally
ro.build.host=wally-ubuntu1604-vm1
ro.build.tags=test-keys
ro.build.flavor=bridge_arm-eng
ro.product.model=AOSP on ARM Emulator.
ro.product.brand=Android
ro.product.name=bridge_arm
ro.product.device=generic
ro.product.board=
# ro.product.cpu.abi and ro.product.cpu.abi2 are obsolete,
# use ro.product.cpu.abilist instead.
ro.product.cpu.abi=armeabi-v7a
ro.product.cpu.abi2=armeabi
ro.product.cpu.abilist=armeabi-v7a,armeabi
ro.product.cpu.abilist32=armeabi-v7a,armeabi
ro.product.cpu.abilist64=
ro.product.manufacturer=unknown
ro.product.locale=en-US
ro.wifi.channels=
ro.board.platform=
# ro.build.product is obsolete; use ro.product.device
ro.build.product=generic
# Do not try to parse description, fingerprint, or thumbprint
ro.build.description=bridge_arm-eng 7.1.1 N6F26Q eng.wally.20170117.144723 test-keys
ro.build.fingerprint=Android/bridge_arm/generic:7.1.1/N6F26Q/wally01171447:eng/test-keys
ro.build.characteristics=default
# end build properties
#
# from build/target/board/generic/system.prop
#
#
# system.prop for generic sdk
#

rild.libpath=/system/lib/libreference-ril.so
rild.libargs=-d /dev/ttyS0

#
# ADDITIONAL_BUILD_PROPERTIES
#
ro.config.ringtone=Ring_Synth_04.ogg
ro.config.notification_sound=pixiedust.ogg
ro.carrier=unknown
ro.config.alarm_alert=Alarm_Classic.ogg
ro.ril.hsxpa=1
ro.ril.gprsclass=10
ro.adb.qemud=1
persist.sys.dalvik.vm.lib.2=libart.so
dalvik.vm.isa.arm.variant=generic
dalvik.vm.isa.arm.features=default
ro.kernel.android.checkjni=1
dalvik.vm.lockprof.threshold=500
dalvik.vm.image-dex2oat-filter=verify-at-runtime
net.bt.name=Android
dalvik.vm.stack-trace-file=/data/anr/traces.txt  */

/*
# Open GL
ro.bq.gpu_to_cpu_unsupported=1
ro.zygote.disable_gl_preload=true
ro.opengles.version=131072
debug.sf.no_hw_vsync=1

# ANGLE reports as being able to preserve the back buffer though
# our method of composition (hybrid hwc/framebuffer) combined with
# ANGLE seems to reveal some subtle races when hwui's dirty region
# logic is enabled.
# If/when we switch to a true hardware composer render pipeline
# we should reevaluate toggling this setting.
debug.hwui.render_dirty_regions=false

# Force ui to be hardware accelerated by default
persist.sys.ui.hw=true

# No boot animation
debug.sf.nobootanimation=1

# Dalvik heap config

# Initialize size of managed heap
dalvik.vm.heapstartsize=5m

# Maximum size of managed heap for an app
# which does not specify android:largeHeap
# in its manifest
dalvik.vm.heapgrowthlimit=48m

# Maximum size of the managed heap for an app
# that specifies android:largeHeap in its manifest
dalvik.vm.heapsize=128m

# How full the managed heap can be
dalvik.vm.heaptargetutilization=0.75

# How much min free space should be kept
dalvik.vm.heapminfree=512k

# How much max free space should be kept
dalvik.vm.heapmaxfree=2m

# Keyboard config
keyguard.no_require_sim=true
keyguard.enable=false
hw.keyboard=yes

# Disable unnecessary services
config.disable_telephony=true
config.disable_bluetooth=true

# Allow apps to take advantage of low ram setting
ro.config.low_ram=true

# This setting will disable the following types of scans done by PackageManagerService to speed up startup.
#     a. Dexopt scanning done to ensure that files such as /system/framework/* have a .odex dexopt file
#        corresponding to a .jar file. Disabling this assumes that an external process (e.g., build) ensures this
#        and hence PackageManagerService does not need to take the startup performance hit.
#     b. If called during boot, disable the unpacking of non-system app APKs for the purpose of regenerating
#        native libraries inside the APK into /data/app-lib/<app>. Disabling assumes that the APKs are
#        always installed through the Package Manager install API as opposed to dropping an APK file to the
#        file system at a random point.
config.pm.disablescan=true*/

		add_property("ro.product.cpu.abilist32", "armeabi-v7a,armeabi"); // armeabi-v7a
		add_property("ro.product.cpu.abilist", "armeabi-v7a,armeabi");
		add_property("persist.sys.locale", "en-US");

		add_property("ro.build.version.incremental", "eng.wally.20170117.144723");
		add_property("ro.build.version.sdk", "25");
		add_property("ro.build.version.preview_sdk", "0");
		add_property("ro.build.version.codename", "REL");
		add_property("ro.build.version.all_codenames", "REL");
		add_property("ro.build.version.release", "7.1.1");
		add_property("ro.build.version.security_patch", "2017-01-05");
		add_property("ro.build.version.base_os", "");
		
		add_property("ro.build.fingerprint", "google/angler/angler:6.0.1/MTC20L/3230295:user/release-keys");
		add_property("ro.build.characteristics", "nosdcard");

		add_property("ro.dalvik.vm.native.bridge", "0");
		add_property("debug.generate-debug-info", "true");
		add_property("dalvik.vm.checkjni", "true");
		//add_property("dalvik.vm.usejit", "false");
		//add_property("dalvik.vm.execution-mode", "int:portable"); //int:portable, int:jit, int:fast
		add_property("debug.atrace.tags.enableflags", "131071");
		add_property("dalvik.vm.extra-opts", "-verbose:startup,class,signals,oat,jni,gc,compiler,jit,heap");// , threads");
		add_property("dalvik.vm.stack-trace-file", "/data/anr/traces.txt");
		add_property("dalvik.vm.isa.arm.variant", "cortex-a7");
		add_property("dalvik.vm.isa.arm.features", "default");
		add_property("persist.sys.dalvik.vm.lib.2", "libart");
		add_property("persist.sys.timezone", "Europe/Berlin");
		add_property("dalvik.vm.method-trace", "true");
		add_property("dalvik.vm.appimageformat", "lz4");
		add_property("dalvik.vm.image-dex2oat-filter", "verify-at-runtime");

		//add_property("dalvik.vm.heapstartsize", "8m");
		//add_property("dalvik.vm.heapgrowthlimit", "192m");
		//add_property("dalvik.vm.heapsize", "512m");
		//add_property("dalvik.vm.heaptargetutilization", "0.75");
		//add_property("dalvik.vm.heapminfree", "512k");
		//add_property("dalvik.vm.heapmaxfree", "8m");
		add_property("dalvik.vm.image-dex2oat-Xms", "64m");
		add_property("dalvik.vm.image-dex2oat-Xmx", "64m");
		add_property("dalvik.vm.dex2oat-Xms", "64m");
		add_property("dalvik.vm.dex2oat-Xmx", "512m");

		add_property("config.pm.disablescan", "true");
		add_property("debug.hwui.render_dirty_regions", "false");
		add_property("ro.bq.gpu_to_cpu_unsupported", "1");
		add_property("ro.zygote.disable_gl_preload", "true");
		add_property("ro.opengles.version", "131072");
		add_property("debug.sf.no_hw_vsync", "1");
		add_property("config.disable_telephony", "true");
		add_property("config.disable_bluetooth", "true");
	}

	//RnD 1
	// 
	char *args[] = { "/system/bin/patchoat",
	"--input-image-location=/system/framework/boot.art",
	"--output-image-file=/data/dalvik-cache/arm/system@framework@boot.art",
	"--instruction-set=arm",
	"--base-offset-delta=-7286784" };
	moduleName = L"patchoat.dll";
	//


	// RnD 2
	/*
	char *args[] = { "/bin/app_process32",
	"-Xzygote",
	"/system/bin",
	"--zygote",
	"--start-system-server" };
	*/

	//{ "/system/bin/dex2oat" --runtime-arg -classpath --runtime-arg /system/framework/am.jar 
	//  --instruction-set=arm --instruction-set-features=smp,-div,-atomic_ldrd_strd 
    //  --runtime-arg -Xrelocate --boot-image=/system/framework/boot.art --runtime-arg -Xms64m 
	//  --runtime-arg -Xmx512m --instruction-set-variant=cortex-a7 
	//  --instruction-set-features=default --generate-debug-info --dex-file=/system/framework/am.jar 
	//  --oat-fd=11 --oat-location=/data/dalvik-cache/arm/system@framework@am.jar@classes.dex 
	//  --compiler-filter=speed"
	
	//RnD 3
	/*
	char *args[] = { "/system/bin/dex2oat" ,
		"--instruction-set=arm",
		"--instruction-set-features=smp,-div,-atomic_ldrd_strd",
		"--boot-image=/system/framework/boot.art",
		"--instruction-set-variant=cortex-a7",
		"--instruction-set-features=default",
		"--dex-file=/system/app/EasterEgg/EasterEgg.apk",
		"--oat-file=/data/dalvik-cache/arm/system@app@EasterEgg@EasterEgg.apk.oat",
		"--compiler-filter=speed"
		};
	moduleName = L"dex2oat.dll"; 
	*/

	//RnD
	//moduleName = L"dex2oat.dll";

	//char *args[] = { "/bin/app_process32",
	//	"/system/bin",
	//	"com.android.commands.am.Am", "start", "com.android.settings/.Settings" };

	// TODO : solve AV here

	HMODULE app_process;
	try {
		app_process = ::LoadPackagedLibrary(moduleName, 0);
	}
	catch (...) {
		// Code that executes when an exception of type
		// networkIOException is thrown in the try block
		// ...
		// Log error message in the exception object
		//cerr << e.what();
		//throw;
	}

	if (app_process != 0)
	{

		InvokeUserSignalHandlerOriginal = (InvokeUserSignalHandlerType)::GetProcAddress(app_process, "InvokeUserSignalHandler");
		ClaimSignalChainOriginal = (ClaimSignalChainType)::GetProcAddress(app_process, "ClaimSignalChain");
		UnclaimSignalChainOriginal = (UnclaimSignalChainType)::GetProcAddress(app_process, "UnclaimSignalChain");
		InitializeSignalChainOriginal = (InitializeSignalChainType)::GetProcAddress(app_process, "InitializeSignalChain");
		EnsureFrontOfChainOriginal = (EnsureFrontOfChainType)::GetProcAddress(app_process, "EnsureFrontOfChain");
		SetSpecialSignalHandlerFnOriginal = (SetSpecialSignalHandlerFnType)::GetProcAddress(app_process, "SetSpecialSignalHandlerFn");

		entrypoint_t _module_entry_point = (entrypoint_t)::GetProcAddress(app_process, "_module_entry_point_");

		if (_module_entry_point != NULL)
		{
			//_module_entry_point(build_kernel_args());


			int argc = sizeof(args) / sizeof(args[0]);
			int argsize = arg_size(argc, args);

			char *arg_array = new char[argsize];
			char **arg_ptrs = new char*[argc];

			//va_list arglist;
			//va_start(arglist, arg_ptrs);
			

			//copy args to one memory block
			char* arg_ptr = arg_array;
			size_t dest_size = argsize;

			for (int i = 0; i < argc; i++)
			{
				strcpy_s(arg_ptr, dest_size, args[i]);
				arg_ptrs[i] = arg_ptr;
				int len = strlen(args[i]) + 1;
				arg_ptr += len;
				dest_size -= len;
			}

			//RnD
			
             // !TODO !
			/*
			// Demaged -- memory access violation :(
			_module_entry_point(
#ifdef _M_ARM
				0, 0, 0, 0, //skip register params on ARM, we need copy all params to stack
#endif
				argc,
				arg_ptrs[0], arg_ptrs[1], arg_ptrs[2], arg_ptrs[3], arg_ptrs[4], //arg_ptrs[5], arg_ptrs[6], arg_ptrs[7], arg_ptrs[8],
				0,
				"CLASSPATH=/system/app/EasterEgg/EasterEgg.apk",
				0);
				//AT_FLAGS, 0,
				//AT_NULL, 0);
			 */
			
		}
	}
}
