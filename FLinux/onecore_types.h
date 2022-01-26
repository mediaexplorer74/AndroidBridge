#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>

WINBASEAPI
HANDLE
WINAPI
CreateFileA(
	_In_ LPCSTR lpFileName,
	_In_ DWORD dwDesiredAccess,
	_In_ DWORD dwShareMode,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	_In_ DWORD dwCreationDisposition,
	_In_ DWORD dwFlagsAndAttributes,
	_In_opt_ HANDLE hTemplateFile
);

WINBASEAPI
HANDLE
WINAPI
CreateFileW(
	_In_ LPCWSTR lpFileName,
	_In_ DWORD dwDesiredAccess,
	_In_ DWORD dwShareMode,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	_In_ DWORD dwCreationDisposition,
	_In_ DWORD dwFlagsAndAttributes,
	_In_opt_ HANDLE hTemplateFile
);

#ifdef UNICODE
#define CreateFile  CreateFileW
#else
#define CreateFile  CreateFileA
#endif // !UNICODE

WINBASEAPI
BOOL
WINAPI
CreatePipe(
	_Out_ PHANDLE hReadPipe,
	_Out_ PHANDLE hWritePipe,
	_In_opt_ LPSECURITY_ATTRIBUTES lpPipeAttributes,
	_In_ DWORD nSize
);

WINBASEAPI
HANDLE
WINAPI
CreateNamedPipeW(
	_In_ LPCWSTR lpName,
	_In_ DWORD dwOpenMode,
	_In_ DWORD dwPipeMode,
	_In_ DWORD nMaxInstances,
	_In_ DWORD nOutBufferSize,
	_In_ DWORD nInBufferSize,
	_In_ DWORD nDefaultTimeOut,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes
);


#ifdef UNICODE
#define CreateNamedPipe  CreateNamedPipeW
#endif

WINBASEAPI
BOOL
WINAPI
WaitNamedPipeW(
	_In_ LPCWSTR lpNamedPipeName,
	_In_ DWORD nTimeOut
);


#ifdef UNICODE
#define WaitNamedPipe  WaitNamedPipeW
#endif

WINBASEAPI
BOOL
WINAPI
ConnectNamedPipe(
	_In_ HANDLE hNamedPipe,
	_Inout_opt_ LPOVERLAPPED lpOverlapped
);


WINBASEAPI
BOOL
WINAPI
DisconnectNamedPipe(
	_In_ HANDLE hNamedPipe
);

WINBASEAPI
BOOL
WINAPI
GetSystemTimes(
	_Out_opt_ PFILETIME lpIdleTime,
	_Out_opt_ PFILETIME lpKernelTime,
	_Out_opt_ PFILETIME lpUserTime
);

WINBASEAPI
BOOL
WINAPI
SetThreadContext(
	_In_ HANDLE hThread,
	_In_ CONST CONTEXT * lpContext
);


WINBASEAPI
BOOL
WINAPI
GetExitCodeProcess(
	_In_ HANDLE hProcess,
	_Out_ LPDWORD lpExitCode
);

WINBASEAPI
DWORD
WINAPI
GetProcessId(
	_In_ HANDLE Process
);

typedef struct _PROCESS_INFORMATION {
	HANDLE hProcess;
	HANDLE hThread;
	DWORD dwProcessId;
	DWORD dwThreadId;
} PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION;


typedef struct _STARTUPINFOW {
	DWORD   cb;
	LPWSTR  lpReserved;
	LPWSTR  lpDesktop;
	LPWSTR  lpTitle;
	DWORD   dwX;
	DWORD   dwY;
	DWORD   dwXSize;
	DWORD   dwYSize;
	DWORD   dwXCountChars;
	DWORD   dwYCountChars;
	DWORD   dwFillAttribute;
	DWORD   dwFlags;
	WORD    wShowWindow;
	WORD    cbReserved2;
	LPBYTE  lpReserved2;
	HANDLE  hStdInput;
	HANDLE  hStdOutput;
	HANDLE  hStdError;
} STARTUPINFOW, *LPSTARTUPINFOW;

WINBASEAPI STARTUPINFOW STARTUPINFO;
WINBASEAPI LPSTARTUPINFOW LPSTARTUPINFO;



WINBASEAPI
BOOL
WINAPI
CreateProcessW(
	_In_opt_ LPCWSTR lpApplicationName,
	_Inout_opt_ LPWSTR lpCommandLine,
	_In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_ BOOL bInheritHandles,
	_In_ DWORD dwCreationFlags,
	_In_opt_ LPVOID lpEnvironment,
	_In_opt_ LPCWSTR lpCurrentDirectory,
	_In_ LPSTARTUPINFOW lpStartupInfo,
	_Out_ LPPROCESS_INFORMATION lpProcessInformation
);


#define CreateProcess  CreateProcessW

WINBASEAPI
VOID
WINAPI
ExitProcess(
	_In_ UINT uExitCode
);



WINBASEAPI
DWORD
WINAPI
K32GetMappedFileNameA(
	_In_  HANDLE hProcess,
	_In_  LPVOID lpv,
	_Out_ LPCSTR lpFilename,
	_In_  DWORD  nSize
);

#define GetMappedFileNameA K32GetMappedFileNameA


BOOL
WINAPI
GetAppContainerNamedObjectPath(
	_In_opt_ HANDLE Token,
	_In_opt_ PSID AppContainerSid,
	_In_ ULONG ObjectPathLength,
	_Out_writes_opt_(ObjectPathLength) LPWSTR ObjectPath,
	_Out_ PULONG ReturnLength
);

WINBASEAPI
BOOL
WINAPI
ProcessIdToSessionId(
	_In_ DWORD dwProcessId,
	_Out_ DWORD * pSessionId
);


WINBASEAPI
BOOL
WINAPI
GetSystemTimes(
	_Out_opt_ PFILETIME lpIdleTime,
	_Out_opt_ PFILETIME lpKernelTime,
	_Out_opt_ PFILETIME lpUserTime
);




WINBASEAPI
HANDLE
WINAPI
ReOpenFile(
	_In_ HANDLE  hOriginalFile,
	_In_ DWORD   dwDesiredAccess,
	_In_ DWORD   dwShareMode,
	_In_ DWORD   dwFlagsAndAttributes
);

// memoryapi.h

WINBASEAPI
_Ret_maybenull_ _Post_writable_byte_size_(dwSize)
LPVOID
WINAPI
VirtualAllocEx(
	_In_ HANDLE hProcess,
	_In_opt_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD flAllocationType,
	_In_ DWORD flProtect
);

WINBASEAPI
_Success_(return != FALSE)
BOOL
WINAPI
VirtualProtectEx(
	_In_ HANDLE hProcess,
	_In_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD flNewProtect,
	_Out_ PDWORD lpflOldProtect
);

WINBASEAPI
SIZE_T
WINAPI
VirtualQueryEx(
	_In_ HANDLE hProcess,
	_In_opt_ LPCVOID lpAddress,
	_Out_writes_bytes_to_(dwLength, return) PMEMORY_BASIC_INFORMATION lpBuffer,
	_In_ SIZE_T dwLength
);

WINBASEAPI
BOOL
WINAPI
VirtualLock(
	_In_ LPVOID lpAddress,
	_In_ SIZE_T dwSize
);


WINBASEAPI
BOOL
WINAPI
VirtualUnlock(
	_In_ LPVOID lpAddress,
	_In_ SIZE_T dwSize
);


WINBASEAPI
PVOID
WINAPI
AddVectoredExceptionHandler(
	_In_ ULONG                       FirstHandler,
	_In_ PVECTORED_EXCEPTION_HANDLER VectoredHandler
);

WINBASEAPI
ULONG
WINAPI
RemoveVectoredExceptionHandler(
	_In_ PVOID Handler
);

WINBASEAPI
BOOL
WINAPI
FlushInstructionCache(
	_In_ HANDLE hProcess,
	_In_reads_bytes_opt_(dwSize) LPCVOID lpBaseAddress,
	_In_ SIZE_T dwSize
);

VOID
WINAPI
RtlCaptureContext(
	_Out_ PCONTEXT ContextRecord
);


typedef enum _SE_OBJECT_TYPE {
	SE_UNKNOWN_OBJECT_TYPE = 0,
	SE_FILE_OBJECT,
	SE_SERVICE,
	SE_PRINTER,
	SE_REGISTRY_KEY,
	SE_LMSHARE,
	SE_KERNEL_OBJECT,
	SE_WINDOW_OBJECT,
	SE_DS_OBJECT,
	SE_DS_OBJECT_ALL,
	SE_PROVIDER_DEFINED_OBJECT,
	SE_WMIGUID_OBJECT,
	SE_REGISTRY_WOW64_32KEY
} SE_OBJECT_TYPE;


DWORD
WINAPI
GetSecurityInfo(
	_In_      HANDLE               handle,
	_In_      SE_OBJECT_TYPE       ObjectType,
	_In_      SECURITY_INFORMATION SecurityInfo,
	_Out_opt_ PSID                 *ppsidOwner,
	_Out_opt_ PSID                 *ppsidGroup,
	_Out_opt_ PACL                 *ppDacl,
	_Out_opt_ PACL                 *ppSacl,
	_Out_opt_ PSECURITY_DESCRIPTOR *ppSecurityDescriptor
);



BOOL
WINAPI
WriteProcessMemory(
	_In_  HANDLE  hProcess,
	_In_  LPVOID  lpBaseAddress,
	_In_  LPCVOID lpBuffer,
	_In_  SIZE_T  nSize,
	_Out_ SIZE_T  *lpNumberOfBytesWritten
);
