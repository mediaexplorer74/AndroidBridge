#include "pch.h"
#include "ProcessHost.h"
#include "tools.h"

extern "C" {
#include "ntdll.h"
}

#include "windefs.h"

PIMAGE_NT_HEADERS WINAPI ImageNtHeader(PVOID Base)
{
	return (PIMAGE_NT_HEADERS)
		((LPBYTE)Base + ((PIMAGE_DOS_HEADER)Base)->e_lfanew);
}

PIMAGE_SECTION_HEADER WINAPI RtlImageRvaToSection(const IMAGE_NT_HEADERS *nt,
	HMODULE module, DWORD_PTR rva)
{
	int i;
	const IMAGE_SECTION_HEADER *sec;

	sec = (const IMAGE_SECTION_HEADER*)((const char*)&nt->OptionalHeader +
		nt->FileHeader.SizeOfOptionalHeader);
	for (i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
	{
		if ((sec->VirtualAddress <= rva) && (sec->VirtualAddress + sec->SizeOfRawData > rva))
			return (PIMAGE_SECTION_HEADER)sec;
	}
	return NULL;
}

PVOID WINAPI RtlImageRvaToVa(const IMAGE_NT_HEADERS *nt, HMODULE module,
	DWORD_PTR rva, IMAGE_SECTION_HEADER **section)
{
	IMAGE_SECTION_HEADER *sec;

	if (section && *section)  /* try this section first */
	{
		sec = *section;
		if ((sec->VirtualAddress <= rva) && (sec->VirtualAddress + sec->SizeOfRawData > rva))
			goto found;
	}
	if (!(sec = RtlImageRvaToSection(nt, module, rva))) return NULL;
found:
	if (section) *section = sec;
	return (char *)module + sec->PointerToRawData + (rva - sec->VirtualAddress);
}

PVOID WINAPI ImageDirectoryEntryToDataEx(PVOID base, BOOLEAN image, USHORT dir, PULONG size, PIMAGE_SECTION_HEADER *section)
{
	const IMAGE_NT_HEADERS *nt;
	DWORD_PTR addr;

	*size = 0;
	if (section) *section = NULL;

	if (!(nt = ImageNtHeader(base))) return NULL;
	if (dir >= nt->OptionalHeader.NumberOfRvaAndSizes) return NULL;
	if (!(addr = nt->OptionalHeader.DataDirectory[dir].VirtualAddress)) return NULL;

	*size = nt->OptionalHeader.DataDirectory[dir].Size;
	if (image || addr < nt->OptionalHeader.SizeOfHeaders) return (char *)base + addr;

	return RtlImageRvaToVa(nt, (HMODULE)base, addr, section);
}

// == Windows API GetProcAddress
void *PeGetProcAddressA(void *Base, LPCSTR Name)
{
	DWORD Tmp;

	IMAGE_NT_HEADERS *NT = ImageNtHeader(Base);
	IMAGE_EXPORT_DIRECTORY *Exp = (IMAGE_EXPORT_DIRECTORY*)ImageDirectoryEntryToDataEx(Base, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &Tmp, 0);
	if (Exp == 0 || Exp->NumberOfFunctions == 0)
	{
		SetLastError(ERROR_NOT_FOUND);
		return 0;
	}

	DWORD *Names = (DWORD*)(Exp->AddressOfNames + (DWORD_PTR)Base);
	WORD *Ordinals = (WORD*)(Exp->AddressOfNameOrdinals + (DWORD_PTR)Base);
	DWORD *Functions = (DWORD*)(Exp->AddressOfFunctions + (DWORD_PTR)Base);

	FARPROC Ret = 0;

	if ((DWORD_PTR)Name<65536)
	{
		if ((DWORD_PTR)Name - Exp->Base<Exp->NumberOfFunctions)
			Ret = (FARPROC)(Functions[(DWORD_PTR)Name - Exp->Base] + (DWORD_PTR)Base);
	}
	else
	{
		for (DWORD i = 0; i<Exp->NumberOfNames && Ret == 0; i++)
		{
			char *Func = (char*)(Names[i] + (DWORD_PTR)Base);
			if (Func && strcmp(Func, Name) == 0)
				Ret = (FARPROC)(Functions[Ordinals[i]] + (DWORD_PTR)Base);
		}
	}

	if (Ret)
	{
		DWORD ExpStart = NT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (DWORD)Base;
		DWORD ExpSize = NT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
		if ((DWORD)Ret >= ExpStart && (DWORD)Ret <= ExpStart + ExpSize)
		{
			// Forwarder
			return 0;
		}
		return Ret;
	}

	return 0;
}




typedef HMODULE __stdcall t_LLA(char *);
typedef FARPROC __stdcall t_GPA(HMODULE H, char *);
typedef DWORD __stdcall t_MBA(HWND, char *, char*, DWORD);

/*t_LLA* LoadLibraryA = 0;
t_GPA* GetProcAddressA = 0;
t_MBA* MessageBoxA = 0;
t_CreateProcessA *CreateProcessA = 0;
t_GetExitCodeProcess* GetExitCodeProcess = 0;

void* FindKerneDllBase()
{
	char *tmp = (char*)GetTickCount64;
	tmp = (char*)((~0xFFF)&(DWORD_PTR)tmp);

	while (tmp)
	{
		__try
		{
			if (tmp[0] == 'M' && tmp[1] == 'Z')
				break;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
		}
		tmp -= 0x1000;
	}

	return tmp;
}*/

int RunHost()
{
	/*void* kerneldll = FindKerneDllBase();

	if (kerneldll == 0)
		return 0;*/


	
	//LoadLibraryA = (t_LLA*)PeGetProcAddressA(kerneldll, "LoadLibraryA");
	//GetProcAddressA = (t_GPA*)PeGetProcAddressA(kerneldll, "GetProcAddress");
	//CreateProcessA = (t_CreateProcessA*)PeGetProcAddressA(kerneldll, "CreateProcessA");
	//GetExitCodeProcess = (t_GetExitCodeProcess*)PeGetProcAddressA(kerneldll, "GetExitCodeProcess");


	//HMODULE ntdll = LoadLibraryA("ntdll.dll");


	//il2cpp_initFunc il2cpp_init = (il2cpp_initFunc)GetProcAddressA(ntdll, "il2cpp_init");



	//NtClose(NULL);


	STARTUPINFO si;
	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);

	PROCESS_INFORMATION pi;

	BOOL ok = CreateProcessA("ProcessHost.exe", 0, 0, 0, FALSE, 0, 0, 0, &si, &pi);

	if (ok)
	{
		DebugLog("Process started, pid:%d\n", pi.dwProcessId);
		/*WaitForSingleObject(pi.hProcess, INFINITE);

		DWORD exit_code;
		GetExitCodeProcess(pi.hProcess, &exit_code);

		DebugLog("Process finished 0x%x\n", exit_code);

		// Close process and thread handles. 
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);*/
	}
	else
	{
		DebugLog("Process start failed\n");
	}

	return 1;


}