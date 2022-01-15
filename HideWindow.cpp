#include "headers.h"
#include "HideWindow.h"

struct tag_thread_info
{
	PETHREAD owning_thread;
};

struct tag_wnd
{
	char pad_0[0x10];
	tag_thread_info* thread_info;
};

UNICODE_STRING _ToUnicode(const char* str)
{
	UNICODE_STRING ret;
	ANSI_STRING ansi_str;
	RtlInitAnsiString(&ansi_str, str);
	RtlAnsiStringToUnicodeString(&ret, &ansi_str, TRUE);
	return ret;
}

UNICODE_STRING _ToUnicode(const wchar_t* str)
{
	UNICODE_STRING ret;
	RtlInitUnicodeString(&ret, str);
	return ret;
}

PVOID GetKernelBase(const char* szModuleName,PULONG pImageSize)
{
	typedef struct _SYSTEM_MODULE_ENTRY
	{
		HANDLE Section;
		PVOID MappedBase;
		PVOID ImageBase;
		ULONG ImageSize;
		ULONG Flags;
		USHORT LoadOrderIndex;
		USHORT InitOrderIndex;
		USHORT LoadCount;
		USHORT OffsetToFileName;
		UCHAR FullPathName[256];
	} SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

#pragma warning(disable:4200)
	typedef struct _SYSTEM_MODULE_INFORMATION
	{
		ULONG Count;
		SYSTEM_MODULE_ENTRY Module[0];
	} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

	PVOID pModuleBase = NULL;
	PSYSTEM_MODULE_INFORMATION pSystemInfoBuffer = NULL;

	ULONG SystemInfoBufferSize = 0;

	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation,
		&SystemInfoBufferSize,
		0,
		&SystemInfoBufferSize);

	if (!SystemInfoBufferSize)
	{
		return NULL;
	}

	pSystemInfoBuffer = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, SystemInfoBufferSize * 2,'1gaT');

	if (!pSystemInfoBuffer)
	{
		return NULL;
	}

	memset(pSystemInfoBuffer, 0, SystemInfoBufferSize * 2);

	status = ZwQuerySystemInformation(SystemModuleInformation,
		pSystemInfoBuffer,
		SystemInfoBufferSize * 2,
		&SystemInfoBufferSize);

	if (NT_SUCCESS(status))
	{
		for (int ModuleCount = 0; ModuleCount < pSystemInfoBuffer->Count; ModuleCount++)
		{

			char* ModuleFileName = (char*)pSystemInfoBuffer->Module[ModuleCount].FullPathName;

			int l = strlen(ModuleFileName);

			for (int i = l; i != 0; i--)
			{
				if (ModuleFileName[i] == '\\')
				{
					ModuleFileName = ModuleFileName + i + 1;
					break;
				}
			}

			if (_stricmp(szModuleName, ModuleFileName) == 0)
			{
				pModuleBase = pSystemInfoBuffer->Module[ModuleCount].ImageBase;

				if (pImageSize)
					*pImageSize = pSystemInfoBuffer->Module[ModuleCount].ImageSize;

				break;
			}

		}
	}

	ExFreePoolWithTag(pSystemInfoBuffer,'1gaT');

	return pModuleBase;
}

BOOLEAN GetNtUserSetWindowDisplayAffinity(PULONG64 Addr)
{
	ULONG kernelSize;
	ULONG_PTR win32kfullBase = (ULONG_PTR)GetKernelBase("win32kfull.sys", &kernelSize);
	if (win32kfullBase == 0 || kernelSize == 0)
	{
		DbgPrint("[-] win32kfull.sys not geted \n");
		return FALSE;
	}

	DbgPrint("[+] win32kfull.sys=%llx \n", win32kfullBase);

	ULONG64 NtUserSetWindowDisplayAffinity = 0;

	NtUserSetWindowDisplayAffinity = (ULONG64)RtlFindExportedRoutineByName((PVOID)win32kfullBase, "NtUserSetWindowDisplayAffinity");

	*Addr = NtUserSetWindowDisplayAffinity;

	return TRUE;

}

BOOLEAN GetZwUserSetWindowDisplayAffinity(PULONG64 Addr)
{

	ULONG64 NtUserSetWindowDisplayAffinity = 0;
	if (GetNtUserSetWindowDisplayAffinity(&NtUserSetWindowDisplayAffinity) && NtUserSetWindowDisplayAffinity)
	{
		//DbgBreakPoint();
		DbgPrint("[+] NtUserSetWindowDisplayAffinity=%llx\n", NtUserSetWindowDisplayAffinity);

		for (int SearchCount = 0; SearchCount < 0x100; SearchCount++)
		{
			//mov edx,esi |mov rcx,rdi |call ZwUserxxx
			if (*(PULONG)(NtUserSetWindowDisplayAffinity + SearchCount) == 0x8B48D68B
				&& *(PUSHORT)(NtUserSetWindowDisplayAffinity + SearchCount + 4) == 0xE8CF)
			{
				*Addr = NtUserSetWindowDisplayAffinity + SearchCount + 10 + *(PLONG)(NtUserSetWindowDisplayAffinity + SearchCount + 6);
				return TRUE;
			}
		}

	}

	DbgPrint("[-] NtUserSetWindowDisplayAffinity not found \n");

	return FALSE;
}

BOOLEAN GetChangeWindowTreeProtection(PULONG64 Addr)
{
	ULONG64 ZwUserSetWindowDisplayAffinity = 0;
	if (GetZwUserSetWindowDisplayAffinity(&ZwUserSetWindowDisplayAffinity) && ZwUserSetWindowDisplayAffinity)
	{
		DbgPrint("[+] ZwUserSetWindowDisplayAffinity=%llx\n", ZwUserSetWindowDisplayAffinity);

		for (int SearchCount = 0; SearchCount < 0x200; SearchCount++)
		{
			//mov edx,xxx |mov rcx,rbx |call ChangeWindowTreeProtection
			if (*(PUCHAR)(ZwUserSetWindowDisplayAffinity + SearchCount) == 0x8B
				&& *(PULONG)(ZwUserSetWindowDisplayAffinity + SearchCount + 2) == 0xE8CB8B48)
			{
				*Addr = ZwUserSetWindowDisplayAffinity + SearchCount + 10 + *(PLONG)(ZwUserSetWindowDisplayAffinity + SearchCount + 6);
				return TRUE;
			}
		}
	}

	DbgPrint("[-] ZwUserSetWindowDisplayAffinity not found \n");

	return FALSE;
}


LONGLONG (NTAPI* ChangeWindowTreePro)(struct tag_wnd*, unsigned int) = 0;
tag_wnd* (*validate_hwnd)(HANDLE) = 0;

NTSTATUS init_function()
{
	auto status = STATUS_SUCCESS;

	PEPROCESS pepro = 0;
	auto pid = GetProcessIdByProcessImageName("winlogon.exe");

	if (pid)
	{
		if (NT_SUCCESS(PsLookupProcessByProcessId(pid, &pepro)))
		{
			KAPC_STATE apc = { 0 };
			KeStackAttachProcess(pepro, &apc);

			ULONG kernelSize;
			auto win32kbase = (ULONG_PTR)GetKernelBase("win32kbase.sys", &kernelSize);
			if (win32kbase == 0 || kernelSize == 0)
			{
				DbgPrint("[-] win32kbase.sys not geted\n");
				status = STATUS_UNSUCCESSFUL;
				goto cleanup;
			}

			if (GetChangeWindowTreeProtection((PULONG64)&ChangeWindowTreePro) && ChangeWindowTreePro)
			{
				DbgPrint("[+] ChangeWindowTreePro=%llx\n", ChangeWindowTreePro);
			}
			else
			{
				DbgPrint("[-] ChangeWindowTreePro not found\n");
				status = STATUS_UNSUCCESSFUL;
				goto cleanup;
			}

			validate_hwnd = (tag_wnd * (*)(HANDLE))RtlFindExportedRoutineByName((PVOID)win32kbase, "ValidateHwnd");

			if (validate_hwnd)
			{
				DbgPrint("[+] validate_hwnd=%llx\n", validate_hwnd);
			}
			else
			{
				DbgPrint("[-] validate_hwnd not found\n");
				status = STATUS_UNSUCCESSFUL;
				goto cleanup;
			}
			status = STATUS_SUCCESS;
		cleanup:

			KeUnstackDetachProcess(&apc);
			ObDereferenceObject(pepro);

			return status;
		}


	}

	DbgPrint("[-] winlogon.exe not found\n");
	status = STATUS_UNSUCCESSFUL;
	return status;
}


#define WDA_NONE        0x00000000
#define WDA_MONITOR     0x00000001
#define WDA_EXCLUDEFROMCAPTURE 0x00000011

LONGLONG ChangeWindowTreeProtection(HANDLE hwnd, ULONG ulAffinity)
{
	auto window_instance = validate_hwnd(hwnd);

	if (!window_instance)
	{
		DbgPrint("[!] invalid HWND\n");
		return 0;
	}

	return ChangeWindowTreePro(window_instance, ulAffinity );
}


HANDLE GetProcessIdByProcessImageName(const char* process_name) {
	ULONG buffer_size = 0;
	ZwQuerySystemInformation(SystemProcessInformation, NULL, NULL, &buffer_size);

	auto buffer = ExAllocatePoolWithTag(NonPagedPool, buffer_size, 'mder');
	if (!buffer) {
		return INVALID_HANDLE_VALUE;
	}

	HANDLE pid = INVALID_HANDLE_VALUE;
	auto process_name_unicode = _ToUnicode(process_name);
	auto process_info = (PSYSTEM_PROCESS_INFORMATION)buffer;
	if (NT_SUCCESS(ZwQuerySystemInformation(SystemProcessInformation, process_info, buffer_size, NULL))) {
		while (process_info->NextEntryOffset) {
			//DbgPrint("Image: %ws\n", process_info->ImageName.Buffer);
			if (!RtlCompareUnicodeString(&process_name_unicode, &process_info->ImageName, true))
			{
				pid = process_info->UniqueProcessId;
				break;
			}
			process_info = (PSYSTEM_PROCESS_INFORMATION)((BYTE*)process_info + process_info->NextEntryOffset);
		}
	}

	ExFreePoolWithTag(buffer, 'mder');
	return pid;
}