#ifndef _HIDEWINDOW_H
#define _HIDEWINDOW_H

UNICODE_STRING _ToUnicode(const char* str);

PVOID GetKernelBase(const char* szModuleName, PULONG pImageSize);

//BOOLEAN GetNtUserSetWindowDisplayAffinity(PULONG64 Addr);
//
//BOOLEAN GetZwUserSetWindowDisplayAffinity(PULONG64 Addr);
//
//BOOLEAN GetChangeWindowTreeProtection(PULONG64 Addr);

LONGLONG ChangeWindowTreeProtection(HANDLE hwnd, ULONG ulAffinity);

HANDLE GetProcessIdByProcessImageName(const char* process_name);

NTSTATUS init_function();

#endif // _HIDEWINDOW_H