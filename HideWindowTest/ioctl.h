#pragma once
#include <windows.h>
#include <ntstatus.h>
#include <windef.h>

#define drv_device_file L"\\\\.\\AntiCapture" 

HANDLE   h_driver = INVALID_HANDLE_VALUE;
NTSTATUS load_status = STATUS_NOT_FOUND;

#define ctl_hidewindow   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0666, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

typedef struct _change_protect_window
{
	ULONG value;
	HANDLE window_handle;
} change_protect_window, * pchange_protect_window;

bool service_is_load()
{
	h_driver = CreateFileW(drv_device_file, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	return h_driver != INVALID_HANDLE_VALUE;
}

NTSTATUS send_service(ULONG ioctl_code, LPVOID io, DWORD size)
{
	if (h_driver == INVALID_HANDLE_VALUE)
		return STATUS_DEVICE_DOES_NOT_EXIST;

	if (!DeviceIoControl(h_driver, ioctl_code, io, size, nullptr, 0, NULL, NULL))
		return STATUS_UNSUCCESSFUL;

	return STATUS_SUCCESS;
}

NTSTATUS change_protect_window_ex(HWND window_handle, ULONG value)
{
	change_protect_window req = { 0 };

	req.window_handle = window_handle;
	req.value = value;

	return send_service(ctl_hidewindow, &req, sizeof(req));
}
