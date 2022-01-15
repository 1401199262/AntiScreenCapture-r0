#ifndef _IOCTL_H
#define _IOCTL_H

#include "headers.h"
#include "HideWindow.h"


#define ctl_hidewindow CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0666, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)


NTSTATUS ctl_io(PDEVICE_OBJECT device_obj, PIRP irp)
{
	typedef struct _change_protect_window
	{
		ULONG value;
		HANDLE window_handle;
	} change_protect_window, * pchange_protect_window;

	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	auto stack = IoGetCurrentIrpStackLocation(irp);
	auto buffer = irp->AssociatedIrp.SystemBuffer;
	auto input_buffer_length = stack->Parameters.DeviceIoControl.InputBufferLength;

	if (stack)
	{
		switch (stack->Parameters.DeviceIoControl.IoControlCode)
		{
		case ctl_hidewindow:
		{

			// works because of the control handler being attached to the current process that called
			// the current process will have win32kbase mapped in physical memory
			// the System process will not, its aids but its how Windows works..

			ChangeWindowTreeProtection(((pchange_protect_window)buffer)->window_handle, ((pchange_protect_window)buffer)->value);		
			// in order to call ValidateHwnd you must have a win32 version of your current thread
			// PsSetThreadWin32Thread & PsGetThreadWin32Thread can handle this, example:
			
			/*
			void* get_win32() {
				return PsGetThreadWin32Thread(ethr);
			}
			
			void set_win32(void* new_, void* buffer) {
				void* current = get_win32();
				PsSetThreadWin32Thread(ethr, NULL, current); // reset win32
				PsSetThreadWin32Thread(ethr, new_, NULL); // modify win32

				if (buffer && current)
					*reinterpret_cast<void**>(buffer) = current;
			}
			
			void* o_win32 = NULL;
			set_win32(process_thread.get_win32(), &o_win32);
			*/
			
			// a hard notice though, you must have a current system thread, or thread hijack one, or hook KeGetCurrentThread, for this to work
			// you can verify you get a system thread (or have one) by verifying if KeGetCurrentThread is NULL
			
			// so now to explain why this call works here, but no where else in this driver or other drivers
			// since it is in process context, and deviceiocontrol does a shit ton of thread movement and copying
			// it gives this the win32 thread of the process, where system threads dont have a win32 equivalent, process threads do
			// and this gets a process threads win32, now that you know that you can see why the example is necessary

			
			
			break;
		}
		default:
			irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			break;
		}
	}

	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return irp->IoStatus.Status;
}

NTSTATUS unsupported_io(PDEVICE_OBJECT device_obj, PIRP irp)
{
	UNREFERENCED_PARAMETER(device_obj);
	irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	IofCompleteRequest(irp, IO_NO_INCREMENT);
	return irp->IoStatus.Status;
}

NTSTATUS create_io(PDEVICE_OBJECT device_obj, PIRP irp)
{
	UNREFERENCED_PARAMETER(device_obj);
	IofCompleteRequest(irp, IO_NO_INCREMENT);
	return irp->IoStatus.Status;
}

NTSTATUS close_io(PDEVICE_OBJECT device_obj, PIRP irp)
{
	UNREFERENCED_PARAMETER(device_obj);
	IofCompleteRequest(irp, IO_NO_INCREMENT);
	return irp->IoStatus.Status;
}


#endif 