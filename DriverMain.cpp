#include "ioctl.h"
#include "HideWindow.h"

void DriverUnload(PDRIVER_OBJECT DriverObject)
{ 
	UNICODE_STRING DeviceLinkName;
	PDEVICE_OBJECT NextDriver = NULL;
	PDEVICE_OBJECT DeleteDeviceObject = NULL;

	IoDeleteSymbolicLink(&_ToUnicode("\\DosDevices\\AntiCapture"));

	DeleteDeviceObject = DriverObject->DeviceObject;
	while (DeleteDeviceObject != NULL)
	{
		NextDriver = DeleteDeviceObject->NextDevice;
		IoDeleteDevice(DeleteDeviceObject);
		DeleteDeviceObject = NextDriver;
	}

	DbgPrint("[*] Driver Unload\n");
}

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT driver_obj, PUNICODE_STRING registery_path)
{
	auto  status = STATUS_SUCCESS;
	UNICODE_STRING  sym_link, dev_name;
	PDEVICE_OBJECT  dev_obj;

	DbgPrint("[+] Driver Loaded\n");

	status = init_function();
	if (status != STATUS_SUCCESS) {
		return status;
	}

	dev_name = _ToUnicode("\\Device\\AntiCapture");
	status = IoCreateDevice(driver_obj, 0, &dev_name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &dev_obj);

	if (status != STATUS_SUCCESS) {
		return status;
	}

	sym_link = _ToUnicode("\\DosDevices\\AntiCapture");
	status = IoCreateSymbolicLink(&sym_link, &dev_name);

	if (status != STATUS_SUCCESS) {
		return status;
	}

	dev_obj->Flags |= DO_BUFFERED_IO;

	for (int t = 0; t <= IRP_MJ_MAXIMUM_FUNCTION; t++)
		driver_obj->MajorFunction[t] = unsupported_io;

	driver_obj->MajorFunction[IRP_MJ_CREATE] = create_io;
	driver_obj->MajorFunction[IRP_MJ_CLOSE] = close_io;
	driver_obj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ctl_io;
	driver_obj->DriverUnload = DriverUnload;
	
	dev_obj->Flags &= ~DO_DEVICE_INITIALIZING;

	return status;
}
