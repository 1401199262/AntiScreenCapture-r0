#include "ioctl.h"
#include <stdio.h>
#include <iostream>
using namespace std;

void error_message(const char* msg)
{
	cout << msg << endl;
	Sleep(2000);
	ExitProcess(EXIT_SUCCESS);
}

int main()
{
	SetConsoleTitleW(L"");

	if (!service_is_load())
	{
		error_message("error: driver is not loaded");
	}

	HWND window_handle = 0;
	window_handle = FindWindowW(0, L"Cheat Engine 7.3 beta 2.0.1");

	if (!window_handle)
	{
		error_message("error: target window not found");
	}

	cout << hex << "window_handle" << window_handle << "\n\n";

	DWORD oriaffinity = 0;
	GetWindowDisplayAffinity(window_handle, &oriaffinity);
	cout << "Original affinity = " << oriaffinity << "\n\n";

	NTSTATUS status = change_protect_window_ex(window_handle, WDA_EXCLUDEFROMCAPTURE);

	if (status == 0)
	{
		cout << "success: hide target window" << endl;
	}
	else
	{
		error_message("error: hide target window");
	}

	cout << endl;


	DWORD newaffinity = 0;
	GetWindowDisplayAffinity(window_handle, &newaffinity);
	cout << "New affinity = " << newaffinity << endl;


	system("pause");

}