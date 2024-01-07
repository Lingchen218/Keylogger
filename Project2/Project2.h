#pragma once

#define _WIN32_WINNT    0x0400
#define STRICT
#define WIN32_LEAN_AND_MEAN
#include <stdio.h>
#include <stdlib.h>

#include<WinUser.h>

//#include <oleidl.h>
#include <comdef.h>
#include <vector>
#include <string>
#include <shellapi.h>
#include <io.h>

namespace pr {
	extern "C" {
		__declspec(dllexport) void installhook( LPCTSTR exxpath);

		__declspec(dllexport) void HKRunator(LPCTSTR programName);

		__declspec(dllexport) BOOL IsRunAsAdministrator();

		__declspec(dllexport) int  wCreateTask(LPCWSTR exepath);

		__declspec(dllexport) BOOL DisguiseProcess(DWORD dwProcessId, wchar_t* lpwszPath, wchar_t* lpwszCmd);
	}
}
