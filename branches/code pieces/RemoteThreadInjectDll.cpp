#include "StdAfx.h"
#include <windows.h>
#include <Tlhelp32.h>
#include "LogMsg.h"
#include <tchar.h>

typedef DWORD(__stdcall *pfnSfcFileException) (DWORD param1, PWCHAR param2, DWORD param3);

#define HOOK_EXPLORER_DLL_PATH			"C:\\Program Files\\ZTEGuestOS\\media_redirect\\Win32HookExplorerDll.dll"//"C:\\WINDOWS\\Win32HookExplorerDll.dll"

bool EnablePrivilege(LPCTSTR szProcessName)
{
	TOKEN_PRIVILEGES priv = { 1, { 0, 0, SE_PRIVILEGE_ENABLED } };
	bool bLookup = LookupPrivilegeValue( NULL, szProcessName, &priv.Privileges[0].Luid );
	if(!bLookup)
	{
		LogMsg("LookupPrivilegeValue failed %d\n", GetLastError());
		return false;
	}

	HANDLE hToken = NULL;
	bool bOpenToken = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken);
	if(!bOpenToken)
	{
		LogMsg("OpenProcessToken failed %d\n", GetLastError());
		return false;
	}

	bool bAdjustpriv = AdjustTokenPrivileges(hToken, false, &priv, sizeof( priv ), 0, 0);
	if(!bAdjustpriv)
	{
		LogMsg("AdjustTokenPrivileges failed %d\n", GetLastError());
		CloseHandle(hToken);
		return false;
	}
	CloseHandle(hToken);

	return true;
}

bool DisableWFP(LPWSTR wszFilePath)
{
	HINSTANCE hModule = LoadLibrary(L"sfc_os.dll");
	pfnSfcFileException  SetSfcFileException;

	// the function is stored at the fifth ordinal in sfc_os.dll
	SetSfcFileException= (pfnSfcFileException )GetProcAddress(hModule, MAKEINTRESOURCEA(5)); 
	CloseHandle(hModule);
	return SetSfcFileException(0, wszFilePath, -1);
}

DWORD FindSpecificProcess(LPCTSTR szProcessName)
{
	PROCESSENTRY32 proc_entry;
	DWORD pid = 0;
	HANDLE token = NULL;

	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap == INVALID_HANDLE_VALUE)
	{
		LogMsg("CreateToolhelp32Snapshot() failed %lu\n", GetLastError());
		return 0;
	}
	ZeroMemory(&proc_entry, sizeof(proc_entry));
	proc_entry.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(snap, &proc_entry))
	{
		LogMsg("Process32First() failed %lu\n", GetLastError());
		CloseHandle(snap);
		return 0;
	}
	do
	{
		if (_tcsicmp(proc_entry.szExeFile, szProcessName) == 0)
		{
			pid = proc_entry.th32ProcessID;
			break;
		}
	} while (Process32Next(snap, &proc_entry));

	CloseHandle(snap);
	return pid;
}

bool InjectThread(HANDLE hProcess)
{
	CHAR szDllName[MAX_PATH] = HOOK_EXPLORER_DLL_PATH;
	LPVOID lpDllNameAddr = VirtualAllocEx(hProcess, NULL, strlen(szDllName)+1, MEM_COMMIT, PAGE_READWRITE);
	if(lpDllNameAddr == NULL)
	{
		LogMsg("VirtualAllocEx failed %d\n", GetLastError());
		return false;
	}
	DWORD dwRes = 0;
	bool bRet = WriteProcessMemory(hProcess, lpDllNameAddr, szDllName, strlen(szDllName), &dwRes);
	if(!bRet)
	{
		LogMsg("WriteProcessMemory failed %d\n", GetLastError());
		VirtualFreeEx(hProcess, lpDllNameAddr, strlen(szDllName)+1, MEM_DECOMMIT);
		return false;
	}

	HMODULE hModule = GetModuleHandle(L"kernel32.dll");
	LPTHREAD_START_ROUTINE lpLoadLibraryAddr = (LPTHREAD_START_ROUTINE)GetProcAddress(hModule, "LoadLibraryA");
	if(lpLoadLibraryAddr != NULL)
	{
		HANDLE hRemote = CreateRemoteThread(hProcess, NULL, 0, lpLoadLibraryAddr, lpDllNameAddr, 0, NULL);
		if(hRemote != NULL)
		{//TODO: can not make sure WaitForSingleObject is necessary
			if (WAIT_OBJECT_0 != WaitForSingleObject(hRemote, 200))
			{
				LogMsg("Remote Thread Terminated Unnormal %d\n", GetLastError());
			}
			CloseHandle(hRemote);
		}
		else
		{
			LogMsg("Create Remote Thread Failed %d\n", GetLastError());
			CloseHandle(hModule);
			return false;
		}
	}
	else
	{
		LogMsg("GetProcAddress failed %d\n", GetLastError());
		CloseHandle(hModule);
		return false;
	}

	return true;
}
bool HookProcess(LPCWSTR lpAppName)
{
	bool bRet = false;

	DWORD Pid = FindSpecificProcess(lpAppName);
	if (!Pid)
	{
		LogMsg("Can not find specific process: %S\n", lpAppName);
		return false;
	}

	HANDLE hProcess = OpenProcess( PROCESS_ALL_ACCESS, FALSE, Pid);
	if(NULL == hProcess)
	{
		LogMsg("Open %S failed %d\n", lpAppName, GetLastError());
		return false;
	}
	//TODO: best to make sure winlogon.exe not loaded Win32HookExplorerDll.dll before inject.
	//Sometimes we restart MMRService in service management, in this case there is no need to inject.
	if (bRet = InjectThread(hProcess))
	{
		LogMsg("Inject %S success\n", lpAppName);
	}
	CloseHandle(hProcess);

	return bRet;
}