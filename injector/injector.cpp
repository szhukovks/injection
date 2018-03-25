#include "stdafx.h"

#include <iostream>

#include <Windows.h>
#include <Shlwapi.h>


#pragma comment(lib, "shlwapi.lib")


bool check_path(const wchar_t *szPath)
{
	if (!szPath || !::PathFileExistsW(szPath))
	{
		return false;
	}

	return true;	
}


bool start_app(const wchar_t *szAppPath, HANDLE &hApp, HANDLE &hThread)
{
	if (!check_path(szAppPath))
	{
		std::cerr << "Invalid exe module path, please check args" << std::endl;
		return false;
	}

	STARTUPINFOW si = { 0 };
	PROCESS_INFORMATION pi = { 0 };

	SECURITY_DESCRIPTOR sd = {0};
	::InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
	::SetSecurityDescriptorDacl(&sd, true, NULL, false);

	SECURITY_ATTRIBUTES		sa = { 0 };
	sa.lpSecurityDescriptor = &sd;
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.bInheritHandle = FALSE;

	auto success = ::CreateProcessW(szAppPath, L"", &sa, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi);
	if (!success)
	{
		std::wcerr << "Error creating process, with error code = " << ::GetLastError() << std::endl;
		return false;
	}

	hApp = pi.hProcess;
	hThread = pi.hThread;

	return true;
}

bool inject_dll(HANDLE hApp, const wchar_t *szInjectionDll)
{
	if (!check_path(szInjectionDll))
	{
		std::cerr << "Invalid dll/injection module path, please check args" << std::endl;
		return false;
	}

	auto pLoadLibraryW = ::GetProcAddress(GetModuleHandleW(L"Kernel32"), "LoadLibraryW");
	if (!pLoadLibraryW)
	{
		std::wcerr << "Error obtaining of adress of LoadLibraryW function" << std::endl;
		return false;
	}

	auto path_cchar = wcslen(szInjectionDll) + 1;
	auto block_size = path_cchar * sizeof(wchar_t);
	auto szPathMemory = ::VirtualAllocEx(hApp, NULL, block_size, MEM_COMMIT, PAGE_READWRITE);
	if (!szPathMemory)
	{
		std::wcerr << "Error allocating memory block, for passing  path to dll" << std::endl;
		return false;
	}
	
	SIZE_T count = 0;
	auto success = ::WriteProcessMemory(hApp, szPathMemory, szInjectionDll, block_size,  &count);
	if (!success)
	{
		std::wcerr << "Error writing memory block to process address space" << std::endl;
		return false;
	}


	DWORD dwThreadId = 0;
	HANDLE hThread = ::CreateRemoteThread(hApp, nullptr, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryW, szPathMemory, 0, &dwThreadId);
	if (!hThread)
	{
		std::wcerr << "Error creating remote thread, injection failed" << std::endl;
		return  false;
	}
	else
	{
		
		std::wcerr << "Remote thread created, ID=" << dwThreadId << std::endl;		
		::WaitForSingleObject(hThread, INFINITE);
		
		DWORD dwExit = 0;		
		::GetExitCodeThread(hThread, &dwExit );
		std::wcerr << "Remote thread exit code : " << dwExit << std::endl;

		::CloseHandle(hThread);
	}

	return true;
}


int _tmain(int argc, TCHAR **argv)
{
	if (argc != 3)
	{
		std::wcerr << L"Error: Invalid argments!" << std::endl;
		std::wcerr << L"How to use: " << std::endl;
		std::wcerr << L"injector.exe path\\to\\example-app.exe  path\\to\\injection.dll" << std::endl;
		return -1;
	}

	auto szAppPath = (const wchar_t *)argv[1];
	auto szInjectPath = (const wchar_t *)argv[2];

	HANDLE hApp = INVALID_HANDLE_VALUE;
	HANDLE hThread = INVALID_HANDLE_VALUE;
	if (!start_app(szAppPath, hApp, hThread))
	{
		return -1;
	}

	if (inject_dll(hApp, szInjectPath))
	{
		std::wcerr << "Injection successfull, waiting until application close" << std::endl;
		::ResumeThread(hThread);
		::WaitForSingleObject(hApp, INFINITE);
	}
	else
	{
		std::wcerr << "Unable to inject module, so example app will be terminated" << std::endl;
		::TerminateProcess(hApp, 0);
	}
	
	::CloseHandle(hThread);
	::CloseHandle(hApp);

    return 0;
}

