#include "stdafx.h"

#include <Dbghelp.h>

#include <fstream>

#pragma comment(lib, "dbghelp.lib")


typedef  int(FAR WINAPI  *DrawTextPtr)(HDC, LPCTSTR, int, LPRECT, UINT);


// Globar variables
//
DrawTextPtr g_pDrawTextW = (DrawTextPtr)::GetProcAddress(::GetModuleHandleW(L"User32.dll"), "DrawTextW");



template <typename T>
bool apply_IAT_patch(LPCSTR pszCalleeModName, T pfnCurrent, T pfnNew, HMODULE hmodCaller)
{

	ULONG ulSize = 0;

	PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(hmodCaller, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &ulSize);
	if (!pImportDesc)
	{
		return false;
	}

	for (; pImportDesc->Name; pImportDesc++)
	{
		PSTR pszModName = (PSTR)((PBYTE)hmodCaller + pImportDesc->Name);

		if (0 == lstrcmpiA(pszModName, pszCalleeModName))
		{
			break;
		}
	}

	if (!pImportDesc->Name)
	{
		return false;
	}


	PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((PBYTE)hmodCaller + pImportDesc->FirstThunk);
	for (; pThunk->u1.Function; pThunk++)
	{
		T *ppfn = (T*)&pThunk->u1.Function;
		if (*ppfn == pfnCurrent)
		{
			MEMORY_BASIC_INFORMATION info = {0};
			::VirtualQuery(ppfn, &info, sizeof(MEMORY_BASIC_INFORMATION));

			if (!VirtualProtect(info.BaseAddress, info.RegionSize, PAGE_READWRITE, &info.Protect))
			{
				return false;
			}

			*ppfn  = (T)pfnNew;

			DWORD dwVal = 0;
			if (!::VirtualProtect(info.BaseAddress, info.RegionSize, info.Protect, &dwVal))
			{
				return false;
			}

			return true;
		}
	}

	return false;
}


 int FAR WINAPI  DrawTextW_Custom(HDC dc, LPCTSTR text, int length, LPRECT rc, UINT format)
{
	auto szText = L"Goodbye, World";
	int len = (int)wcslen(szText);

	return g_pDrawTextW(dc, szText, len, rc, format);
}



bool intercept()
{
	if (!g_pDrawTextW)
	{
		return false;
	}

	return apply_IAT_patch("User32.dll", g_pDrawTextW, &DrawTextW_Custom, ::GetModuleHandle(NULL));
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
		case DLL_PROCESS_ATTACH:
		{		
			if (!intercept())
			{
				//Not so good idea to call User32 functions, because in generic cases this module can be not loaded .
				//But it's ok for this demo project.
				::MessageBoxA(NULL, "Error intercepting API", "Injection !", MB_OK | MB_ICONERROR);
				return FALSE;
			}
		}break;
	}

	return TRUE;
}

