#pragma once

#include <stdio.h>
#include <Windows.h>
#pragma comment (lib, "ntdll.lib")
//dllmain pointer
typedef BOOL(WINAPI* dllmain)(HINSTANCE dll, DWORD reason, LPVOID reserved);
LPVOID       LoadPE(const HANDLE lpPEData);
BOOL         FreePE(const LPVOID lpModule);
LPVOID       GetProcAddressByName(HMODULE hModule, LPSTR lpFunctionName);
LPVOID       GetProcAddressByOrdinal(HMODULE hModule, WORD ordinal);
LPVOID       GetFunctionAddress(const LPVOID lpModule, const LPSTR lpFunctionName);
LPVOID       GetFunctionAddressByOrdinal(const LPVOID lpModule, const DWORD_PTR dOrdinal);
BOOL         IsValidPE(const LPVOID lpImage);
BOOL         IsDLL(const LPVOID hDLLData);
BOOL         IsValidArch(const LPVOID lpImage);
DWORD_PTR    GetImageSize(const LPVOID lpImage);
BOOL         HasCallbacks(const LPVOID lpImage);
BOOL         ProcessLoadConfig(const LPVOID lpImage);
BOOL         ProcessDelayImports(const LPVOID lpImage);
BOOL         RegisterExceptionHandlers(const LPVOID lpImage);
BOOL         UnregisterExceptionHandlers(const LPVOID lpImage);
BOOL         ApplySectionProtections(const LPVOID lpImage);
LPVOID       GetFunctionAddressEx(const LPVOID lpModule, const LPSTR lpFunctionName);