#ifndef LOADER_H
#define LOADER_H

#include <cstdio>
#include <Windows.h>

//dllmain pointer
using dllmain = BOOL(WINAPI*)(HINSTANCE dll, DWORD reason, LPVOID reserved);

class MemoryLoader
{
    public:
        // Main loader functions
        static LPVOID       LoadPE(const LPSTR lpDLLPath);
        static BOOL         FreePE(const LPVOID lpModule);

        // Custom GetProcAddress implementations (work on both system and manual PEs)
        static LPVOID       GetProcAddressByName(HMODULE hModule, LPSTR lpFunctionName);
        static LPVOID       GetProcAddressByOrdinal(HMODULE hModule, WORD ordinal);

        // Legacy methods (for manually-loaded PEs only)
        static LPVOID       GetFunctionAddress(const LPVOID lpModule, const LPSTR lpFunctionName);
        static LPVOID       GetFunctionAddressByOrdinal(const LPVOID lpModule, const DWORD_PTR dOrdinal);

    private:
	    static HANDLE       GetFileContent(const LPSTR lpFilePath);
	    static BOOL         IsValidPE(const LPVOID lpImage);
	    static BOOL         IsDLL(const LPVOID hDLLData);
	    static BOOL         IsValidArch(const LPVOID lpImage);
	    static DWORD_PTR    GetImageSize(const LPVOID lpImage);
	    static BOOL         HasCallbacks(const LPVOID lpImage);
        static BOOL         ProcessLoadConfig(const LPVOID lpImage);
        static BOOL         ProcessDelayImports(const LPVOID lpImage);
        static BOOL         RegisterExceptionHandlers(const LPVOID lpImage);
        static BOOL         UnregisterExceptionHandlers(const LPVOID lpImage);
        static BOOL         ApplySectionProtections(const LPVOID lpImage);
        static LPVOID       GetFunctionAddressEx(const LPVOID lpModule, const LPSTR lpFunctionName);
};
#endif