#include "Loader.h"

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define ZwCurrentProcess() NtCurrentProcess()
#define NtCurrentThread() ((HANDLE)(LONG_PTR)-2)
#define ZwCurrentThread() NtCurrentThread()
#define NtCurrentSession() ((HANDLE)(LONG_PTR)-3)
#define ZwCurrentSession() NtCurrentSession()

/**
 *	Function to check if the image is a valid PE file.
 *	\param lpImage : PE image data.
 *	\return : TRUE if the image is a valid PE else no.
 */
BOOL IsValidPE(const LPVOID lpImage)
{
    PIMAGE_DOS_HEADER lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
    PIMAGE_NT_HEADERS lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
    if (lpImageNTHeader->Signature == IMAGE_NT_SIGNATURE)
        return TRUE;

    return FALSE;
}

/**
 *	Function to identify if the PE file is a DLL.
 *	\param hDLLData : DLL image.
 *	\return : true if the image is a DLL else false.
 */
BOOL IsDLL(const LPVOID hDLLData)
{
    PIMAGE_DOS_HEADER lpImageDOSHeader = (PIMAGE_DOS_HEADER)(hDLLData);
    PIMAGE_NT_HEADERS lpImageNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)hDLLData + lpImageDOSHeader->e_lfanew);

    if (lpImageNtHeader->FileHeader.Characteristics & IMAGE_FILE_DLL)
        return TRUE;

    return FALSE;
}

/**
 *	Function to check if the image has the same arch.
 *	\param lpImage : PE image data.
 *	\return : TRUE if the image has the arch else FALSE.
 */
BOOL IsValidArch(const LPVOID lpImage)
{
    PIMAGE_DOS_HEADER lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
    PIMAGE_NT_HEADERS lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
    if (lpImageNTHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR_MAGIC)
        return TRUE;

    return FALSE;
}

/**
 *	Function to retrieve the size of the PE image.
 *	\param lpImage : PE image data.
 *	\return : the size of the PE image.
 */
DWORD_PTR GetImageSize(const LPVOID lpImage)
{
    PIMAGE_DOS_HEADER lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
    PIMAGE_NT_HEADERS lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
    return lpImageNTHeader->OptionalHeader.SizeOfImage;
}

/**
 *	Function to identify if the PE file contains TLS callback directory.
 *	\param lpImage : PE image data.
 *	\return : true if TLS callback directory is present, FALSE otherwise.
 */
BOOL HasCallbacks(const LPVOID lpImage)
{
    PIMAGE_DOS_HEADER lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
    PIMAGE_NT_HEADERS lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImage + lpImageDOSHeader->e_lfanew);
    const DWORD_PTR dVirtualAddress = lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;

    return dVirtualAddress != 0;
}

// ============================================================================
// FUNCTION IMPLEMENTATIONS (x64 only)
// ============================================================================

/**
 * Function to process delay-load imports
 * @param lpImage : base address of the loaded PE image
 * @return : TRUE if success, FALSE otherwise
 */
BOOL ProcessDelayImports(const LPVOID lpImage)
{
    PIMAGE_DOS_HEADER lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
    PIMAGE_NT_HEADERS lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImage + lpImageDOSHeader->e_lfanew);

    // Check if delay import directory exists
    const IMAGE_DATA_DIRECTORY ImageDataDelayImport = lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    if (ImageDataDelayImport.VirtualAddress == 0 || ImageDataDelayImport.Size == 0)
    {
        printf("[+] No delay-load imports found.\n");
        return TRUE;
    }

    printf("[+] Processing delay-load imports...\n");

    PIMAGE_DELAYLOAD_DESCRIPTOR lpDelayImportDescriptor = (PIMAGE_DELAYLOAD_DESCRIPTOR)((DWORD_PTR)lpImage + ImageDataDelayImport.VirtualAddress);

    // Iterate through delay import descriptors (terminated by null entry)
    while (lpDelayImportDescriptor->DllNameRVA != 0)
    {
        LPSTR lpLibraryName = (LPSTR)((DWORD_PTR)lpImage + lpDelayImportDescriptor->DllNameRVA);

        HMODULE hModule = NULL;
        NTSTATUS status;
        UNICODE_STRING uModuleName;
        WCHAR wLibraryName[MAX_PATH];

        // Convert ANSI library name to wide char

        MultiByteToWideChar(CP_ACP, 0, lpLibraryName, -1, wLibraryName, MAX_PATH);

        // Initialize UNICODE_STRING with the library name
        RtlInitUnicodeString(&uModuleName, wLibraryName);

        // Load the DLL using LdrLoadDll
        status = LdrLoadDll(
            NULL,           // PathToFile (NULL = use default search path)
            0,              // Flags (0 = default behavior)
            &uModuleName,   // ModuleFileName as UNICODE_STRING
            (PHANDLE)&hModule  // Output handle to the loaded module
        );
        //const HMODULE hModule = LoadLibraryA(lpLibraryName);

        if (hModule == NULL)
        {
            printf("[-] Failed to load delay-imported DLL: %s\n", lpLibraryName);
            return FALSE;
        }

        printf("[+] Delay-loading %s\n", lpLibraryName);

        // Process Import Name Table (INT) and Import Address Table (IAT)
        PIMAGE_THUNK_DATA lpINT = (PIMAGE_THUNK_DATA)((DWORD_PTR)lpImage + lpDelayImportDescriptor->ImportNameTableRVA);
        PIMAGE_THUNK_DATA lpIAT = (PIMAGE_THUNK_DATA)((DWORD_PTR)lpImage + lpDelayImportDescriptor->ImportAddressTableRVA);

        // Resolve all delay-imported functions
        while (lpINT->u1.AddressOfData != 0)
        {
            if (IMAGE_SNAP_BY_ORDINAL(lpINT->u1.Ordinal))
            {
                // Import by ordinal
                UINT functionOrdinal = (UINT)IMAGE_ORDINAL(lpINT->u1.Ordinal);
                lpIAT->u1.Function = (DWORD_PTR)GetProcAddressByOrdinal(hModule, functionOrdinal);
                printf("[+]\tDelay Function Ordinal #%u\n", functionOrdinal);
            }
            else
            {
                // Import by name
                PIMAGE_IMPORT_BY_NAME lpData = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)lpImage + lpINT->u1.AddressOfData);
                DWORD_PTR functionAddress = (DWORD_PTR)GetProcAddressByName(hModule, lpData->Name);
                lpIAT->u1.Function = functionAddress;
                printf("[+]\tDelay Function %s\n", (LPSTR)lpData->Name);
            }

            lpINT++;
            lpIAT++;
        }

        lpDelayImportDescriptor++;
    }

    printf("[+] Delay-load imports processed successfully.\n");
    return TRUE;
}

/**
 * Function to process Load Config Directory
 * @param lpImage : base address of the loaded PE image
 * @return : TRUE if success, FALSE otherwise
 */
BOOL ProcessLoadConfig(const LPVOID lpImage)
{
    PIMAGE_DOS_HEADER lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
    PIMAGE_NT_HEADERS lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImage + lpImageDOSHeader->e_lfanew);

    // Check if Load Config directory exists
    const IMAGE_DATA_DIRECTORY ImageDataLoadConfig = lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
    if (ImageDataLoadConfig.VirtualAddress == 0 || ImageDataLoadConfig.Size == 0)
    {
        printf("[+] No Load Config directory found.\n");
        return TRUE;
    }

    printf("[+] Processing Load Config directory...\n");

    PIMAGE_LOAD_CONFIG_DIRECTORY64 lpLoadConfig = (PIMAGE_LOAD_CONFIG_DIRECTORY64)((DWORD_PTR)lpImage + ImageDataLoadConfig.VirtualAddress);

    // Validate Size field
    if (lpLoadConfig->Size < sizeof(IMAGE_LOAD_CONFIG_DIRECTORY64))
    {
        printf("[!] Load Config size mismatch (expected: %zu, got: %lu)\n",
            sizeof(IMAGE_LOAD_CONFIG_DIRECTORY64), lpLoadConfig->Size);
    }

    // Log security features
    if (lpLoadConfig->SecurityCookie != 0)
    {
        printf("[+] Security Cookie (GS): 0x%llx\n", lpLoadConfig->SecurityCookie);
    }

    if (lpLoadConfig->SEHandlerTable != 0 && lpLoadConfig->SEHandlerCount > 0)
    {
        printf("[+] SEH Handlers: %llu handler(s) at 0x%llx\n",
            lpLoadConfig->SEHandlerCount, lpLoadConfig->SEHandlerTable);
    }

    if (lpLoadConfig->GuardCFCheckFunctionPointer != 0)
    {
        printf("[+] Control Flow Guard (CFG) enabled\n");
    }

    if (lpLoadConfig->GuardFlags & 0x00000100)
    {
        printf("[+] CFG instrumentation present\n");
    }

    printf("[+] Load Config directory processed.\n");
    return TRUE;
}

/**
 * Function to register exception handlers for x64
 * @param lpImage : base address of the loaded PE image
 * @return : TRUE if success, FALSE otherwise
 */
BOOL RegisterExceptionHandlers(const LPVOID lpImage)
{
    PIMAGE_DOS_HEADER lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
    PIMAGE_NT_HEADERS lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImage + lpImageDOSHeader->e_lfanew);

    // x64: Register exception handlers using .pdata section
    const IMAGE_DATA_DIRECTORY ImageDataException = lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (ImageDataException.VirtualAddress == 0 || ImageDataException.Size == 0)
    {
        printf("[+] No exception handlers to register.\n");
        return TRUE;
    }

    printf("[+] Registering exception handlers...\n");

    PRUNTIME_FUNCTION lpRuntimeFunction = (PRUNTIME_FUNCTION)((DWORD_PTR)lpImage + ImageDataException.VirtualAddress);
    const DWORD dwFunctionCount = ImageDataException.Size / sizeof(RUNTIME_FUNCTION);

    // Register the function table with Windows
    const BOOLEAN bResult = RtlAddFunctionTable(
        lpRuntimeFunction,
        dwFunctionCount,
        (DWORD64)lpImage
    );

    if (!bResult)
    {
        printf("[-] Failed to register exception handlers!\n");
        return FALSE;
    }

    printf("[+] Registered %lu exception handler(s).\n", dwFunctionCount);
    return TRUE;
}

/**
 * Function to unregister exception handlers (for cleanup)
 * @param lpImage : base address of the loaded PE image
 * @return : TRUE if success, FALSE otherwise
 */
BOOL UnregisterExceptionHandlers(const LPVOID lpImage)
{
    PIMAGE_DOS_HEADER lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
    PIMAGE_NT_HEADERS lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImage + lpImageDOSHeader->e_lfanew);

    const IMAGE_DATA_DIRECTORY ImageDataException = lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (ImageDataException.VirtualAddress == 0 || ImageDataException.Size == 0)
    {
        return TRUE;
    }

    PRUNTIME_FUNCTION lpRuntimeFunction = (PRUNTIME_FUNCTION)((DWORD_PTR)lpImage + ImageDataException.VirtualAddress);

    const BOOLEAN bResult = RtlDeleteFunctionTable(lpRuntimeFunction);
    if (!bResult)
    {
        printf("[-] Failed to unregister exception handlers!\n");
        return FALSE;
    }

    printf("[+] Exception handlers unregistered.\n");
    return TRUE;
}

/**
 * Function to apply proper memory protection to sections
 * @param lpImage : base address of the loaded PE image
 * @return : TRUE if success, FALSE otherwise
 */
BOOL ApplySectionProtections(const LPVOID lpImage)
{
    PIMAGE_DOS_HEADER lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
    PIMAGE_NT_HEADERS lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImage + lpImageDOSHeader->e_lfanew);
    PIMAGE_SECTION_HEADER lpImageSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)lpImageNTHeader + 4 + sizeof(IMAGE_FILE_HEADER) + lpImageNTHeader->FileHeader.SizeOfOptionalHeader);

    printf("[+] Applying section memory protections...\n");

    for (int i = 0; i < lpImageNTHeader->FileHeader.NumberOfSections; i++)
    {
        PIMAGE_SECTION_HEADER lpCurrentSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)lpImageSectionHeader + (i * sizeof(IMAGE_SECTION_HEADER)));

        DWORD dwProtection = PAGE_NOACCESS;
        const DWORD dwCharacteristics = lpCurrentSectionHeader->Characteristics;

        // Determine protection based on section characteristics
        // IMAGE_SCN_MEM_EXECUTE = 0x20000000
        // IMAGE_SCN_MEM_READ    = 0x40000000
        // IMAGE_SCN_MEM_WRITE   = 0x80000000

        if (dwCharacteristics & IMAGE_SCN_MEM_EXECUTE)
        {
            if (dwCharacteristics & IMAGE_SCN_MEM_WRITE)
                dwProtection = PAGE_EXECUTE_READWRITE;
            else if (dwCharacteristics & IMAGE_SCN_MEM_READ)
                dwProtection = PAGE_EXECUTE_READ;
            else
                dwProtection = PAGE_EXECUTE;
        }
        else
        {
            if (dwCharacteristics & IMAGE_SCN_MEM_WRITE)
                dwProtection = PAGE_READWRITE;
            else if (dwCharacteristics & IMAGE_SCN_MEM_READ)
                dwProtection = PAGE_READONLY;
            else
                dwProtection = PAGE_NOACCESS;
        }

        LPVOID lpSectionAddress = (LPVOID)((DWORD_PTR)lpImage + lpCurrentSectionHeader->VirtualAddress);
        SIZE_T stSectionSize = lpCurrentSectionHeader->Misc.VirtualSize;

        if (stSectionSize == 0)
            continue;

        DWORD dwOldProtection = 0;

        /*if (!VirtualProtect(lpSectionAddress, stSectionSize, dwProtection, &dwOldProtection))
        {
            printf("[-] Failed to set protection for section %s (Error: %lu)\n",
                (LPSTR)lpCurrentSectionHeader->Name, GetLastError());
            return FALSE;
        }*/

        NTSTATUS status;
        PVOID baseAddress = lpSectionAddress;
        SIZE_T regionSize = stSectionSize;
        ULONG oldProtection = 0;

        status = NtProtectVirtualMemory(
            NtCurrentProcess(),    // Process handle (use -1 or GetCurrentProcess() for current process)
            &baseAddress,           // Pointer to base address (will be updated to page-aligned address)
            &regionSize,            // Pointer to size (will be updated to page-aligned size)
            dwProtection,           // New protection flags (same as VirtualProtect)
            &oldProtection          // Pointer to receive old protection
        );

        // Readable protection name
        const char* protStr = "UNKNOWN";
        if (dwProtection == PAGE_EXECUTE_READWRITE) protStr = "RWX";
        else if (dwProtection == PAGE_EXECUTE_READ) protStr = "R-X";
        else if (dwProtection == PAGE_READWRITE) protStr = "RW-";
        else if (dwProtection == PAGE_READONLY) protStr = "R--";
        else if (dwProtection == PAGE_EXECUTE) protStr = "--X";
        else if (dwProtection == PAGE_NOACCESS) protStr = "---";

        printf("[+] Section %s: %s (0x%lx)\n",
            (LPSTR)lpCurrentSectionHeader->Name, protStr, dwProtection);
    }

    printf("[+] Section protections applied successfully.\n");
    return TRUE;
}

/**
 * Enhanced GetFunctionAddress with forwarded exports support
 * @param lpModule : address of the DLL
 * @param lpFunctionName : name of the function
 * @return : address of the function if success else NULL
 */
LPVOID GetFunctionAddressEx(const LPVOID lpModule, const LPSTR lpFunctionName)
{
    PIMAGE_DOS_HEADER lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpModule;
    PIMAGE_NT_HEADERS lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);

    if (lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
        return NULL;

    PIMAGE_EXPORT_DIRECTORY lpImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)lpModule + lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    const DWORD_PTR dNumberOfNames = lpImageExportDirectory->NumberOfNames;

    // Get export directory bounds for forwarded export detection
    const DWORD_PTR dwExportDirStart = lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    const DWORD_PTR dwExportDirEnd = dwExportDirStart + lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    for (int i = 0; i < (int)dNumberOfNames; i++)
    {
        LPSTR lpCurrentFunctionName = (LPSTR)(((DWORD*)(lpImageExportDirectory->AddressOfNames + (DWORD_PTR)lpModule))[i] + (DWORD_PTR)lpModule);
        WORD lpCurrentOridnal = ((WORD*)(lpImageExportDirectory->AddressOfNameOrdinals + (DWORD_PTR)lpModule))[i];
        DWORD addRVA = ((DWORD*)((DWORD_PTR)lpModule + lpImageExportDirectory->AddressOfFunctions))[lpCurrentOridnal];

        if (strcmp(lpCurrentFunctionName, lpFunctionName) == 0)
        {
            // Check if this is a forwarded export
            if (addRVA >= dwExportDirStart && addRVA < dwExportDirEnd)
            {
                // This is a forwarded export (e.g., "NTDLL.RtlAllocateHeap")
                char* lpForwardString = (char*)((DWORD_PTR)lpModule + addRVA);
                printf("[+] Forwarded export: %s -> %s\n", lpFunctionName, lpForwardString);

                // Parse forward string (format: "DllName.FunctionName" or "DllName.#Ordinal")
                char szForwardDll[256] = { 0 };
                char szForwardFunction[256] = { 0 };

                char* lpDot = strchr(lpForwardString, '.');
                if (lpDot != NULL)
                {
                    size_t dllNameLen = lpDot - lpForwardString;
                    strncpy_s(szForwardDll, sizeof(szForwardDll), lpForwardString, dllNameLen);
                    strcat_s(szForwardDll, sizeof(szForwardDll), ".dll");
                    strcpy_s(szForwardFunction, sizeof(szForwardFunction), lpDot + 1);

                    // Load the forwarded DLL
                    HMODULE hForwardModule = LoadLibraryA(szForwardDll);
                    if (hForwardModule != NULL)
                    {
                        // Check if forwarding to ordinal (starts with '#')
                        if (szForwardFunction[0] == '#')
                        {
                            WORD ordinal = (WORD)atoi(szForwardFunction + 1);
                            return (LPVOID)GetProcAddressByOrdinal(hForwardModule, ordinal);
                        }
                        else
                        {
                            return (LPVOID)GetProcAddressByName(hForwardModule, szForwardFunction);
                        }
                    }
                }

                printf("[-] Failed to resolve forwarded export: %s\n", lpForwardString);
                return NULL;
            }

            // Normal export
            return (LPVOID)((DWORD_PTR)lpModule + addRVA);
        }
    }

    return NULL;
}


/**
 * Custom GetProcAddress - Works on both system and manually-loaded modules
 * @param hModule : Module handle (from LoadLibrary or your LoadDLL)
 * @param lpFunctionName : Name of the function to find
 * @return : Function address if success, NULL otherwise
 */
LPVOID GetProcAddressByName(const HMODULE hModule, const LPSTR lpFunctionName)
{
    if (hModule == NULL || lpFunctionName == NULL)
        return NULL;

    PIMAGE_DOS_HEADER lpImageDOSHeader = (PIMAGE_DOS_HEADER)hModule;

    // Validate DOS header
    if (lpImageDOSHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    PIMAGE_NT_HEADERS lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)hModule + lpImageDOSHeader->e_lfanew);

    // Validate NT header
    if (lpImageNTHeader->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    // Check if export directory exists
    if (lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
        return NULL;

    PIMAGE_EXPORT_DIRECTORY lpImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(
        (DWORD_PTR)hModule + lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
        );

    // Get export tables
    const DWORD* lpAddressOfFunctions = (DWORD*)((DWORD_PTR)hModule + lpImageExportDirectory->AddressOfFunctions);
    const DWORD* lpAddressOfNames = (DWORD*)((DWORD_PTR)hModule + lpImageExportDirectory->AddressOfNames);
    const WORD* lpAddressOfNameOrdinals = (WORD*)((DWORD_PTR)hModule + lpImageExportDirectory->AddressOfNameOrdinals);

    // Get export directory bounds for forwarded export detection
    const DWORD_PTR dwExportDirStart = lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    const DWORD_PTR dwExportDirEnd = dwExportDirStart + lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    // Search for function by name
    for (DWORD i = 0; i < lpImageExportDirectory->NumberOfNames; i++)
    {
        const char* lpCurrentFunctionName = (const char*)((DWORD_PTR)hModule + lpAddressOfNames[i]);

        if (strcmp(lpCurrentFunctionName, lpFunctionName) == 0)
        {
            // Found the function - get its ordinal
            const WORD ordinal = lpAddressOfNameOrdinals[i];
            const DWORD functionRVA = lpAddressOfFunctions[ordinal];

            // Check if this is a forwarded export (PE spec section 6.3.2)
            if (functionRVA >= dwExportDirStart && functionRVA < dwExportDirEnd)
            {
                // This is a forwarded export (e.g., "NTDLL.RtlAllocateHeap")
                char* lpForwardString = (char*)((DWORD_PTR)hModule + functionRVA);

                // Parse forward string (format: "DllName.FunctionName" or "DllName.#Ordinal")
                char szForwardDll[256] = { 0 };
                char szForwardFunction[256] = { 0 };

                char* lpDot = strchr(lpForwardString, '.');
                if (lpDot != NULL)
                {
                    size_t dllNameLen = lpDot - lpForwardString;
                    strncpy_s(szForwardDll, sizeof(szForwardDll), lpForwardString, dllNameLen);
                    strcat_s(szForwardDll, sizeof(szForwardDll), ".dll");
                    strcpy_s(szForwardFunction, sizeof(szForwardFunction), lpDot + 1);

                    // Load the forwarded DLL
                    //HMODULE hForwardModule = LoadLibraryA(szForwardDll);

                    HMODULE hForwardModule = NULL;
                    NTSTATUS status;
                    UNICODE_STRING uModuleName;
                    WCHAR wLibraryName[MAX_PATH];

                    // Convert ANSI library name to wide char
                    MultiByteToWideChar(CP_ACP, 0, szForwardDll, -1, wLibraryName, MAX_PATH);

                    // Initialize UNICODE_STRING with the library name
                    RtlInitUnicodeString(&uModuleName, wLibraryName);

                    // Load the DLL using LdrLoadDll
                    status = LdrLoadDll(
                        NULL,           // PathToFile (NULL = use default search path)
                        0,              // Flags (0 = default behavior)
                        &uModuleName,   // ModuleFileName as UNICODE_STRING
                        (PHANDLE)&hForwardModule  // Output handle to the loaded module
                    );

                    if (hForwardModule != NULL)
                    {
                        // Check if forwarding to ordinal (starts with '#')
                        if (szForwardFunction[0] == '#')
                        {
                            WORD forwardOrdinal = (WORD)atoi(szForwardFunction + 1);
                            return GetProcAddressByOrdinal(hForwardModule, forwardOrdinal);
                        }
                        else
                        {
                            // Recursive call to handle forwarding chains
                            return GetProcAddressByName(hForwardModule, szForwardFunction);
                        }
                    }
                }

                return NULL;  // Failed to resolve forward
            }

            // Normal export - return function address
            return (LPVOID)((DWORD_PTR)hModule + functionRVA);
        }
    }

    return NULL;  // Function not found
}

/**
 * Custom GetProcAddress by ordinal - Works on both system and manually-loaded modules
 * @param hModule : Module handle (from LoadLibrary or your LoadDLL)
 * @param ordinal : Ordinal of the function to find
 * @return : Function address if success, NULL otherwise
 */
LPVOID GetProcAddressByOrdinal(const HMODULE hModule, const WORD ordinal)
{
    if (hModule == NULL)
        return NULL;

    PIMAGE_DOS_HEADER lpImageDOSHeader = (PIMAGE_DOS_HEADER)hModule;

    // Validate DOS header
    if (lpImageDOSHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    PIMAGE_NT_HEADERS lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)hModule + lpImageDOSHeader->e_lfanew);

    // Validate NT header
    if (lpImageNTHeader->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    // Check if export directory exists
    if (lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
        return NULL;

    PIMAGE_EXPORT_DIRECTORY lpImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(
        (DWORD_PTR)hModule + lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
        );

    // Calculate actual ordinal index (ordinal - base)
    const DWORD ordinalIndex = ordinal - lpImageExportDirectory->Base;

    // Validate ordinal is in range
    if (ordinalIndex >= lpImageExportDirectory->NumberOfFunctions)
        return NULL;

    // Get function RVA from AddressOfFunctions table
    const DWORD* lpAddressOfFunctions = (DWORD*)((DWORD_PTR)hModule + lpImageExportDirectory->AddressOfFunctions);
    const DWORD functionRVA = lpAddressOfFunctions[ordinalIndex];

    if (functionRVA == 0)
        return NULL;  // Ordinal slot is empty

    // Get export directory bounds for forwarded export detection
    const DWORD_PTR dwExportDirStart = lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    const DWORD_PTR dwExportDirEnd = dwExportDirStart + lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    // Check if this is a forwarded export
    if (functionRVA >= dwExportDirStart && functionRVA < dwExportDirEnd)
    {
        // Forwarded export - resolve it
        char* lpForwardString = (char*)((DWORD_PTR)hModule + functionRVA);

        char szForwardDll[256] = { 0 };
        char szForwardFunction[256] = { 0 };

        char* lpDot = strchr(lpForwardString, '.');
        if (lpDot != NULL)
        {
            size_t dllNameLen = lpDot - lpForwardString;
            strncpy_s(szForwardDll, sizeof(szForwardDll), lpForwardString, dllNameLen);
            strcat_s(szForwardDll, sizeof(szForwardDll), ".dll");
            strcpy_s(szForwardFunction, sizeof(szForwardFunction), lpDot + 1);

            //HMODULE hForwardModule = LoadLibraryA(szForwardDll);

            HMODULE hForwardModule = NULL;
            NTSTATUS status;
            UNICODE_STRING uModuleName;
            WCHAR wLibraryName[MAX_PATH];

            // Convert ANSI library name to wide char
            MultiByteToWideChar(CP_ACP, 0, szForwardDll, -1, wLibraryName, MAX_PATH);

            // Initialize UNICODE_STRING with the library name
            RtlInitUnicodeString(&uModuleName, wLibraryName);

            // Load the DLL using LdrLoadDll
            status = LdrLoadDll(
                NULL,           // PathToFile (NULL = use default search path)
                0,              // Flags (0 = default behavior)
                &uModuleName,   // ModuleFileName as UNICODE_STRING
                (PHANDLE)&hForwardModule  // Output handle to the loaded module
            );

            if (hForwardModule != NULL)
            {
                if (szForwardFunction[0] == '#')
                {
                    WORD forwardOrdinal = (WORD)atoi(szForwardFunction + 1);
                    return GetProcAddressByOrdinal(hForwardModule, forwardOrdinal);
                }
                else
                {
                    return GetProcAddressByName(hForwardModule, szForwardFunction);
                }
            }
        }

        return NULL;
    }

    // Normal export - return function address
    return (LPVOID)((DWORD_PTR)hModule + functionRVA);
}


/**
 *	Function to find function in the DLL.
 *	\param lpModule : address of the DLL.
 *	\param lpFunctionName : name of the function.
 *	\return : address of the function if success else NULL.
 */
LPVOID GetFunctionAddress(const LPVOID lpModule, const LPSTR lpFunctionName)
{
    PIMAGE_DOS_HEADER lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpModule;
    PIMAGE_NT_HEADERS lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
    if (lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
        return NULL;

    PIMAGE_EXPORT_DIRECTORY lpImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)lpModule + lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    const DWORD_PTR dNumberOfNames = lpImageExportDirectory->NumberOfNames;

    for (int i = 0; i < (int)dNumberOfNames; i++)
    {
        LPSTR lpCurrentFunctionName = (LPSTR)(((DWORD*)(lpImageExportDirectory->AddressOfNames + (DWORD_PTR)lpModule))[i] + (DWORD_PTR)lpModule);
        WORD lpCurrentOridnal = ((WORD*)(lpImageExportDirectory->AddressOfNameOrdinals + (DWORD_PTR)lpModule))[i];
        DWORD addRVA = ((DWORD*)((DWORD_PTR)lpModule + lpImageExportDirectory->AddressOfFunctions))[lpCurrentOridnal];
        if (strcmp(lpCurrentFunctionName, lpFunctionName) == 0)
            return (LPVOID)((DWORD_PTR)lpModule + addRVA);
    }

    return NULL;
}

/**
 *	Function to retrieve function address by using ordinal.
 *	\param lpModule : address of the DLL.
 *	\param dOrdinal : ordinal of the function.
 *	\return : the address of the function.
 */
LPVOID GetFunctionAddressByOrdinal(const LPVOID lpModule, const DWORD_PTR dOrdinal)
{
    PIMAGE_DOS_HEADER lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpModule;
    PIMAGE_NT_HEADERS lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
    if (lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
        return NULL;

    PIMAGE_EXPORT_DIRECTORY lpImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)lpModule + lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD addRVA = ((DWORD*)((DWORD_PTR)lpModule + lpImageExportDirectory->AddressOfFunctions))[dOrdinal];
    return (LPVOID)((DWORD_PTR)lpModule + addRVA);
}

/**
 *	Function to free the PE.
 *	\param lpModule : address of the loaded PE.
 *	\return : FALSE if it failed else TRUE.
 */
BOOL FreePE(const LPVOID lpModule)
{
    PIMAGE_DOS_HEADER lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpModule;
    PIMAGE_NT_HEADERS lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);

    if (HasCallbacks(lpModule))
    {
        /*const auto lpImageTLSDirectory = (PIMAGE_TLS_DIRECTORY)((DWORD_PTR)lpModule + lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        auto lpCallbackArray = (PIMAGE_TLS_CALLBACK*)lpImageTLSDirectory->AddressOfCallBacks;

        while (*lpCallbackArray != NULL)
        {
            const auto lpImageCallback = *lpCallbackArray;
            lpImageCallback(lpModule, DLL_PROCESS_DETACH, NULL);
            lpCallbackArray++;
        }*/

        // Convert to C-style casts and remove auto keyword
        PIMAGE_TLS_DIRECTORY lpImageTLSDirectory = (PIMAGE_TLS_DIRECTORY)((DWORD_PTR)lpModule + lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        PIMAGE_TLS_CALLBACK* lpCallbackArray = (PIMAGE_TLS_CALLBACK*)lpImageTLSDirectory->AddressOfCallBacks;

        while (*lpCallbackArray != NULL)
        {
            PIMAGE_TLS_CALLBACK lpImageCallback = *lpCallbackArray;
            lpImageCallback(lpModule, DLL_PROCESS_ATTACH, NULL);
            lpCallbackArray++;
        }


        printf("[+] TLS callbacks executed (DLL_PROCESS_DETACH).\n");
    }

    dllmain main = (dllmain)((DWORD_PTR)lpModule + lpImageNTHeader->OptionalHeader.AddressOfEntryPoint);
    const BOOL result = main((HINSTANCE)lpModule, DLL_PROCESS_DETACH, NULL);

    if (!result)
    {
        printf("[-] An error is occured when trying to call dllmain with DLL_PROCESS_DETACH !\n");
        return FALSE;
    }

    printf("[+] dllmain have been called (DLL_PROCESS_DETACH).\n");

    const BOOL bFree = VirtualFree(lpModule, 0, MEM_RELEASE);
    if (!bFree)
    {
        printf("[-] An error is occured when trying to free the DLL !\n");
        return FALSE;
    }

    printf("[+] DLL unloaded successfully !\n");

    return TRUE;
}
/**
 *	Function to load a PE in memory
 *	\param lpPEData : Raw bytes of PE file.
 *	\return : PE address if success else NULL.
 */
LPVOID LoadPE(const HANDLE lpPEData)
{
    printf("[+] DLL LOADER\n");

    //const HANDLE hDLLData = GetFileContent(lpDLLPath);
    if (lpPEData == INVALID_HANDLE_VALUE || lpPEData == NULL)
    {
        printf("[-] An error occurred when trying to get DLL's data!\n");
        return NULL;
    }

    printf("[+] DLL's data at 0x%p\n", (LPVOID)lpPEData);

    if (!IsValidPE(lpPEData))
    {
        printf("[-] The DLL is not a valid PE file!\n");
        if (lpPEData != NULL)
            HeapFree(GetProcessHeap(), 0, lpPEData);
        return NULL;
    }

    printf("[+] The PE image is valid.\n");

    if (!IsValidArch(lpPEData))
    {
        printf("[-] The architectures are not compatible!\n");
        return NULL;
    }

    printf("[+] The architectures are compatible.\n");

    // Parse file buffer headers
    PIMAGE_DOS_HEADER lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpPEData;
    PIMAGE_NT_HEADERS lpImageNTHeaderFile = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpPEData + lpImageDOSHeader->e_lfanew);
    PIMAGE_SECTION_HEADER lpImageSectionHeaderFile = (PIMAGE_SECTION_HEADER)((DWORD_PTR)lpImageNTHeaderFile + 4 + sizeof(IMAGE_FILE_HEADER) + lpImageNTHeaderFile->FileHeader.SizeOfOptionalHeader);

    const DWORD_PTR dImageSize = lpImageNTHeaderFile->OptionalHeader.SizeOfImage;
    const DWORD_PTR dOriginalImageBase = lpImageNTHeaderFile->OptionalHeader.ImageBase;

    printf("[+] PE image size: 0x%x\n", (UINT)dImageSize);

    NTSTATUS status;
    PVOID lpAllocAddress = NULL;  // NULL = let OS choose the address
    SIZE_T regionSize = dImageSize;

    status = NtAllocateVirtualMemory(
        NtCurrentProcess(),        // Process handle (use -1 or GetCurrentProcess() for current process)
        &lpAllocAddress,            // Pointer to base address (NULL = OS chooses address)
        0,                          // ZeroBits (0 = no special requirements)
        &regionSize,                // Pointer to region size
        MEM_COMMIT | MEM_RESERVE,   // Allocation type (same flags as VirtualAlloc)
        PAGE_EXECUTE_READWRITE      // Protection flags (same as VirtualAlloc)
    );


    printf("[+] DLL memory allocated at 0x%p\n", (LPVOID)lpAllocAddress);

    // Calculate delta for relocations
    const DWORD_PTR dDeltaAddress = (DWORD_PTR)lpAllocAddress - dOriginalImageBase;

    // Copy PE headers
    RtlCopyMemory(lpAllocAddress, lpPEData, lpImageNTHeaderFile->OptionalHeader.SizeOfHeaders);

    // NOW we can safely access headers in lpAllocAddress
    PIMAGE_NT_HEADERS lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpAllocAddress + lpImageDOSHeader->e_lfanew);
    lpImageNTHeader->OptionalHeader.ImageBase = (DWORD_PTR)lpAllocAddress;  // Update in loaded image

    /* Copy sections */
    printf("[+] Copying sections...\n");
    for (int i = 0; i < lpImageNTHeaderFile->FileHeader.NumberOfSections; i++)
    {
        PIMAGE_SECTION_HEADER lpCurrentSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)lpImageSectionHeaderFile + (i * sizeof(IMAGE_SECTION_HEADER)));

        LPVOID lpSectionDest = (LPVOID)((DWORD_PTR)lpAllocAddress + lpCurrentSectionHeader->VirtualAddress);
        SIZE_T virtualSize = lpCurrentSectionHeader->Misc.VirtualSize;
        SIZE_T rawSize = lpCurrentSectionHeader->SizeOfRawData;

        /* Always zero-initialize the FULL virtual size first */
        if (virtualSize > 0)
        {
            RtlZeroMemory(lpSectionDest, virtualSize);
        }

        /* Then copy raw data if it exists */
        if (rawSize > 0 && lpCurrentSectionHeader->PointerToRawData > 0)
        {
            SIZE_T copySize = (rawSize < virtualSize) ? rawSize : virtualSize;
            RtlCopyMemory(
                lpSectionDest,
                (LPVOID)((DWORD_PTR)lpPEData + lpCurrentSectionHeader->PointerToRawData),
                copySize
            );
            printf("[+] Section %s: Copied 0x%x bytes (VirtualSize=0x%x)\n",
                (LPSTR)lpCurrentSectionHeader->Name, (UINT)copySize, (UINT)virtualSize);
        }
        else
        {
            printf("[+] Section %s: Zero-initialized virtual section (0x%x bytes)\n",
                (LPSTR)lpCurrentSectionHeader->Name, (UINT)virtualSize);
        }
    }


    // Process relocations (using headers from lpAllocAddress now)
    const IMAGE_DATA_DIRECTORY ImageDataReloc = lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if (ImageDataReloc.VirtualAddress != 0 && ImageDataReloc.Size != 0 && dDeltaAddress != 0)
    {
        printf("[+] Processing relocations...\n");

        IMAGE_BASE_RELOCATION* pRelocTable = (IMAGE_BASE_RELOCATION*)((DWORD_PTR)lpAllocAddress + ImageDataReloc.VirtualAddress);

        while (pRelocTable->VirtualAddress != 0)
        {
            if (pRelocTable->SizeOfBlock == 0)
                break;

            DWORD sizeOfTable = (pRelocTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
            WORD* reloc = (WORD*)(pRelocTable + 1);

            for (DWORD i = 0; i < sizeOfTable; ++i)
            {
                int type = reloc[i] >> 12;
                int offset = reloc[i] & 0x0fff;

                if (type == IMAGE_REL_BASED_DIR64)  // 10 for x64
                {
                    DWORD_PTR* addressToChange = (DWORD_PTR*)((DWORD_PTR)lpAllocAddress + pRelocTable->VirtualAddress + offset);
                    *addressToChange += dDeltaAddress;
                }
            }

            pRelocTable = (IMAGE_BASE_RELOCATION*)(((DWORD_PTR)pRelocTable) + pRelocTable->SizeOfBlock);
        }

        printf("[+] Relocations applied.\n");
    }
    else
    {
        printf("[+] No relocations needed.\n");
    }

    // Process imports
    const IMAGE_DATA_DIRECTORY ImageDataImport = lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (ImageDataImport.VirtualAddress != 0 && ImageDataImport.Size != 0)
    {
        printf("[+] Processing imports...\n");

        PIMAGE_IMPORT_DESCRIPTOR lpImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)lpAllocAddress + ImageDataImport.VirtualAddress);

        while (lpImageImportDescriptor->Name != 0)
        {
            LPSTR lpLibraryName = (LPSTR)((DWORD_PTR)lpAllocAddress + lpImageImportDescriptor->Name);
            // const HMODULE hModule = LoadLibraryA(lpLibraryName);

            HMODULE hModule = NULL;
            NTSTATUS status;
            UNICODE_STRING uModuleName;
            WCHAR wLibraryName[MAX_PATH];

            // Convert ANSI library name to wide char
            MultiByteToWideChar(CP_ACP, 0, lpLibraryName, -1, wLibraryName, MAX_PATH);

            // Initialize UNICODE_STRING with the library name
            RtlInitUnicodeString(&uModuleName, wLibraryName);

            // Load the DLL using LdrLoadDll
            status = LdrLoadDll(
                NULL,           // PathToFile (NULL = use default search path)
                0,              // Flags (0 = default behavior)
                &uModuleName,   // ModuleFileName as UNICODE_STRING
                (PHANDLE)&hModule  // Output handle to the loaded module
            );

            if (hModule == NULL)
            {
                printf("[-] Failed to load %s DLL!\n", lpLibraryName);
                return NULL;
            }

            printf("[+] Loading %s\n", lpLibraryName);

            PIMAGE_THUNK_DATA lpThunkData = (PIMAGE_THUNK_DATA)((DWORD_PTR)lpAllocAddress + lpImageImportDescriptor->FirstThunk);
            while (lpThunkData->u1.AddressOfData != 0)
            {
                if (IMAGE_SNAP_BY_ORDINAL(lpThunkData->u1.Ordinal))
                {
                    UINT functionOrdinal = (UINT)IMAGE_ORDINAL(lpThunkData->u1.Ordinal);
                    lpThunkData->u1.Function = (DWORD_PTR)GetProcAddressByOrdinal(hModule, functionOrdinal);
                    printf("[+]\tFunction Ordinal %u\n", functionOrdinal);
                }
                else
                {
                    PIMAGE_IMPORT_BY_NAME lpData = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)lpAllocAddress + lpThunkData->u1.AddressOfData);
                    DWORD_PTR functionAddress = (DWORD_PTR)GetProcAddressByName(hModule, lpData->Name);
                    lpThunkData->u1.Function = functionAddress;
                    printf("[+]\tFunction %s\n", (LPSTR)lpData->Name);
                }
                lpThunkData++;
            }
            lpImageImportDescriptor++;
        }
    }
    else
    {
        printf("[+] No imports found.\n");
    }

    // Process delay-load imports
    if (!ProcessDelayImports(lpAllocAddress))
    {
        printf("[-] Failed to process delay imports!\n");
        return NULL;
    }

    // Process Load Config directory
    if (!ProcessLoadConfig(lpAllocAddress))
    {
        printf("[-] Failed to process Load Config!\n");
        return NULL;
    }

    // Register exception handlers (critical for x64)
    if (!RegisterExceptionHandlers(lpAllocAddress))
    {
        printf("[-] Failed to register exception handlers!\n");
        return NULL;
    }

    // Apply section protections (MUST BE LAST before calling any code)
    if (!ApplySectionProtections(lpAllocAddress))
    {
        printf("[-] Failed to apply section protections!\n");
        return NULL;
    }

    /* ========== TLS CALLBACK HANDLING (x64 ONLY) ========== */
    if (HasCallbacks(lpAllocAddress))
    {
        printf("[+] Processing TLS callbacks...\n");

        PIMAGE_TLS_DIRECTORY64 lpImageTLSDirectory = (PIMAGE_TLS_DIRECTORY64)((DWORD_PTR)lpAllocAddress +
            lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);

        /* Get original ImageBase from file */
        PIMAGE_DOS_HEADER lpImageDOSHeaderFile = (PIMAGE_DOS_HEADER)lpPEData;
        PIMAGE_NT_HEADERS lpImageNTHeaderFile = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpPEData + lpImageDOSHeaderFile->e_lfanew);
        DWORD_PTR originalImageBase = lpImageNTHeaderFile->OptionalHeader.ImageBase;
        DWORD_PTR currentImageBase = (DWORD_PTR)lpAllocAddress;
        DWORD_PTR delta = currentImageBase - originalImageBase;
        DWORD_PTR imageEnd = currentImageBase + lpImageNTHeader->OptionalHeader.SizeOfImage;
        DWORD_PTR originalImageEnd = originalImageBase + lpImageNTHeaderFile->OptionalHeader.SizeOfImage;

        printf("[+] TLS Relocation Info:\n");
        printf("    Original ImageBase: 0x%I64x\n", (ULONGLONG)originalImageBase);
        printf("    Current ImageBase:  0x%I64x\n", (ULONGLONG)currentImageBase);
        printf("    Delta:              0x%I64x\n", (ULONGLONG)delta);

        /* Debug TLS directory */
        printf("[+] AddressOfCallBacks in TLS directory: 0x%I64x\n",
            (ULONGLONG)lpImageTLSDirectory->AddressOfCallBacks);

        /* Validate TLS directory is not all zeros */
        BYTE* tlsBytes = (BYTE*)lpImageTLSDirectory;
        BOOL isAllZeros = TRUE;
        size_t i;
        for (i = 0; i < sizeof(IMAGE_TLS_DIRECTORY64); i++)
        {
            if (tlsBytes[i] != 0)
            {
                isAllZeros = FALSE;
                break;
            }
        }

        if (isAllZeros)
        {
            printf("[!] TLS directory is all zeros. Skipping.\n");
        }
        else if (lpImageTLSDirectory->AddressOfCallBacks == 0)
        {
            printf("[+] No TLS callbacks (AddressOfCallBacks = 0).\n");
        }
        else
        {
            PIMAGE_TLS_CALLBACK* lpCallbackArray = NULL;
            ULONGLONG callbacksAddr = lpImageTLSDirectory->AddressOfCallBacks;

            /* Check if AddressOfCallBacks has already been relocated */
            if (callbacksAddr >= currentImageBase && callbacksAddr < imageEnd)
            {
                /* Already relocated */
                lpCallbackArray = (PIMAGE_TLS_CALLBACK*)callbacksAddr;
                printf("[+]   -> Already relocated, using: 0x%p\n", (LPVOID)lpCallbackArray);
            }
            else if (callbacksAddr >= originalImageBase && callbacksAddr < originalImageEnd)
            {
                /* Not relocated yet */
                lpCallbackArray = (PIMAGE_TLS_CALLBACK*)(callbacksAddr + delta);
                printf("[+]   -> Applying delta: 0x%p\n", (LPVOID)lpCallbackArray);
            }
            else
            {
                printf("[-]   -> Invalid AddressOfCallBacks (not in original or current range)\n");
                lpCallbackArray = NULL;
            }

            /* Validate callback array pointer */
            if (lpCallbackArray == NULL ||
                (DWORD_PTR)lpCallbackArray < currentImageBase ||
                (DWORD_PTR)lpCallbackArray >= imageEnd)
            {
                printf("[-] Callback array pointer invalid or outside image bounds. Skipping TLS.\n");
            }
            else
            {
                printf("[+] TLS Callback array at: 0x%p\n", (LPVOID)lpCallbackArray);

                int callbackCount = 0;
                while (callbackCount < 100)
                {
                    ULONGLONG callbackPtr = (ULONGLONG)lpCallbackArray[callbackCount];
                    PIMAGE_TLS_CALLBACK lpImageCallback;

                    if (callbackPtr == 0)
                    {
                        printf("[+] Found NULL terminator\n");
                        break;
                    }

                    printf("[+] TLS callback #%d pointer: 0x%I64x\n", callbackCount, callbackPtr);

                    /* Check if callback needs relocation */
                    if (callbackPtr >= currentImageBase && callbackPtr < imageEnd)
                    {
                        /* Already relocated */
                        lpImageCallback = (PIMAGE_TLS_CALLBACK)callbackPtr;
                        printf("[+]   -> Using as-is: 0x%p\n", (LPVOID)lpImageCallback);
                    }
                    else if (callbackPtr >= originalImageBase && callbackPtr < originalImageEnd)
                    {
                        /* Needs relocation */
                        lpImageCallback = (PIMAGE_TLS_CALLBACK)(callbackPtr + delta);
                        printf("[+]   -> Relocated to: 0x%p\n", (LPVOID)lpImageCallback);
                    }
                    else
                    {
                        printf("[-]   -> Invalid callback address\n");
                        break;
                    }

                    /* Validate final address */
                    if ((DWORD_PTR)lpImageCallback < currentImageBase ||
                        (DWORD_PTR)lpImageCallback >= imageEnd)
                    {
                        printf("[-] Callback #%d outside bounds!\n", callbackCount);
                        break;
                    }

                    /* Execute callback */
                    printf("[+] Executing callback #%d...\n", callbackCount);
                    lpImageCallback((HINSTANCE)lpAllocAddress, DLL_PROCESS_ATTACH, NULL);
                    printf("[+]   -> SUCCESS\n");

                    callbackCount++;
                }

                if (callbackCount > 0)
                {
                    printf("[+] Executed %d TLS callback(s).\n", callbackCount);
                }
            }
        }
    }


    // Call entry point
    const BOOL bIsDLL = (lpImageNTHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;

    if (bIsDLL)
    {
        dllmain main = (dllmain)((DWORD_PTR)lpAllocAddress + lpImageNTHeader->OptionalHeader.AddressOfEntryPoint);
        const BOOL result = main((HINSTANCE)lpAllocAddress, DLL_PROCESS_ATTACH, NULL);
        if (!result)
        {
            printf("[-] DllMain returned FALSE!\n");
            return NULL;
        }
        printf("[+] DllMain called (DLL_PROCESS_ATTACH).\n");
        printf("[+] DLL loaded successfully.\n");
    }
    else
    {
        typedef int (WINAPI* EXEENTRYPOINT)(VOID);
        EXEENTRYPOINT entryPoint = (EXEENTRYPOINT)((DWORD_PTR)lpAllocAddress + lpImageNTHeader->OptionalHeader.AddressOfEntryPoint);

        printf("[+] EXE loaded successfully.\n");
        printf("[+] Calling entry point at: 0x%p\n", (LPVOID)entryPoint);
        int exitCode = entryPoint();
    

    }
    return (LPVOID)lpAllocAddress;
}