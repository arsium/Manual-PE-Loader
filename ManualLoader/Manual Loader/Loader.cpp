#include "Loader.h"

/**
 *	Function to retrieve the PE file content.
 *	\param lpFilePath : path of the PE file.
 *	\return : address of the content in the explorer memory.
 */
HANDLE MemoryLoader::GetFileContent(const LPSTR lpFilePath)
{
	const HANDLE hFile = CreateFileA(lpFilePath, GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("[-] An error occured when trying to open the PE file !\n");
		CloseHandle(hFile);
		return nullptr;
	}

	const DWORD_PTR dFileSize = GetFileSize(hFile, nullptr);
	if (dFileSize == INVALID_FILE_SIZE)
	{
		printf("[-] An error occured when trying to get the PE file size !\n");
		CloseHandle(hFile);
		return nullptr;
	}

	const HANDLE hFileContent = HeapAlloc(GetProcessHeap(), 0, dFileSize);
	if (hFileContent == INVALID_HANDLE_VALUE)
	{
		printf("[-] An error occured when trying to allocate memory for the PE file content !\n");
		CloseHandle(hFile);
		CloseHandle(hFileContent);
		return nullptr;
	}

	const BOOL bFileRead = ReadFile(hFile, hFileContent, dFileSize, nullptr, nullptr);
	if (!bFileRead)
	{
		printf("[-] An error occured when trying to read the PE file content !\n");

		CloseHandle(hFile);
		if (hFileContent != nullptr)
			CloseHandle(hFileContent);

		return nullptr;
	}

	CloseHandle(hFile);
	return hFileContent;
}

/**
 *	Function to check if the image is a valid PE file.
 *	\param lpImage : PE image data.
 *	\return : TRUE if the image is a valid PE else no.
 */
BOOL MemoryLoader::IsValidPE(const LPVOID lpImage)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	if (lpImageNTHeader->Signature == IMAGE_NT_SIGNATURE)
		return TRUE;

	return FALSE;
}

/**
 *	Function to identify if the PE file is a DLL.
 *	\param hDLLData : DLL image.
 *	\return : true if the image is a DLL else false.
 */
BOOL MemoryLoader::IsDLL(const LPVOID hDLLData)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)(hDLLData);
	const auto lpImageNtHeader = (PIMAGE_NT_HEADERS32)((DWORD_PTR)hDLLData + lpImageDOSHeader->e_lfanew);

	if (lpImageNtHeader->FileHeader.Characteristics & IMAGE_FILE_DLL)
		return TRUE;

	return FALSE;
}

/**
 *	Function to check if the image has the same arch.
 *	\param lpImage : PE image data.
 *	\return : TRUE if the image has the arch else FALSE.
 */
BOOL MemoryLoader::IsValidArch(const LPVOID lpImage)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	if (lpImageNTHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR_MAGIC)
		return TRUE;

	return FALSE;
}

/**
 *	Function to retrieve the size of the PE image.
 *	\param lpImage : PE image data.
 *	\return : the size of the PE image.
 */
DWORD_PTR MemoryLoader::GetImageSize(const LPVOID lpImage)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	return lpImageNTHeader->OptionalHeader.SizeOfImage;
}

BOOL MemoryLoader::HasCallbacks(const LPVOID lpImage)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImage + lpImageDOSHeader->e_lfanew);
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
BOOL MemoryLoader::ProcessDelayImports(const LPVOID lpImage)
{
    const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
    const auto lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImage + lpImageDOSHeader->e_lfanew);

    // Check if delay import directory exists
    const IMAGE_DATA_DIRECTORY ImageDataDelayImport = lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    if (ImageDataDelayImport.VirtualAddress == 0 || ImageDataDelayImport.Size == 0)
    {
        printf("[+] No delay-load imports found.\n");
        return TRUE;
    }

    printf("[+] Processing delay-load imports...\n");

    auto lpDelayImportDescriptor = (PIMAGE_DELAYLOAD_DESCRIPTOR)((DWORD_PTR)lpImage + ImageDataDelayImport.VirtualAddress);

    // Iterate through delay import descriptors (terminated by null entry)
    while (lpDelayImportDescriptor->DllNameRVA != 0)
    {
        const auto lpLibraryName = (LPSTR)((DWORD_PTR)lpImage + lpDelayImportDescriptor->DllNameRVA);
        const HMODULE hModule = LoadLibraryA(lpLibraryName);

        if (hModule == nullptr)
        {
            printf("[-] Failed to load delay-imported DLL: %s\n", lpLibraryName);
            return FALSE;
        }

        printf("[+] Delay-loading %s\n", lpLibraryName);

        // Process Import Name Table (INT) and Import Address Table (IAT)
        auto lpINT = (PIMAGE_THUNK_DATA)((DWORD_PTR)lpImage + lpDelayImportDescriptor->ImportNameTableRVA);
        auto lpIAT = (PIMAGE_THUNK_DATA)((DWORD_PTR)lpImage + lpDelayImportDescriptor->ImportAddressTableRVA);

        // Resolve all delay-imported functions
        while (lpINT->u1.AddressOfData != 0)
        {
            if (IMAGE_SNAP_BY_ORDINAL(lpINT->u1.Ordinal))
            {
                // Import by ordinal
                const auto functionOrdinal = (UINT)IMAGE_ORDINAL(lpINT->u1.Ordinal);
                lpIAT->u1.Function = (DWORD_PTR)GetProcAddress(hModule, MAKEINTRESOURCEA(functionOrdinal));
                printf("[+]\tDelay Function Ordinal #%u\n", functionOrdinal);
            }
            else
            {
                // Import by name
                const auto lpData = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)lpImage + lpINT->u1.AddressOfData);
                const auto functionAddress = (DWORD_PTR)GetProcAddress(hModule, lpData->Name);
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
BOOL MemoryLoader::ProcessLoadConfig(const LPVOID lpImage)
{
    const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
    const auto lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImage + lpImageDOSHeader->e_lfanew);

    // Check if Load Config directory exists
    const IMAGE_DATA_DIRECTORY ImageDataLoadConfig = lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
    if (ImageDataLoadConfig.VirtualAddress == 0 || ImageDataLoadConfig.Size == 0)
    {
        printf("[+] No Load Config directory found.\n");
        return TRUE;
    }

    printf("[+] Processing Load Config directory...\n");

    const auto lpLoadConfig = (PIMAGE_LOAD_CONFIG_DIRECTORY64)((DWORD_PTR)lpImage + ImageDataLoadConfig.VirtualAddress);

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
BOOL MemoryLoader::RegisterExceptionHandlers(const LPVOID lpImage)
{
    const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
    const auto lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImage + lpImageDOSHeader->e_lfanew);

    // x64: Register exception handlers using .pdata section
    const IMAGE_DATA_DIRECTORY ImageDataException = lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (ImageDataException.VirtualAddress == 0 || ImageDataException.Size == 0)
    {
        printf("[+] No exception handlers to register.\n");
        return TRUE;
    }

    printf("[+] Registering exception handlers...\n");

    const auto lpRuntimeFunction = (PRUNTIME_FUNCTION)((DWORD_PTR)lpImage + ImageDataException.VirtualAddress);
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
BOOL MemoryLoader::UnregisterExceptionHandlers(const LPVOID lpImage)
{
    const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
    const auto lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImage + lpImageDOSHeader->e_lfanew);

    const IMAGE_DATA_DIRECTORY ImageDataException = lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (ImageDataException.VirtualAddress == 0 || ImageDataException.Size == 0)
    {
        return TRUE;
    }

    const auto lpRuntimeFunction = (PRUNTIME_FUNCTION)((DWORD_PTR)lpImage + ImageDataException.VirtualAddress);

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
BOOL MemoryLoader::ApplySectionProtections(const LPVOID lpImage)
{
    const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
    const auto lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImage + lpImageDOSHeader->e_lfanew);
    const auto lpImageSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)lpImageNTHeader + 4 + sizeof(IMAGE_FILE_HEADER) + lpImageNTHeader->FileHeader.SizeOfOptionalHeader);

    printf("[+] Applying section memory protections...\n");

    for (int i = 0; i < lpImageNTHeader->FileHeader.NumberOfSections; i++)
    {
        const auto lpCurrentSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)lpImageSectionHeader + (i * sizeof(IMAGE_SECTION_HEADER)));

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
        if (!VirtualProtect(lpSectionAddress, stSectionSize, dwProtection, &dwOldProtection))
        {
            printf("[-] Failed to set protection for section %s (Error: %lu)\n",
                (LPSTR)lpCurrentSectionHeader->Name, GetLastError());
            return FALSE;
        }

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
 * @return : address of the function if success else nullptr
 */
LPVOID MemoryLoader::GetFunctionAddressEx(const LPVOID lpModule, const LPSTR lpFunctionName)
{
    const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpModule;
    const auto lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);

    if (lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
        return nullptr;

    const auto lpImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)lpModule + lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    const DWORD_PTR dNumberOfNames = lpImageExportDirectory->NumberOfNames;

    // Get export directory bounds for forwarded export detection
    const DWORD_PTR dwExportDirStart = lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    const DWORD_PTR dwExportDirEnd = dwExportDirStart + lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    for (int i = 0; i < (int)dNumberOfNames; i++)
    {
        const auto lpCurrentFunctionName = (LPSTR)(((DWORD*)(lpImageExportDirectory->AddressOfNames + (DWORD_PTR)lpModule))[i] + (DWORD_PTR)lpModule);
        const auto lpCurrentOridnal = ((WORD*)(lpImageExportDirectory->AddressOfNameOrdinals + (DWORD_PTR)lpModule))[i];
        const auto addRVA = ((DWORD*)((DWORD_PTR)lpModule + lpImageExportDirectory->AddressOfFunctions))[lpCurrentOridnal];

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
                if (lpDot != nullptr)
                {
                    size_t dllNameLen = lpDot - lpForwardString;
                    strncpy_s(szForwardDll, sizeof(szForwardDll), lpForwardString, dllNameLen);
                    strcat_s(szForwardDll, sizeof(szForwardDll), ".dll");
                    strcpy_s(szForwardFunction, sizeof(szForwardFunction), lpDot + 1);

                    // Load the forwarded DLL
                    HMODULE hForwardModule = LoadLibraryA(szForwardDll);
                    if (hForwardModule != nullptr)
                    {
                        // Check if forwarding to ordinal (starts with '#')
                        if (szForwardFunction[0] == '#')
                        {
                            WORD ordinal = (WORD)atoi(szForwardFunction + 1);
                            return (LPVOID)GetProcAddress(hForwardModule, MAKEINTRESOURCEA(ordinal));
                        }
                        else
                        {
                            return (LPVOID)GetProcAddress(hForwardModule, szForwardFunction);
                        }
                    }
                }

                printf("[-] Failed to resolve forwarded export: %s\n", lpForwardString);
                return nullptr;
            }

            // Normal export
            return (LPVOID)((DWORD_PTR)lpModule + addRVA);
        }
    }

    return nullptr;
}

/**
 *	Function to load a DLL in memory
 *	\param lpDLLPath : path of the DLL file.
 *	\return : DLL address if success else nullptr.
 */
LPVOID MemoryLoader::LoadDLL(const LPSTR lpDLLPath)
{
    printf("[+] DLL LOADER\n");

    const HANDLE hDLLData = GetFileContent(lpDLLPath);
    if (hDLLData == INVALID_HANDLE_VALUE || hDLLData == nullptr)
    {
        printf("[-] An error occurred when trying to get DLL's data!\n");
        return nullptr;
    }

    printf("[+] DLL's data at 0x%p\n", (LPVOID)hDLLData);

    if (!IsValidPE(hDLLData))
    {
        printf("[-] The DLL is not a valid PE file!\n");
        if (hDLLData != nullptr)
            HeapFree(GetProcessHeap(), 0, hDLLData);
        return nullptr;
    }

    printf("[+] The PE image is valid.\n");

    if (!IsValidArch(hDLLData))
    {
        printf("[-] The architectures are not compatible!\n");
        return nullptr;
    }

    printf("[+] The architectures are compatible.\n");

    // Parse file buffer headers
    const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)hDLLData;
    const auto lpImageNTHeaderFile = (PIMAGE_NT_HEADERS)((DWORD_PTR)hDLLData + lpImageDOSHeader->e_lfanew);
    const auto lpImageSectionHeaderFile = (PIMAGE_SECTION_HEADER)((DWORD_PTR)lpImageNTHeaderFile + 4 + sizeof(IMAGE_FILE_HEADER) + lpImageNTHeaderFile->FileHeader.SizeOfOptionalHeader);

    const DWORD_PTR dImageSize = lpImageNTHeaderFile->OptionalHeader.SizeOfImage;
    const DWORD_PTR dOriginalImageBase = lpImageNTHeaderFile->OptionalHeader.ImageBase;

    printf("[+] PE image size: 0x%x\n", (UINT)dImageSize);

    // Allocate memory for PE
    const LPVOID lpAllocAddress = VirtualAlloc(nullptr, dImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (lpAllocAddress == nullptr)
    {
        printf("[-] An error occurred when trying to allocate the DLL's memory!\n");
        return nullptr;
    }

    printf("[+] DLL memory allocated at 0x%p\n", (LPVOID)lpAllocAddress);

    // Calculate delta for relocations
    const DWORD_PTR dDeltaAddress = (DWORD_PTR)lpAllocAddress - dOriginalImageBase;

    // Copy PE headers
    RtlCopyMemory(lpAllocAddress, hDLLData, lpImageNTHeaderFile->OptionalHeader.SizeOfHeaders);

    // NOW we can safely access headers in lpAllocAddress
    const auto lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpAllocAddress + lpImageDOSHeader->e_lfanew);
    lpImageNTHeader->OptionalHeader.ImageBase = (DWORD_PTR)lpAllocAddress;  // Update in loaded image

    // Copy sections
    printf("[+] Copying sections...\n");
    for (int i = 0; i < lpImageNTHeaderFile->FileHeader.NumberOfSections; i++)
    {
        const auto lpCurrentSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)lpImageSectionHeaderFile + (i * sizeof(IMAGE_SECTION_HEADER)));

        if (lpCurrentSectionHeader->SizeOfRawData > 0)
        {
            RtlCopyMemory(
                (LPVOID)((DWORD_PTR)lpAllocAddress + lpCurrentSectionHeader->VirtualAddress),
                (LPVOID)((DWORD_PTR)hDLLData + lpCurrentSectionHeader->PointerToRawData),
                lpCurrentSectionHeader->SizeOfRawData
            );
        }

        printf("[+] Section %s written.\n", (LPSTR)lpCurrentSectionHeader->Name);
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

        auto lpImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)lpAllocAddress + ImageDataImport.VirtualAddress);

        while (lpImageImportDescriptor->Name != 0)
        {
            const auto lpLibraryName = (LPSTR)((DWORD_PTR)lpAllocAddress + lpImageImportDescriptor->Name);
            const HMODULE hModule = LoadLibraryA(lpLibraryName);
            if (hModule == nullptr)
            {
                printf("[-] Failed to load %s DLL!\n", lpLibraryName);
                return nullptr;
            }

            printf("[+] Loading %s\n", lpLibraryName);

            auto lpThunkData = (PIMAGE_THUNK_DATA)((DWORD_PTR)lpAllocAddress + lpImageImportDescriptor->FirstThunk);
            while (lpThunkData->u1.AddressOfData != 0)
            {
                if (IMAGE_SNAP_BY_ORDINAL(lpThunkData->u1.Ordinal))
                {
                    const auto functionOrdinal = (UINT)IMAGE_ORDINAL(lpThunkData->u1.Ordinal);
                    lpThunkData->u1.Function = (DWORD_PTR)GetProcAddressByOrdinal(hModule,functionOrdinal);
                    printf("[+]\tFunction Ordinal %u\n", functionOrdinal);
                }
                else
                {
                    const auto lpData = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)lpAllocAddress + lpThunkData->u1.AddressOfData);
                    const auto functionAddress = (DWORD_PTR)GetProcAddressByName(hModule, lpData->Name);
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
        return nullptr;
    }

    // Process Load Config directory
    if (!ProcessLoadConfig(lpAllocAddress))
    {
        printf("[-] Failed to process Load Config!\n");
        return nullptr;
    }

    // Register exception handlers (critical for x64)
    if (!RegisterExceptionHandlers(lpAllocAddress))
    {
        printf("[-] Failed to register exception handlers!\n");
        return nullptr;
    }

    // Apply section protections (MUST BE LAST before calling any code)
    if (!ApplySectionProtections(lpAllocAddress))
    {
        printf("[-] Failed to apply section protections!\n");
        return nullptr;
    }

    // TLS Callbacks
    if (HasCallbacks(lpAllocAddress))  // Use lpAllocAddress, not hDLLData
    {
        const auto lpImageTLSDirectory = (PIMAGE_TLS_DIRECTORY)((DWORD_PTR)lpAllocAddress + lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        auto lpCallbackArray = (PIMAGE_TLS_CALLBACK*)lpImageTLSDirectory->AddressOfCallBacks;

        while (*lpCallbackArray != nullptr)
        {
            const auto lpImageCallback = *lpCallbackArray;
            lpImageCallback(lpAllocAddress, DLL_PROCESS_ATTACH, nullptr);
            lpCallbackArray++;
        }
        printf("[+] TLS callbacks executed (DLL_PROCESS_ATTACH).\n");
    }

    // Call entry point
    const BOOL bIsDLL = (lpImageNTHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;

    if (bIsDLL)
    {
        const auto main = (dllmain)((DWORD_PTR)lpAllocAddress + lpImageNTHeader->OptionalHeader.AddressOfEntryPoint);
        const BOOL result = main((HINSTANCE)lpAllocAddress, DLL_PROCESS_ATTACH, nullptr);
        if (!result)
        {
            printf("[-] DllMain returned FALSE!\n");
            return nullptr;
        }
        printf("[+] DllMain called (DLL_PROCESS_ATTACH).\n");
        printf("[+] DLL loaded successfully.\n");
    }
    else
    {
        printf("[+] EXE loaded successfully (entry point NOT executed).\n");
        printf("[!] Entry point: 0x%p\n",
            (LPVOID)((DWORD_PTR)lpAllocAddress + lpImageNTHeader->OptionalHeader.AddressOfEntryPoint));
    }

    HeapFree(GetProcessHeap(), 0, hDLLData);
    return (LPVOID)lpAllocAddress;
}

/**
 * Custom GetProcAddress - Works on both system and manually-loaded modules
 * @param hModule : Module handle (from LoadLibrary or your LoadDLL)
 * @param lpFunctionName : Name of the function to find
 * @return : Function address if success, nullptr otherwise
 */
LPVOID MemoryLoader::GetProcAddressByName(const HMODULE hModule, const LPSTR lpFunctionName)
{
    if (hModule == nullptr || lpFunctionName == nullptr)
        return nullptr;

    const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)hModule;

    // Validate DOS header
    if (lpImageDOSHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return nullptr;

    const auto lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)hModule + lpImageDOSHeader->e_lfanew);

    // Validate NT header
    if (lpImageNTHeader->Signature != IMAGE_NT_SIGNATURE)
        return nullptr;

    // Check if export directory exists
    if (lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
        return nullptr;

    const auto lpImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(
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
                if (lpDot != nullptr)
                {
                    size_t dllNameLen = lpDot - lpForwardString;
                    strncpy_s(szForwardDll, sizeof(szForwardDll), lpForwardString, dllNameLen);
                    strcat_s(szForwardDll, sizeof(szForwardDll), ".dll");
                    strcpy_s(szForwardFunction, sizeof(szForwardFunction), lpDot + 1);

                    // Load the forwarded DLL
                    HMODULE hForwardModule = LoadLibraryA(szForwardDll);
                    if (hForwardModule != nullptr)
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

                return nullptr;  // Failed to resolve forward
            }

            // Normal export - return function address
            return (LPVOID)((DWORD_PTR)hModule + functionRVA);
        }
    }

    return nullptr;  // Function not found
}

/**
 * Custom GetProcAddress by ordinal - Works on both system and manually-loaded modules
 * @param hModule : Module handle (from LoadLibrary or your LoadDLL)
 * @param ordinal : Ordinal of the function to find
 * @return : Function address if success, nullptr otherwise
 */
LPVOID MemoryLoader::GetProcAddressByOrdinal(const HMODULE hModule, const WORD ordinal)
{
    if (hModule == nullptr)
        return nullptr;

    const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)hModule;

    // Validate DOS header
    if (lpImageDOSHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return nullptr;

    const auto lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)hModule + lpImageDOSHeader->e_lfanew);

    // Validate NT header
    if (lpImageNTHeader->Signature != IMAGE_NT_SIGNATURE)
        return nullptr;

    // Check if export directory exists
    if (lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
        return nullptr;

    const auto lpImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(
        (DWORD_PTR)hModule + lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
        );

    // Calculate actual ordinal index (ordinal - base)
    const DWORD ordinalIndex = ordinal - lpImageExportDirectory->Base;

    // Validate ordinal is in range
    if (ordinalIndex >= lpImageExportDirectory->NumberOfFunctions)
        return nullptr;

    // Get function RVA from AddressOfFunctions table
    const DWORD* lpAddressOfFunctions = (DWORD*)((DWORD_PTR)hModule + lpImageExportDirectory->AddressOfFunctions);
    const DWORD functionRVA = lpAddressOfFunctions[ordinalIndex];

    if (functionRVA == 0)
        return nullptr;  // Ordinal slot is empty

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
        if (lpDot != nullptr)
        {
            size_t dllNameLen = lpDot - lpForwardString;
            strncpy_s(szForwardDll, sizeof(szForwardDll), lpForwardString, dllNameLen);
            strcat_s(szForwardDll, sizeof(szForwardDll), ".dll");
            strcpy_s(szForwardFunction, sizeof(szForwardFunction), lpDot + 1);

            HMODULE hForwardModule = LoadLibraryA(szForwardDll);
            if (hForwardModule != nullptr)
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

        return nullptr;
    }

    // Normal export - return function address
    return (LPVOID)((DWORD_PTR)hModule + functionRVA);
}


/**
 *	Function to find function in the DLL.
 *	\param lpModule : address of the DLL.
 *	\param lpFunctionName : name of the function.
 *	\return : address of the function if success else nullptr.
 */
LPVOID MemoryLoader::GetFunctionAddress(const LPVOID lpModule, const LPSTR lpFunctionName)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpModule;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	if (lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
		return nullptr;

	const auto lpImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)lpModule + lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	const DWORD_PTR dNumberOfNames = lpImageExportDirectory->NumberOfNames;

	for (int i = 0; i < (int)dNumberOfNames; i++)
	{
		const auto lpCurrentFunctionName = (LPSTR)(((DWORD*)(lpImageExportDirectory->AddressOfNames + (DWORD_PTR)lpModule))[i] + (DWORD_PTR)lpModule);
		const auto lpCurrentOridnal = ((WORD*)(lpImageExportDirectory->AddressOfNameOrdinals + (DWORD_PTR)lpModule))[i];
		const auto addRVA = ((DWORD*)((DWORD_PTR)lpModule + lpImageExportDirectory->AddressOfFunctions))[lpCurrentOridnal];
		if (strcmp(lpCurrentFunctionName, lpFunctionName) == 0)
			return (LPVOID)((DWORD_PTR)lpModule + addRVA);
	}

	return nullptr;
}

/**
 *	Function to retrieve function address by using ordinal.
 *	\param lpModule : address of the DLL.
 *	\param dOrdinal : ordinal of the function.
 *	\return : the address of the function.
 */
LPVOID MemoryLoader::GetFunctionAddressByOrdinal(const LPVOID lpModule, const DWORD_PTR dOrdinal)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpModule;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	if (lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
		return nullptr;

	const auto lpImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)lpModule + lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	const auto addRVA = ((DWORD*)((DWORD_PTR)lpModule + lpImageExportDirectory->AddressOfFunctions))[dOrdinal];
	return (LPVOID)((DWORD_PTR)lpModule + addRVA);
}

/**
 *	Function to free the DLL.
 *	\param lpModule : address of the loaded DLL.
 *	\return : FALSE if it failed else TRUE.
 */
BOOL MemoryLoader::FreeDLL(const LPVOID lpModule)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpModule;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);

	if (HasCallbacks(lpModule))
	{
		const auto lpImageTLSDirectory = (PIMAGE_TLS_DIRECTORY)((DWORD_PTR)lpModule + lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto lpCallbackArray = (PIMAGE_TLS_CALLBACK*)lpImageTLSDirectory->AddressOfCallBacks;

		while (*lpCallbackArray != nullptr)
		{
			const auto lpImageCallback = *lpCallbackArray;
			lpImageCallback(lpModule, DLL_PROCESS_DETACH, nullptr);
			lpCallbackArray++;
		}

		printf("[+] TLS callbacks executed (DLL_PROCESS_DETACH).\n");
	}

	const auto main = (dllmain)((DWORD_PTR)lpModule + lpImageNTHeader->OptionalHeader.AddressOfEntryPoint);
	const BOOL result = main((HINSTANCE)lpModule, DLL_PROCESS_DETACH, nullptr);

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
