# Manual PE Loader

This project is a modern PE Loader designed for x64 PE (exe or dll) only. 

* Modern Manual Loader is written in C++ and contains classic Windows API.
* Native Manual Loader is written in pure C and contains Nt* procedures with debugging.
* Native Manual Loader GCC is written in pure C and no dependencies. It is used to output shellcode. (Supports debugging)

Evasion & obfuscation will be added later.

## Supports

* Map each sections to their VA.
* Apply relocations
* Fix imports (by ordinal, name or forwarder)
* Fix delay-load imports (by ordinal, name or forwarder)
* Apply load config directory
* Register exception handlers
* Call TLS callbacks

![LD1](https://github.com/arsium/Manual-PE-Loader/blob/main/Loader.png?raw=true)

## Shellcode

* Can be executed with RX attribute
* Can load DLL or PE
* Can link to PEB LDR Data
* Can execute entry point (threaded)

### Options

```c
#define CLASSIC										0x00000000	//default, no option set
#define USE_NT_CREATE_SECTION_FOR_ALLOCATION		0x00000001  //default, use NtAllocateVirtualMemory
#define CALL_ENTRY_POINT							0x00000002  //set to execute EXE entrypoint, DLL is by default executed
#define THREADED_ENTRY_POINT						0x00000004  //set to execute entrypoint with NtCreateThreadex (EXE ONLY)
#define LINK_TO_PEB_LDR								0x00000008  //if set, specify a name as 3rd argument to shellcode	
```

## Example with linked to PEB

![PEBLINKED](https://github.com/arsium/Manual-PE-Loader/blob/main/LinkedToPEB.png?raw=true)
