#include "windows.h"
#include <stdio.h>
#pragma comment(lib, "delayimp.lib")

void NTAPI __stdcall TLSCallbacks(PVOID DllHandle, DWORD dwReason, PVOID Reserved);

#ifdef _M_IX86
#pragma comment (linker, "/INCLUDE:__tls_used")
#pragma comment (linker, "/INCLUDE:__tls_callback")
#else
#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:_tls_callback")
#endif
EXTERN_C
#ifdef _M_X64
#pragma const_seg (".CRT$XLB")
const
#else
#pragma data_seg (".CRT$XLB")
#endif

PIMAGE_TLS_CALLBACK _tls_callback = TLSCallbacks;
#pragma data_seg ()
#pragma const_seg ()

VOID TLSCallbacks(PVOID DllHandle, DWORD dwReason, PVOID Reserved)
{
	printf("Hello loader from TLS callback !\n");
}

int main(VOID)
{
	printf("Hello loader from exe !\n");
	return 0;
}
