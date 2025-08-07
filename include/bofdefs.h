#pragma once
#include <windows.h>

// KERNEL32
WINBASEAPI DWORD WINAPI KERNEL32$GetFileAttributesW(LPCWSTR lpFileName);
WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
WINBASEAPI LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI int WINAPI KERNEL32$VirtualFree (LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap(VOID);
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);

// MSVCRT
WINBASEAPI int __cdecl MSVCRT$vsnprintf(char * __restrict__ d,size_t n,const char * __restrict__ format,va_list arg);
WINBASEAPI char* __cdecl MSVCRT$strrchr(const char *str, int c);
WINBASEAPI char* __cdecl MSVCRT$strncpy(char * destination, const char * source, size_t num);
WINBASEAPI int __cdecl MSVCRT$_stricmp(const char *string1,const char *string2);
WINBASEAPI int __cdecl MSVCRT$strncmp(const char *_Str1,const char *_Str2,size_t _MaxCount);
WINBASEAPI int __cdecl MSVCRT$memcmp(const void *_Buf1,const void *_Buf2,size_t _Size);