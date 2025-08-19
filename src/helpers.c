#include <windows.h>
#include <stdio.h>

#include "beacon.h"
#include "peb.h"
#include "bofdefs.h"

LDR_DATA_TABLE_ENTRY *GetNextLoadedModule(LDR_DATA_TABLE_ENTRY *CurrentModule)
{
    // Read the PEB address from the GS register at offset 0x60
    PEB *pPeb = (PEB *)__readgsqword(0x60);

    // Get the first module from the loaded module list (typically the executable itself)
    LDR_DATA_TABLE_ENTRY *FirstModule = (LDR_DATA_TABLE_ENTRY *)((PBYTE)pPeb->Ldr->InLoadOrderModuleList.Flink);

    // If this is the first call (CurrentModule is NULL), return the first module
    if (CurrentModule == NULL)
    {
        return FirstModule;
    }

    // Get the next module in the loaded module list
    LDR_DATA_TABLE_ENTRY *NextModule = (LDR_DATA_TABLE_ENTRY *)((PBYTE)CurrentModule->InLoadOrderLinks.Flink);

    // Check if we've reached the end of the circular linked list (back to the first module)
    if (NextModule == FirstModule)
    {
        return NULL;
    }

    // Return the next module in the list
    return NextModule;
}

// Check if a file exists on disk and is not a directory
BOOL FileExistsW(LPCWSTR szPath)
{
    DWORD dwAttrib = KERNEL32$GetFileAttributesW(szPath);

    return (dwAttrib != INVALID_FILE_ATTRIBUTES && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

// BOF output system for buffered string output - credit: RalfHacker
#define OutBlockSize 8192
LPVOID *MEMORY_BANK __attribute__((section(".data"))) = 0;
DWORD BANK_COUNT __attribute__((section(".data"))) = 0;
char *globalOut __attribute__((section(".data"))) = 0;
WORD globalOutSize __attribute__((section(".data"))) = 0;
WORD currentOutSize __attribute__((section(".data"))) = 0;

LPVOID MemAlloc(SIZE_T dwBytes)
{
    LPVOID mem = KERNEL32$VirtualAlloc(NULL, dwBytes, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    MEMORY_BANK[BANK_COUNT++] = mem;
    return mem;
}

void SEND_OUT(BOOL done)
{
    if (currentOutSize > 0)
    {
        BeaconOutput(CALLBACK_OUTPUT, globalOut, currentOutSize);

        for (int i = 0; i < currentOutSize; i++)
            globalOut[i] = 0;

        currentOutSize = 0;
    }
    if (done)
    {
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, globalOut);
    }
}

int INIT_BOF()
{
    globalOut = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), 0, OutBlockSize);
    globalOutSize = OutBlockSize;
    return 1;
}

void PRINT_OUT(char *format, ...)
{
    va_list args;
    va_start(args, format);
    int bufSize = MSVCRT$vsnprintf(NULL, 0, format, args);
    va_end(args);

    if (bufSize == -1)
        return;

    if (bufSize + currentOutSize < globalOutSize)
    {
        MSVCRT$vsnprintf(globalOut + currentOutSize, bufSize, format, args);
        currentOutSize += bufSize;
    }
    else
    {
        SEND_OUT(FALSE);
        if (bufSize <= globalOutSize)
        {
            MSVCRT$vsnprintf(globalOut + currentOutSize, bufSize, format, args);
            currentOutSize += bufSize;
        }
        else
        {
            char *tmpOut = MemAlloc(bufSize);
            MSVCRT$vsnprintf(tmpOut, bufSize, format, args);
            BeaconOutput(CALLBACK_OUTPUT, tmpOut, bufSize);
            //            MemFree(tmpOut);
        }
    }
}

void FreeBank()
{
    for (int i = 0; i < BANK_COUNT; i++)
    {
        KERNEL32$VirtualFree(MEMORY_BANK[i], 0, MEM_RELEASE);
    }
    KERNEL32$VirtualFree(MEMORY_BANK, 0, MEM_RELEASE);
}

void END_BOF()
{
    SEND_OUT(TRUE);
}