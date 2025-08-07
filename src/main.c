#include <windows.h>

#include "beacon.h"
#include "peb.h"
#include "helpers.c"
#include "bofdefs.h"

// BOF entry point
void go()
{

    INIT_BOF();

    SIZE_T Size = 0;
    int totalHooks = 0;
    CHAR ModulePath[MAX_PATH] = {0};
    char *FalsePositives[] = {"NtGetTickCount", "NtQuerySystemTime", "NtdllDefWindowProc_A", "NtdllDefWindowProc_W", "NtdllDialogWndProc_A", "NtdllDialogWndProc_W", "\0"};

    // Loop through all the loaded modules
    for (LDR_DATA_TABLE_ENTRY *currentModule = GetNextLoadedModule(NULL); currentModule != NULL; currentModule = GetNextLoadedModule(currentModule))
    {

        /* These safety checks validate module integrity to prevent crashes when parsing potentially corrupted or invalid modules */

        // Convert module name to ANSI
        Size = WCharStringToCharString(ModulePath, currentModule->FullDllName.Buffer, currentModule->FullDllName.Length);

        // Extract filename from path
        char *LastBackSlash = MSVCRT$strrchr(ModulePath, '\\');
        char FileName[MAX_PATH];

        // Skip unloaded modules
        if (currentModule->BaseDllName.Buffer == NULL)
        {
            continue;
        }

        // Skip non-DLL modules
        char *FileExtension = MSVCRT$strrchr(ModulePath, '.');
        if (MSVCRT$_stricmp(FileExtension, ".dll") != 0)
        {
            continue;
        }

        // Skip modules not on disk
        if (!FileExistsW(currentModule->FullDllName.Buffer))
        {
            continue;
        }

        // Extract and display the module filename
        if (LastBackSlash != NULL && Size < MAX_PATH)
        {
            MSVCRT$strncpy(FileName, LastBackSlash + 1, MAX_PATH - 1);
            FileName[MAX_PATH - 1] = '\0';
            PRINT_OUT("[+] Module %s\n", FileName);
        }
        else
        {
            PRINT_OUT("[+] Module %s\n", ModulePath);
        }

        // Verify the DOS header of the DLL
        PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)currentModule->DllBase;
        if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        {
            PRINT_OUT("[-] Not a valid DOS header\n");
            continue;
        }

        // Verify the NT Header of the DLL
        PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)(pDosHdr->e_lfanew + currentModule->DllBase);
        if (pNtHdr->Signature != IMAGE_NT_SIGNATURE)
        {
            PRINT_OUT("[-] Not a valid NT header\n");
            continue;
        }

        // Get the optional header
        IMAGE_OPTIONAL_HEADER ImgOptHdr = pNtHdr->OptionalHeader;
        if (ImgOptHdr.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
        {
            PRINT_OUT("[-] Not a valid optional header\n");
            continue;
        }

        /* Safety checks ends here */

        // Get export directory and arrays
        PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(currentModule->DllBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

        PDWORD FunctionNameArray = (PDWORD)(currentModule->DllBase + pImgExportDir->AddressOfNames);
        PDWORD FunctionAddressArray = (PDWORD)(currentModule->DllBase + pImgExportDir->AddressOfFunctions);
        PWORD FunctionOrdinalArray = (PWORD)(currentModule->DllBase + pImgExportDir->AddressOfNameOrdinals);

        // Check each exported function
        for (DWORD i = 0; i < pImgExportDir->NumberOfNames; i++)
        {
            char *pFunctionName = (char *)(currentModule->DllBase + FunctionNameArray[i]);
            PVOID pFunctionAddress = (PVOID)(currentModule->DllBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

            // Skip Zw functions
            if (MSVCRT$strncmp(pFunctionName, (char *)"Zw", 2) == 0)
            {
                continue;
            }

            // Check for hooked syscalls in ntdll
            if (MSVCRT$strncmp(pFunctionName, (char *)"Nt", 2) == 0)
            {
                // Skip known false positives
                BOOL isFalsePositive = FALSE;
                for (int i = 0; i < (sizeof(FalsePositives) / sizeof(FalsePositives[0])); i++)
                {
                    if (MSVCRT$_stricmp(pFunctionName, FalsePositives[i]) == 0)
                    {
                        isFalsePositive = TRUE;
                    }
                }

                if (isFalsePositive)
                {
                    continue;
                }

                // Check syscall stub pattern
                if (MSVCRT$memcmp(pFunctionAddress, "\x4C\x8B\xd1\xb8", 4) != 0 && MSVCRT$_stricmp(FileName, "ntdll.dll") == 0)
                {
                    PRINT_OUT("\t[+] Hooked syscall %s\n", pFunctionName);
                    totalHooks++;
                    continue;
                }
            }

            // Check for inline hooks
            if (MSVCRT$memcmp(pFunctionAddress, "\xE9", 1) == 0)
            {
                int relOffset = *(int *)((BYTE *)pFunctionAddress + 1);
                BYTE *jumpTarget = (BYTE *)pFunctionAddress + 5 + relOffset;

                // Check if jump target is outside module bounds
                if (jumpTarget < (BYTE *)currentModule->DllBase || jumpTarget >= ((BYTE *)currentModule->DllBase + ImgOptHdr.SizeOfImage))
                {
                    PRINT_OUT("\t[+] Hooked function %s\n", pFunctionName);
                    totalHooks++;
                }
            }
        }
    }

    PRINT_OUT("[+] Hooks found: %d\n", totalHooks);
    FreeBank();
    END_BOF();
}