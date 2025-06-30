#ifndef HELPERS_H
#define HELPERS_H

LDR_DATA_TABLE_ENTRY *GetNextLoadedModule(LDR_DATA_TABLE_ENTRY *CurrentModule);
SIZE_T WCharStringToCharString(PCHAR Destination, PWCHAR Source, SIZE_T MaximumAllowed);
BOOL FileExistsW(LPCWSTR szPath);

int INIT_BOF();
int END_BOF();
void PRINT_OUT(char *format, ...);
void FreeBank();
LPVOID MemAlloc(SIZE_T dwBytes);

#endif