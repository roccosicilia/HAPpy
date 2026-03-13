#include <windows.h>
#include <stdio.h>

void PrintBytes(void* addr, int len)
{
    unsigned char* p = (unsigned char*)addr;

    for (int i = 0; i < len; i++)
        printf("%02X ", p[i]);

    printf("\n");
}

int main()
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");

    if (!ntdll) {
        printf("Failed to load ntdll\n");
        return 1;
    }

    void* NtCreateFile = GetProcAddress(ntdll, "NtCreateFile");

    if (!NtCreateFile) {
        printf("Function not found\n");
        return 1;
    }

    printf("NtCreateFile address: %p\n\n", NtCreateFile);

    printf("First bytes:\n");
    PrintBytes(NtCreateFile, 20);

    unsigned char* p = (unsigned char*)NtCreateFile;

    if (p[0] == 0xE9 || p[0] == 0xFF)
        printf("\nPossible INLINE HOOK detected\n");
    else if (p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1)
        printf("\nLikely original syscall stub\n");
    else
        printf("\nUnknown stub format\n");

    return 0;
}