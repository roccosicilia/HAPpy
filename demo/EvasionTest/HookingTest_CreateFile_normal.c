/*
 * Programma demo per la creazione di un file per analizzare
 * la syscall NtCreateFile a runtime
 */

#include <stdio.h>
#include <windows.h>

int main()
{
    // test output
    printf("Programma di test per creazione di un file");

    // crea un file TXT vuoto
    HANDLE hFile = CreateFileA(
        "C:\\\\Users\\\\Public\\\\test.txt",
        GENERIC_WRITE,          // scrittura
        0,                      // nessuna condivisione
        NULL,                   // security attributes default
        CREATE_ALWAYS,          // crea sempre, sovrascrive se esiste
        FILE_ATTRIBUTE_NORMAL,  // file senza attributi speciali
        NULL                    // nessun template
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Errore creazione file: %d\\n", GetLastError());
        return 1;
    }

    // contenuto del file
    const char* contenuto = "test scrittura";
    DWORD bytesWritten;
    
    WriteFile(
        hFile,
        contenuto,
        (DWORD)strlen(contenuto),
        &bytesWritten,
        NULL
    );

    CloseHandle(hFile);
    getchar();

    return 0;
}