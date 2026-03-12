/*
 *
 * Programma di test BASELINE - creazione processo normale
 * ========================================================
 *
 * SCOPO
 * =====
 * Questo programma crea un processo PowerShell che esegue
 * il comando "whoami" usando il path normale attraverso
 * le API Win32 standard.
 *
 * Serve come baseline per confrontare la telemetria generata
 * rispetto alla versione con argument spoofing.
 *
 * COSA VEDE LA CALLBACK DELL'EDR
 * ================================
 * Quando questo programma viene eseguito, la callback
 * PsSetCreateProcessNotifyRoutineEx dell'EDR riceve:
 *
 *   ImageFileName: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
 *   CommandLine:   powershell.exe -NoProfile -Command whoami
 *   ParentProcessId: PID di questo programma
 *
 * La command line corrisponde esattamente a quello che
 * il processo eseguirà — nessuna discrepanza.
 *
 * FLUSSO DI ESECUZIONE
 * =====================
 *
 *   test_normal_process.exe
 *       ↓
 *   CreateProcess("powershell.exe -NoProfile -Command whoami")
 *       ↓
 *   kernel crea il processo
 *       ↓
 *   kernel chiama callback EDR
 *       CommandLine loggata: "powershell.exe -NoProfile -Command whoami"
 *       ↓
 *   processo PowerShell esegue
 *       legge PEB → trova "powershell.exe -NoProfile -Command whoami"
 *       esegue whoami
 *       ↓
 *   output: nome utente corrente
 *
 * COSA CERCARE IN ELASTIC/KIBANA
 * ================================
 * Dopo l'esecuzione cerca:
 *
 *   process.name: "powershell.exe" AND process.args: "whoami"
 *
 * Dovresti vedere l'evento con la command line completa
 * e il processo padre correttamente identificato.
 */

#include <windows.h>
#include <stdio.h>

int main() {

    printf("=================================================\n");
    printf(" Test Baseline - Creazione Processo Normale\n");
    printf(" powershell.exe -NoProfile -Command whoami\n");
    printf("=================================================\n\n");

    /*
     * STRUTTURE PER CreateProcess
     * ============================
     * STARTUPINFOA descrive come deve apparire la finestra
     * del processo figlio e dove va il suo I/O.
     *
     * PROCESS_INFORMATION riceve gli handle e i PID del
     * processo e del thread principale appena creati.
     * Questi handle devono essere chiusi dopo l'uso.
     */
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    /*
     * COMMAND LINE DEL PROCESSO FIGLIO
     * ==================================
     * Questa è la command line REALE che:
     * 1. Viene passata al kernel durante la creazione
     * 2. Viene letta dalla callback dell'EDR
     * 3. Viene scritta nel PEB del processo figlio
     * 4. Viene letta ed eseguita da PowerShell
     *
     * Tutti e quattro i passaggi usano la stessa stringa —
     * questo è il comportamento normale e atteso.
     *
     * -NoProfile evita di caricare il profilo PowerShell
     * per velocizzare l'esecuzione nel test.
     * -Command specifica il comando da eseguire direttamente.
     */
    char cmdLine[] = "powershell.exe -NoProfile -Command whoami";

    printf("[*] Creazione processo con command line:\n");
    printf("    %s\n\n", cmdLine);

    /*
     * CREAZIONE DEL PROCESSO
     * =======================
     * CreateProcessA crea il processo figlio.
     *
     * Parametri rilevanti:
     *   lpApplicationName = NULL
     *     Il path dell'eseguibile viene estratto dal primo
     *     token della command line. Windows cerca powershell.exe
     *     nel PATH di sistema.
     *
     *   lpCommandLine = cmdLine
     *     La command line completa inclusi gli argomenti.
     *     Questa stringa viene copiata nel PEB del processo figlio
     *     e letta dalla callback dell'EDR.
     *
     *   dwCreationFlags = 0
     *     Nessun flag speciale — processo creato normalmente
     *     e avviato immediatamente senza sospensione.
     *     Confronta con CREATE_SUSPENDED usato nello spoofing.
     */
    BOOL result = CreateProcessA(
        NULL,       // path estratto dalla command line
        cmdLine,    // command line reale
        NULL,       // security attributes processo default
        NULL,       // security attributes thread default
        FALSE,      // non ereditare handle del padre
        0,          // nessun flag speciale - avvio immediato
        NULL,       // eredita environment variables
        NULL,       // eredita working directory
        &si,        // struttura startup info
        &pi         // riceve handle e PID del nuovo processo
    );

    if (!result) {
        printf("[ERRORE] CreateProcess fallita: %d\n", GetLastError());
        return 1;
    }

    printf("[OK] Processo creato\n");
    printf("[INFO] PID processo figlio: %lu\n", pi.dwProcessId);
    printf("[INFO] PID processo padre (questo): %lu\n\n", GetCurrentProcessId());

    printf("[*] Cosa ha visto la callback dell'EDR:\n");
    printf("    ImageFileName: powershell.exe\n");
    printf("    CommandLine:   %s\n", cmdLine);
    printf("    ParentPID:     %lu\n\n", GetCurrentProcessId());

    printf("[*] Output di whoami:\n");
    printf("--------------------\n");

    /*
     * ATTESA COMPLETAMENTO PROCESSO FIGLIO
     * ======================================
     * WaitForSingleObject aspetta che il processo figlio
     * termini prima di continuare. Il timeout INFINITE
     * significa attesa senza limite di tempo.
     *
     * In un programma reale si userebbe un timeout finito
     * per evitare blocchi indefiniti.
     */
    WaitForSingleObject(pi.hProcess, INFINITE);

    printf("--------------------\n\n");

    /*
     * CLEANUP DEGLI HANDLE
     * =====================
     * Gli handle al processo e al thread principale
     * devono essere chiusi esplicitamente per evitare
     * resource leak. Windows non li chiude automaticamente
     * alla terminazione del processo padre.
     */
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    printf("[OK] Processo terminato normalmente\n\n");
    printf("[VERIFICA IN KIBANA]\n");
    printf("  Cerca: process.name: \"powershell.exe\"\n");
    printf("  Dovresti vedere la command line completa\n");
    printf("  con whoami come argomento\n\n");

    printf("Premi invio per terminare...\n");
    getchar();
    return 0;
}