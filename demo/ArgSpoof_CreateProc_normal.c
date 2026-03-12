#include <windows.h>  // API Win32 (CreatePipe, CreateProcess, ecc.)
#include <stdio.h>    // printf, I/O standard

int main() {

    // Handle per i due capi della pipe: lettura e scrittura
    HANDLE readPipe, writePipe;

    // Attributi di sicurezza: dimensione struttura, no descriptor esplicito,
    // TRUE = gli handle sono ereditabili dai processi figli
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };

    // Crea una pipe anonima bidirezionale (unidirezionale in pratica:
    // si scrive su writePipe, si legge da readPipe)
    if (!CreatePipe(&readPipe, &writePipe, &sa, 0)) {
        printf("CreatePipe failed: %lu\n", GetLastError());
        return 1;
    }

    // Rimuove il flag di ereditabilità da readPipe:
    // il processo figlio NON deve ereditare il capo di lettura,
    // altrimenti la pipe non si chiuderebbe mai correttamente
    SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);

    // Struttura che descrive la finestra/console del processo figlio
    STARTUPINFOA si = {0};

    // Struttura che riceverà i handle e gli ID del processo/thread figlio
    PROCESS_INFORMATION pi = {0};

    si.cb = sizeof(si);  // Dimensione obbligatoria della struttura

    // Indica che vogliamo ridefinire stdin/stdout/stderr del figlio
    si.dwFlags = STARTF_USESTDHANDLES;

    // Reindirizza stdout del figlio verso la pipe (capo di scrittura)
    si.hStdOutput = writePipe;

    // Reindirizza anche stderr sulla stessa pipe (cattura errori + output)
    si.hStdError  = writePipe;

    // Il figlio eredita lo stdin del processo corrente (la tastiera)
    si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);

    // Comando da eseguire: PowerShell senza profilo utente, esegue "whoami"
    char cmd[] = "powershell.exe -NoProfile -Command whoami";

    if (!CreateProcessA(
        NULL,       // Nome eseguibile (NULL = ricavato da cmd)
        cmd,        // Riga di comando completa
        NULL,       // Attributi di sicurezza del processo (default)
        NULL,       // Attributi di sicurezza del thread (default)
        TRUE,       // Eredita gli handle aperti (necessario per la pipe)
        CREATE_NO_WINDOW,  // Non aprire nessuna finestra/console visibile
        NULL,       // Variabili d'ambiente (NULL = eredita dal padre)
        NULL,       // Directory di lavoro (NULL = stessa del padre)
        &si,        // STARTUPINFO con i reindirizzamenti configurati sopra
        &pi))       // Riceve handle e ID del nuovo processo
    {
        printf("CreateProcess failed: %lu\n", GetLastError());
        return 1;
    }

    // Chiude il capo di scrittura nel processo padre:
    // ora solo il figlio scrive sulla pipe; quando il figlio termina
    // e chiude il suo writePipe, ReadFile nel padre riceverà EOF
    CloseHandle(writePipe);

    char buffer[4096];  // Buffer temporaneo per i dati letti
    DWORD bytesRead;    // Numero di byte effettivamente letti

    printf("Output:\n\n");

    // Legge in loop dall'output del processo figlio finché
    // non arriva EOF (figlio terminato + writePipe chiuso) o errore
    while (ReadFile(readPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
        buffer[bytesRead] = 0;  // Terminatore stringa per printf sicuro
        printf("%s", buffer);
    }

    // Attende che il processo figlio finisca prima di proseguire
    WaitForSingleObject(pi.hProcess, INFINITE);

    // Pulizia: chiude tutti gli handle aperti per evitare resource leak
    CloseHandle(readPipe);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return 0;
}