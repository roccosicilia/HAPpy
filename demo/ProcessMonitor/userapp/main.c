/*
 * =============================================================
 * ProcessMonitor - Programma User Mode
 * =============================================================
 *
 * Si connette al driver tramite DeviceIoControl, legge
 * i messaggi di log dal buffer circolare e li scrive
 * su C:\edr.log in tempo reale.
 * =============================================================
 */
#include <windows.h>
#include <stdio.h>

/* Nome del device esposto dal driver nel namespace DOS */
#define DEVICE_NAME     "\\\\.\\ProcessMonitor"

/* Path del file di log */
#define LOG_FILE_PATH   "C:\\edr.log"

/* Deve corrispondere esattamente al valore nel driver */
#define IOCTL_GET_LOG   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_DATA)

/* Dimensione buffer ricezione (deve essere >= MAX_MESSAGE_LEN del driver) */
#define BUFFER_SIZE     1024


int main(void)
{
    HANDLE  hDevice;
    FILE*   logFile;
    WCHAR   buffer[BUFFER_SIZE];
    DWORD   bytesReturned;
    BOOL    ok;

    printf("[*] ProcessMonitor - User Mode Logger\n");
    printf("[*] Output: %s\n\n", LOG_FILE_PATH);

    /* --- Apertura del device --- */

    /*
     * CreateFileA apre il device esposto dal driver.
     * Dal punto di vista del programma sembra l'apertura
     * di un file normale, ma in realtà comunica con il driver.
     * GENERIC_READ      : vogliamo solo leggere dal device
     * OPEN_EXISTING     : il device deve già esistere (il driver caricato)
     */
    hDevice = CreateFileA(
        DEVICE_NAME,
        GENERIC_READ,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hDevice == INVALID_HANDLE_VALUE)
    {
        printf("[!] Impossibile aprire il device: errore %lu\n", GetLastError());
        printf("[!] Verificare che il driver sia caricato (sc start ProcessMonitor)\n");
        return 1;
    }

    printf("[*] Connesso al driver.\n");

    /* --- Apertura del file di log --- */

    /*
     * "a, ccs=UNICODE" apre il file in modalità append Unicode.
     * - "a"          : append, non sovrascrive il file esistente
     * - "ccs=UNICODE": scrive in formato Unicode (UTF-16 LE)
     *                  compatibile con le stringhe WCHAR del driver
     */
    logFile = _wfopen(L"C:\\edr.log", L"a, ccs=UNICODE");

    if (logFile == NULL)
    {
        printf("[!] Impossibile aprire C:\\edr.log\n");
        printf("[!] Verificare di avere i permessi di scrittura\n");
        CloseHandle(hDevice);
        return 1;
    }

    printf("[*] File di log aperto: %s\n", LOG_FILE_PATH);
    printf("[*] In ascolto... (Ctrl+C per fermare)\n\n");

    /* --- Loop principale --- */

    while (1)
    {
        /*
         * Azzera il buffer prima di ogni lettura per evitare
         * che dati vecchi rimangano in caso di lettura parziale.
         */
        memset(buffer, 0, sizeof(buffer));

        /*
         * DeviceIoControl invia una richiesta IOCTL al driver.
         * Parametri:
         *   hDevice       : handle al device aperto
         *   IOCTL_GET_LOG : codice operazione (deve corrispondere al driver)
         *   NULL, 0       : nessun buffer di input (non mandiamo dati al driver)
         *   buffer        : buffer di output (dove il driver scrive la risposta)
         *   sizeof(buffer): dimensione del buffer output in byte
         *   &bytesReturned: quanti byte il driver ha effettivamente scritto
         *   NULL          : operazione sincrona (aspetta il completamento)
         */
        ok = DeviceIoControl(
            hDevice,
            IOCTL_GET_LOG,
            NULL, 0,
            buffer, sizeof(buffer),
            &bytesReturned,
            NULL);

        if (ok && bytesReturned > 0)
        {
            /*
             * Il driver ha restituito un messaggio.
             * Lo stampiamo su console e lo scriviamo sul file.
             */
            wprintf(L"%s", buffer);

            fwprintf(logFile, L"%s", buffer);

            /*
             * fflush forza la scrittura immediata su disco.
             * Senza questo, il runtime C bufferizza le scritture
             * e il file potrebbe non essere aggiornato in tempo reale.
             */
            fflush(logFile);
        }

        /*
         * Pausa di 100ms tra una lettura e l'altra.
         * Evita di saturare la CPU con richieste continue
         * quando il buffer è vuoto. In un EDR reale si userebbe
         * un evento (KEVENT) per essere notificati dal driver
         * quando c'è un nuovo messaggio (più efficiente).
         */
        Sleep(100);
    }

    /* Questo codice non viene mai raggiunto nel loop infinito,
     * ma è buona pratica includerlo per completezza */
    fclose(logFile);
    CloseHandle(hDevice);
    return 0;
}