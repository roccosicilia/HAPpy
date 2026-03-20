/*
 * =============================================================
 * ProcessMonitor - Kernel Driver con buffer circolare
 * =============================================================
 *
 * Architettura:
 *   1. Il driver si registra per gli eventi di creazione/
 *      terminazione processi tramite PsSetCreateProcessNotifyRoutineEx
 *   2. Ogni evento viene scritto in un buffer circolare in memoria
 *   3. Il programma user mode legge il buffer tramite IOCTL
 *      e scrive i dati su C:\edr.log
 *
 * Comunicazione kernel ↔ user mode:
 *   - Il driver espone un "device" (oggetto kernel visibile
 *     come file speciale) a cui il programma user mode si connette
 *   - La comunicazione avviene tramite DeviceIoControl (IOCTL)
 * =============================================================
 */
#include <ntddk.h>

/*
 * -------------------------------------------------------------
 * COSTANTI DI CONFIGURAZIONE
 * -------------------------------------------------------------
 */

/*
 * Nome interno del device nel namespace del kernel.
 * Tutti i device kernel vivono sotto \Device\
 * Questo nome è visibile solo in kernel mode.
 */
#define DEVICE_NAME     L"\\Device\\ProcessMonitor"

/*
 * Nome simbolico del device, visibile in user mode.
 * I programmi user mode accedono ai device tramite
 * il namespace \\.\ (che corrisponde a \DosDevices\ nel kernel).
 * Quindi il programma aprirà "\\.\ProcessMonitor"
 */
#define SYMBOLIC_NAME   L"\\DosDevices\\ProcessMonitor"

/*
 * Codice IOCTL che il programma user mode usa per chiedere
 * al driver il prossimo messaggio di log disponibile.
 *
 * CTL_CODE è una macro che costruisce un codice IOCTL a 32 bit
 * combinando quattro campi:
 *   - FILE_DEVICE_UNKNOWN : tipo di device generico
 *   - 0x800               : codice operazione (scelto da noi,
 *                           i valori < 0x800 sono riservati a Microsoft)
 *   - METHOD_BUFFERED     : il kernel copia i dati in un buffer
 *                           intermedio (più semplice e sicuro)
 *   - FILE_READ_DATA      : il chiamante necessita di accesso in lettura
 */
#define IOCTL_GET_LOG   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_DATA)

/*
 * Dimensione massima di ogni singolo messaggio di log in caratteri.
 * 512 caratteri sono abbondanti per contenere path, PID, PPID ecc.
 */
#define MAX_MESSAGE_LEN 512

/*
 * Numero massimo di messaggi che il buffer circolare può contenere.
 * Se il programma user mode non legge abbastanza velocemente
 * e il buffer si riempie, i messaggi più vecchi vengono sovrascritti.
 * 256 messaggi sono sufficienti per una demo.
 */
#define BUFFER_SIZE     256


/*
 * -------------------------------------------------------------
 * STRUTTURE DATI
 * -------------------------------------------------------------
 */

/*
 * Il buffer circolare (ring buffer) è la struttura dati centrale
 * del driver. Funziona come una coda FIFO (First In, First Out):
 *   - Il driver scrive i nuovi messaggi in WriteIndex
 *   - Il programma user mode legge da ReadIndex
 *   - Quando un indice raggiunge BUFFER_SIZE, riparte da 0
 *
 * Rappresentazione visiva:
 *
 *   [0][1][2][3][4][5][6][7]  ← array di messaggi
 *          ↑           ↑
 *       ReadIndex   WriteIndex
 *
 *   I messaggi da leggere sono quelli tra ReadIndex e WriteIndex
 */
typedef struct _LOG_BUFFER {

    /*
     * Array di stringhe. Ogni elemento è un messaggio di log.
     * Usiamo caratteri WCHAR (Unicode a 16 bit) perché i path
     * di Windows sono nativamente Unicode.
     */
    WCHAR Messages[BUFFER_SIZE][MAX_MESSAGE_LEN];

    /*
     * Indice del prossimo slot dove scrivere il messaggio.
     * Avanza ad ogni scrittura del driver (nella callback).
     */
    ULONG WriteIndex;

    /*
     * Indice del prossimo messaggio da leggere.
     * Avanza ad ogni lettura del programma user mode (IOCTL).
     */
    ULONG ReadIndex;

    /*
     * Oggetto di sincronizzazione (spinlock).
     * La callback può essere chiamata contemporaneamente da
     * più thread (su sistemi multi-core), quindi l'accesso
     * al buffer deve essere serializzato per evitare
     * corruzione dei dati (race condition).
     *
     * Lo spinlock è il meccanismo di sincronizzazione più
     * semplice disponibile in kernel mode: il thread che
     * vuole accedere al buffer "gira" (spin) in un loop
     * finché il lock non è libero.
     */
    KSPIN_LOCK Lock;

} LOG_BUFFER, *PLOG_BUFFER;


/*
 * -------------------------------------------------------------
 * VARIABILI GLOBALI DEL DRIVER
 * -------------------------------------------------------------
 * In kernel mode le variabili globali vivono per tutta la durata
 * del caricamento del driver. Vanno usate con attenzione perché
 * sono condivise tra tutti i thread che eseguono codice del driver.
 */

/* Il buffer circolare, allocato staticamente */
static LOG_BUFFER g_LogBuffer;

/* Puntatore all'oggetto device creato da IoCreateDevice */
static PDEVICE_OBJECT g_DeviceObject = NULL;

/* Puntatore all'oggetto symbolic link (per la pulizia in DriverUnload) */
static BOOLEAN g_SymbolicLinkCreated = FALSE;


/*
 * =============================================================
 * FUNZIONE: WriteToLogBuffer
 * =============================================================
 *
 * Scrive un messaggio nel buffer circolare in modo thread-safe.
 * Chiamata dalla callback ogni volta che c'è un evento da loggare.
 *
 * Parametri:
 *   Message : stringa Unicode (WCHAR) da scrivere nel buffer
 * =============================================================
 */
static VOID WriteToLogBuffer(const WCHAR* Message)
{
    KIRQL oldIrql;

    /*
     * Acquisizione dello spinlock.
     *
     * KeAcquireSpinLock eleva l'IRQL (Interrupt Request Level)
     * al livello DISPATCH_LEVEL, impedendo che altri thread
     * o interrupt preemptino questo codice mentre modifica il buffer.
     * oldIrql salva il livello precedente per ripristinarlo dopo.
     */
    KeAcquireSpinLock(&g_LogBuffer.Lock, &oldIrql);

    /*
     * Copia il messaggio nello slot corrente del buffer.
     * RtlStringCchCopyW è la versione sicura della strcpy per
     * stringhe Unicode in kernel mode: garantisce che non si
     * scriva oltre MAX_MESSAGE_LEN caratteri (buffer overflow protection).
     */
    RtlStringCchCopyW(
        g_LogBuffer.Messages[g_LogBuffer.WriteIndex],
        MAX_MESSAGE_LEN,
        Message);

    /*
     * Avanza l'indice di scrittura in modo circolare.
     * L'operatore modulo (%) fa sì che quando l'indice
     * raggiunge BUFFER_SIZE, riparta da 0.
     */
    g_LogBuffer.WriteIndex = (g_LogBuffer.WriteIndex + 1) % BUFFER_SIZE;

    /*
     * Se il buffer è pieno (WriteIndex ha raggiunto ReadIndex),
     * sovrascriviamo il messaggio più vecchio avanzando anche
     * ReadIndex. Questo garantisce che il buffer non si blocchi
     * mai, al costo di perdere i messaggi più vecchi.
     */
    if (g_LogBuffer.WriteIndex == g_LogBuffer.ReadIndex)
    {
        g_LogBuffer.ReadIndex = (g_LogBuffer.ReadIndex + 1) % BUFFER_SIZE;
    }

    /*
     * Rilascio dello spinlock.
     * Ripristina l'IRQL al valore salvato in oldIrql.
     * Da questo momento altri thread possono acquisire il lock.
     */
    KeReleaseSpinLock(&g_LogBuffer.Lock, oldIrql);
}


/*
 * =============================================================
 * CALLBACK: ProcessCallback
 * =============================================================
 *
 * Chiamata dal kernel ad ogni creazione o terminazione di processo.
 * Costruisce il messaggio di log e lo scrive nel buffer circolare.
 * =============================================================
 */
VOID ProcessCallback(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    /*
     * Buffer locale per costruire il messaggio di log.
     * È allocato sullo stack (variabile locale), quindi
     * è automaticamente liberato al ritorno della funzione.
     * In kernel mode lo stack è limitato (~12KB), quindi
     * non allochiamo buffer troppo grandi qui.
     */
    WCHAR logMessage[MAX_MESSAGE_LEN];

    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo != NULL)
    {
        /* --- CREAZIONE PROCESSO --- */

        if (CreateInfo->ImageFileName != NULL)
        {
            /*
             * RtlStringCchPrintfW è l'equivalente kernel di swprintf_s:
             * formatta una stringa Unicode in modo sicuro.
             * %d  = intero decimale
             * %wZ = UNICODE_STRING (tipo nativo Windows)
             */
            RtlStringCchPrintfW(
                logMessage,
                MAX_MESSAGE_LEN,
                L"[CREATO]    PID=%llu  PPID=%llu  Path=%wZ\r\n",
                (ULONG64)(ULONG_PTR)ProcessId,
                (ULONG64)(ULONG_PTR)CreateInfo->ParentProcessId,
                CreateInfo->ImageFileName);
        }
        else
        {
            RtlStringCchPrintfW(
                logMessage,
                MAX_MESSAGE_LEN,
                L"[CREATO]    PID=%llu  PPID=%llu  Path=<non disponibile>\r\n",
                (ULONG64)(ULONG_PTR)ProcessId,
                (ULONG64)(ULONG_PTR)CreateInfo->ParentProcessId);
        }
    }
    else
    {
        /* --- TERMINAZIONE PROCESSO --- */
        RtlStringCchPrintfW(
            logMessage,
            MAX_MESSAGE_LEN,
            L"[TERMINATO] PID=%llu\r\n",
            (ULONG64)(ULONG_PTR)ProcessId);
    }

    /* Scrivi il messaggio nel buffer circolare */
    WriteToLogBuffer(logMessage);

    /* Manteniamo anche DbgPrint per DebugView come fallback */
    DbgPrint("[ProcessMonitor] %ws", logMessage);
}


/*
 * =============================================================
 * DISPATCH: IrpDeviceControl
 * =============================================================
 *
 * Gestisce le richieste IOCTL provenienti dal programma user mode.
 * Questa funzione è il "gestore delle richieste" del device:
 * viene chiamata dal kernel ogni volta che il programma user mode
 * chiama DeviceIoControl() sul nostro device.
 *
 * In Windows, ogni operazione su un device (apertura, lettura,
 * IOCTL ecc.) arriva al driver come un oggetto IRP
 * (I/O Request Packet). Il driver lo elabora e lo "completa"
 * con IoCompleteRequest().
 * =============================================================
 */
NTSTATUS IrpDeviceControl(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp)
{
    /*
     * PIO_STACK_LOCATION contiene i parametri specifici
     * dell'operazione corrente (in questo caso i parametri IOCTL:
     * codice, dimensione buffer input/output ecc.)
     */
    PIO_STACK_LOCATION irpStack;

    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytesWritten = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    /* Ottieni i parametri dell'operazione corrente */
    irpStack = IoGetCurrentIrpStackLocation(Irp);

    /*
     * Verifica che il codice IOCTL ricevuto sia quello
     * che ci aspettiamo. Un device può gestire più codici IOCTL
     * diversi; in questa demo ne gestiamo solo uno.
     */
    if (irpStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_GET_LOG)
    {
        KIRQL oldIrql;
        WCHAR* outputBuffer;
        ULONG outputBufferSize;

        /*
         * Con METHOD_BUFFERED (specificato in CTL_CODE),
         * il kernel ha già copiato il buffer output del chiamante
         * in Irp->AssociatedIrp.SystemBuffer.
         * Noi dobbiamo scrivere lì la risposta; il kernel
         * la copierà automaticamente nel buffer user mode.
         */
        outputBuffer = (WCHAR*)Irp->AssociatedIrp.SystemBuffer;
        outputBufferSize = irpStack->Parameters.DeviceIoControl.OutputBufferLength;

        /* Verifica che il buffer output sia valido e sufficientemente grande */
        if (outputBuffer == NULL || outputBufferSize < sizeof(WCHAR))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            goto Complete;
        }

        /* Accedi al buffer in modo thread-safe */
        KeAcquireSpinLock(&g_LogBuffer.Lock, &oldIrql);

        if (g_LogBuffer.ReadIndex != g_LogBuffer.WriteIndex)
        {
            /*
             * Ci sono messaggi da leggere.
             * Copia il messaggio corrente nel buffer output.
             */
            RtlStringCchCopyW(
                outputBuffer,
                outputBufferSize / sizeof(WCHAR),
                g_LogBuffer.Messages[g_LogBuffer.ReadIndex]);

            /* Calcola quanti byte stiamo restituendo */
            bytesWritten = (ULONG)(wcslen(outputBuffer) * sizeof(WCHAR));

            /* Avanza l'indice di lettura */
            g_LogBuffer.ReadIndex = (g_LogBuffer.ReadIndex + 1) % BUFFER_SIZE;
        }
        else
        {
            /*
             * Buffer vuoto: nessun nuovo messaggio disponibile.
             * Restituiamo 0 byte — il programma user mode
             * lo interpreterà come "riprova più tardi".
             */
            outputBuffer[0] = L'\0';
            bytesWritten = 0;
        }

        KeReleaseSpinLock(&g_LogBuffer.Lock, oldIrql);
    }
    else
    {
        /* Codice IOCTL non riconosciuto */
        status = STATUS_INVALID_DEVICE_REQUEST;
    }

Complete:
    /*
     * Completa l'IRP: comunica al kernel l'esito dell'operazione
     * e quanti byte abbiamo scritto nel buffer output.
     * IO_NO_INCREMENT significa che non aumentiamo la priorità
     * del thread chiamante al completamento.
     */
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesWritten;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}


/*
 * =============================================================
 * DISPATCH: IrpCreateClose
 * =============================================================
 *
 * Gestisce l'apertura e la chiusura del device da parte del
 * programma user mode (CreateFile / CloseHandle).
 * In questa demo non dobbiamo fare nulla di speciale,
 * ma il handler DEVE esistere altrimenti Windows rifiuta
 * le operazioni di apertura/chiusura con un errore.
 * =============================================================
 */
NTSTATUS IrpCreateClose(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    /* Completa l'IRP con successo senza fare nulla */
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}


/*
 * =============================================================
 * UNLOAD: DriverUnload
 * =============================================================
 *
 * Pulizia completa prima dello scaricamento del driver.
 * L'ordine è importante: prima deregistriamo la callback,
 * poi rimuoviamo il device. Mai il contrario.
 * =============================================================
 */
VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symbolicName;

    /* 1. Deregistra la callback — da questo momento il kernel
     *    non chiamerà più ProcessCallback() */
    PsSetCreateProcessNotifyRoutineEx(ProcessCallback, TRUE);
    DbgPrint("[ProcessMonitor] Callback rimossa.\n");

    /* 2. Rimuovi il symbolic link dal namespace DOS */
    if (g_SymbolicLinkCreated)
    {
        RtlInitUnicodeString(&symbolicName, SYMBOLIC_NAME);
        IoDeleteSymbolicLink(&symbolicName);
    }

    /* 3. Distruggi il device object */
    if (g_DeviceObject != NULL)
    {
        IoDeleteDevice(g_DeviceObject);
    }

    DbgPrint("[ProcessMonitor] Driver scaricato.\n");

    UNREFERENCED_PARAMETER(DriverObject);
}


/*
 * =============================================================
 * ENTRY POINT: DriverEntry
 * =============================================================
 */
NTSTATUS DriverEntry(
    PDRIVER_OBJECT  DriverObject,
    PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNICODE_STRING deviceName;
    UNICODE_STRING symbolicName;

    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[ProcessMonitor] Inizializzazione...\n");

    /* --- 1. Inizializza il buffer circolare --- */

    /*
     * RtlZeroMemory azzera tutta la struttura LOG_BUFFER.
     * Questo imposta WriteIndex e ReadIndex a 0 e pulisce
     * tutti i messaggi. Equivalente a memset(..., 0, ...).
     */
    RtlZeroMemory(&g_LogBuffer, sizeof(LOG_BUFFER));

    /*
     * Inizializza lo spinlock. Va fatto prima di qualsiasi
     * uso del lock. KeInitializeSpinLock imposta lo stato
     * interno del lock su "libero".
     */
    KeInitializeSpinLock(&g_LogBuffer.Lock);

    /* --- 2. Crea il device object --- */

    /*
     * RtlInitUnicodeString inizializza una struttura UNICODE_STRING
     * a partire da una stringa letterale. UNICODE_STRING è il tipo
     * stringa nativo del kernel Windows (lunghezza + buffer Unicode).
     */
    RtlInitUnicodeString(&deviceName, DEVICE_NAME);

    /*
     * IoCreateDevice crea l'oggetto device nel kernel.
     * Parametri principali:
     *   - DriverObject       : questo driver
     *   - 0                  : nessuna estensione privata
     *   - &deviceName        : nome nel namespace kernel
     *   - FILE_DEVICE_UNKNOWN: tipo generico
     *   - 0                  : nessuna caratteristica speciale
     *   - FALSE              : non esclusivo (più processi possono aprirlo)
     *   - &g_DeviceObject    : output: puntatore al device creato
     */
    status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &g_DeviceObject);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("[ProcessMonitor] Errore IoCreateDevice: 0x%X\n", status);
        return status;
    }

    /* --- 3. Crea il symbolic link --- */

    /*
     * Il symbolic link collega il nome kernel (\Device\ProcessMonitor)
     * al nome DOS (\DosDevices\ProcessMonitor), rendendo il device
     * accessibile in user mode come "\\.\ProcessMonitor".
     */
    RtlInitUnicodeString(&symbolicName, SYMBOLIC_NAME);

    status = IoCreateSymbolicLink(&symbolicName, &deviceName);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("[ProcessMonitor] Errore IoCreateSymbolicLink: 0x%X\n", status);
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    g_SymbolicLinkCreated = TRUE;

    /* --- 4. Registra i dispatch handlers --- */

    /*
     * Il driver deve dichiarare quali funzioni gestiscono
     * i vari tipi di operazioni sul device.
     * IRP_MJ_CREATE e IRP_MJ_CLOSE : apertura/chiusura (CreateFile/CloseHandle)
     * IRP_MJ_DEVICE_CONTROL        : richieste IOCTL (DeviceIoControl)
     */
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = IrpCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = IrpCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IrpDeviceControl;

    /* --- 5. Registra l'unload routine --- */
    DriverObject->DriverUnload = DriverUnload;

    /* --- 6. Registra la callback per i processi --- */
    status = PsSetCreateProcessNotifyRoutineEx(ProcessCallback, FALSE);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("[ProcessMonitor] Errore registrazione callback: 0x%X\n", status);
        /* Pulizia: rimuovi symbolic link e device già creati */
        IoDeleteSymbolicLink(&symbolicName);
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    DbgPrint("[ProcessMonitor] Driver caricato e operativo.\n");
    return STATUS_SUCCESS;
}