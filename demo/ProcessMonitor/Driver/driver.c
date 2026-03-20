/*
 * =============================================================
 * ProcessMonitor - Kernel Driver dimostrativo per EDR
 * =============================================================
 *
 * Questo driver si registra presso il kernel di Windows per
 * ricevere una notifica ogni volta che un processo viene
 * creato o terminato.
 *
 * Flusso di esecuzione:
 *   1. Windows carica il driver e chiama DriverEntry()
 *   2. DriverEntry registra ProcessCallback() nel kernel
 *   3. Ad ogni creazione/terminazione di processo il kernel
 *      chiama la nostra ProcessCallback()
 *   4. La callback scrive il log in un buffer circolare
 *   5. Il programma user mode legge il buffer via IOCTL
 *      e scrive su C:\edr.log
 * =============================================================
 */

/*
 * ntddk.h è l'unico header necessario in kernel mode.
 * Contiene tutte le strutture, i tipi e le funzioni del kernel.
 * NON si usano le normali librerie C (stdio.h, stdlib.h ecc.)
 * Usiamo _snwprintf_s che è una funzione intrinseca del
 * compilatore, disponibile anche in kernel mode.
 */
#include <ntddk.h>


/*
 * -------------------------------------------------------------
 * COSTANTI DI CONFIGURAZIONE
 * -------------------------------------------------------------
 */

/*
 * Nome interno del device nel namespace del kernel.
 * Visibile solo in kernel mode, sotto \Device\
 */
#define DEVICE_NAME     L"\\Device\\ProcessMonitor"

/*
 * Nome simbolico del device, visibile in user mode.
 * Il programma user mode aprirà "\\.\ProcessMonitor"
 * che corrisponde a \DosDevices\ProcessMonitor nel kernel.
 */
#define SYMBOLIC_NAME   L"\\DosDevices\\ProcessMonitor"

/*
 * Codice IOCTL per richiedere il prossimo messaggio di log.
 * CTL_CODE costruisce un codice a 32 bit combinando:
 *   FILE_DEVICE_UNKNOWN : tipo device generico
 *   0x800               : codice operazione (valori < 0x800 riservati a Microsoft)
 *   METHOD_BUFFERED     : il kernel gestisce la copia dei buffer automaticamente
 *   FILE_READ_DATA      : il chiamante richiede accesso in lettura
 */
#define IOCTL_GET_LOG   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_DATA)

/*
 * Dimensione massima di ogni messaggio di log in caratteri WCHAR.
 * 512 caratteri sono sufficienti per path, PID e PPID.
 */
#define MAX_MESSAGE_LEN 512

/*
 * Numero massimo di messaggi nel buffer circolare.
 * Se il programma user mode non legge abbastanza velocemente
 * e il buffer si riempie, i messaggi più vecchi vengono sovrascritti.
 */
#define BUFFER_SIZE     256


/*
 * -------------------------------------------------------------
 * STRUTTURE DATI
 * -------------------------------------------------------------
 */

/*
 * Buffer circolare (ring buffer) per i messaggi di log.
 *
 * Funziona come una coda FIFO:
 *   - Il driver scrive in WriteIndex (ProcessCallback)
 *   - Il programma user mode legge da ReadIndex (IOCTL)
 *   - Quando un indice raggiunge BUFFER_SIZE riparte da 0
 *
 * Esempio visivo:
 *   [0][1][2][3][4][5][6][7]
 *          ↑           ↑
 *       ReadIndex   WriteIndex
 *   I messaggi da leggere sono quelli tra ReadIndex e WriteIndex
 */
typedef struct _LOG_BUFFER
{
    /* Array di messaggi Unicode */
    WCHAR   Messages[BUFFER_SIZE][MAX_MESSAGE_LEN];

    /* Indice del prossimo slot dove scrivere */
    ULONG   WriteIndex;

    /* Indice del prossimo messaggio da leggere */
    ULONG   ReadIndex;

    /*
     * Spinlock per l'accesso thread-safe al buffer.
     * La callback può essere chiamata contemporaneamente
     * da più core — lo spinlock serializza gli accessi
     * evitando corruzione dei dati (race condition).
     */
    KSPIN_LOCK Lock;

} LOG_BUFFER, *PLOG_BUFFER;


/*
 * -------------------------------------------------------------
 * VARIABILI GLOBALI
 * -------------------------------------------------------------
 */

/* Il buffer circolare dei log */
static LOG_BUFFER       g_LogBuffer;

/* Oggetto device esposto al programma user mode */
static PDEVICE_OBJECT   g_DeviceObject = NULL;

/* Flag: il symbolic link è stato creato con successo */
static BOOLEAN          g_SymbolicLinkCreated = FALSE;


/*
 * =============================================================
 * FUNZIONE: WriteToLogBuffer
 * =============================================================
 *
 * Scrive un messaggio nel buffer circolare in modo thread-safe.
 * Chiamata da ProcessCallback() ad ogni evento di processo.
 *
 * Parametri:
 *   Message : stringa Unicode da scrivere nel buffer
 * =============================================================
 */
static VOID WriteToLogBuffer(const WCHAR* Message)
{
    KIRQL oldIrql;

    /*
     * Acquisisce lo spinlock elevando l'IRQL a DISPATCH_LEVEL.
     * Nessun altro thread può accedere al buffer fino al rilascio.
     * oldIrql salva il livello precedente per ripristinarlo dopo.
     */
    KeAcquireSpinLock(&g_LogBuffer.Lock, &oldIrql);

    /*
     * _snwprintf_s è una funzione intrinseca del compilatore,
     * disponibile anche in kernel mode (a differenza di funzioni
     * come sprintf che richiedono il runtime CRT non disponibile
     * nel kernel). Il flag _TRUNCATE tronca la stringa se supera
     * MAX_MESSAGE_LEN invece di restituire un errore.
     */
    _snwprintf_s(
        g_LogBuffer.Messages[g_LogBuffer.WriteIndex],
        MAX_MESSAGE_LEN,
        _TRUNCATE,
        L"%ls",
        Message);

    /*
     * Avanza l'indice di scrittura in modo circolare.
     * Il modulo (%) fa ripartire l'indice da 0 quando
     * raggiunge BUFFER_SIZE.
     */
    g_LogBuffer.WriteIndex = (g_LogBuffer.WriteIndex + 1) % BUFFER_SIZE;

    /*
     * Se WriteIndex ha raggiunto ReadIndex il buffer è pieno.
     * Sovrascriviamo il messaggio più vecchio avanzando ReadIndex.
     * Questo garantisce che il driver non si blocchi mai.
     */
    if (g_LogBuffer.WriteIndex == g_LogBuffer.ReadIndex)
    {
        g_LogBuffer.ReadIndex = (g_LogBuffer.ReadIndex + 1) % BUFFER_SIZE;
    }

    /* Rilascia lo spinlock e ripristina l'IRQL precedente */
    KeReleaseSpinLock(&g_LogBuffer.Lock, oldIrql);
}


/*
 * =============================================================
 * CALLBACK: ProcessCallback
 * =============================================================
 *
 * Chiamata dal kernel ad ogni creazione o terminazione di processo.
 * Gira nel contesto del thread che ha generato l'evento.
 *
 * IMPORTANTE: deve essere veloce, non può bloccarsi,
 * non può usare il runtime CRT standard.
 *
 * Parametri:
 *   Process    : struttura kernel EPROCESS del processo
 *   ProcessId  : PID del processo (tipo HANDLE, va castato)
 *   CreateInfo : non-NULL = creazione, NULL = terminazione
 * =============================================================
 */
VOID ProcessCallback(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    /*
     * Buffer locale per costruire il messaggio.
     * Allocato sullo stack — liberato automaticamente al ritorno.
     * In kernel mode lo stack è limitato (~12KB), 512 WCHAR = 1KB,
     * siamo ampiamente nei limiti.
     */
    WCHAR logMessage[MAX_MESSAGE_LEN];

    /* Process non viene usato in questa demo */
    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo != NULL)
    {
        /* -------------------------------------------------
         * CREAZIONE PROCESSO
         *
         * CreateInfo->ImageFileName è una UNICODE_STRING,
         * struttura nativa Windows per le stringhe Unicode:
         *   - Length        : lunghezza in byte
         *   - MaximumLength : capacità massima in byte
         *   - Buffer        : puntatore alla stringa wchar_t*
         *
         * Può essere NULL nelle prime fasi della creazione,
         * prima che il kernel abbia mappato l'eseguibile.
         * ------------------------------------------------- */
        if (CreateInfo->ImageFileName != NULL)
        {
            /*
             * Usiamo .Buffer per estrarre il puntatore wchar_t*
             * dalla struttura UNICODE_STRING e passarlo a
             * _snwprintf_s con il formato %ls (stringa wide).
             */
            _snwprintf_s(
                logMessage,
                MAX_MESSAGE_LEN,
                _TRUNCATE,
                L"[CREATO]    PID=%llu  PPID=%llu  Path=%ls\r\n",
                (ULONG64)(ULONG_PTR)ProcessId,
                (ULONG64)(ULONG_PTR)CreateInfo->ParentProcessId,
                CreateInfo->ImageFileName->Buffer);
        }
        else
        {
            _snwprintf_s(
                logMessage,
                MAX_MESSAGE_LEN,
                _TRUNCATE,
                L"[CREATO]    PID=%llu  PPID=%llu  Path=<non disponibile>\r\n",
                (ULONG64)(ULONG_PTR)ProcessId,
                (ULONG64)(ULONG_PTR)CreateInfo->ParentProcessId);
        }

        /*
         * NOTA - BLOCCO DEL PROCESSO (non attivo in questa demo):
         * Per impedire la creazione del processo basterebbe:
         *   CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
         * Il kernel annullerebbe la creazione dopo che tutte
         * le callback registrate hanno restituito il controllo.
         */
    }
    else
    {
        /* -------------------------------------------------
         * TERMINAZIONE PROCESSO
         *
         * CreateInfo è NULL: il processo sta terminando.
         * Non abbiamo più accesso a ImageFileName o CommandLine,
         * logghiamo solo il PID.
         * ------------------------------------------------- */
        _snwprintf_s(
            logMessage,
            MAX_MESSAGE_LEN,
            _TRUNCATE,
            L"[TERMINATO] PID=%llu\r\n",
            (ULONG64)(ULONG_PTR)ProcessId);
    }

    /* Scrivi nel buffer circolare per la lettura IOCTL */
    WriteToLogBuffer(logMessage);

    /* Scrivi anche su DebugView come fallback diagnostico */
    DbgPrint("[ProcessMonitor] %ws", logMessage);
}


/*
 * =============================================================
 * DISPATCH: IrpCreateClose
 * =============================================================
 *
 * Gestisce apertura e chiusura del device dal programma user mode
 * (CreateFile / CloseHandle). Non dobbiamo fare nulla di speciale
 * ma il handler DEVE esistere altrimenti Windows rifiuta
 * le operazioni con un errore.
 * =============================================================
 */
NTSTATUS IrpCreateClose(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}


/*
 * =============================================================
 * DISPATCH: IrpDeviceControl
 * =============================================================
 *
 * Gestisce le richieste IOCTL dal programma user mode.
 * Chiamata dal kernel ogni volta che il programma esegue
 * DeviceIoControl() sul nostro device.
 *
 * Con METHOD_BUFFERED il kernel copia automaticamente i dati
 * tra kernel e user mode tramite Irp->AssociatedIrp.SystemBuffer.
 * =============================================================
 */
NTSTATUS IrpDeviceControl(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp)
{
    PIO_STACK_LOCATION  irpStack;
    NTSTATUS            status       = STATUS_SUCCESS;
    ULONG               bytesWritten = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    irpStack = IoGetCurrentIrpStackLocation(Irp);

    if (irpStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_GET_LOG)
    {
        KIRQL   oldIrql;
        WCHAR*  outputBuffer;
        ULONG   outputBufferSize;

        /*
         * Con METHOD_BUFFERED il kernel ha già preparato
         * SystemBuffer come buffer di output. Noi scriviamo
         * qui la risposta e il kernel la copia in user mode.
         */
        outputBuffer     = (WCHAR*)Irp->AssociatedIrp.SystemBuffer;
        outputBufferSize = irpStack->Parameters.DeviceIoControl.OutputBufferLength;

        if (outputBuffer == NULL || outputBufferSize < sizeof(WCHAR))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            goto Complete;
        }

        KeAcquireSpinLock(&g_LogBuffer.Lock, &oldIrql);

        if (g_LogBuffer.ReadIndex != g_LogBuffer.WriteIndex)
        {
            /*
             * Ci sono messaggi da leggere.
             * Copia il messaggio corrente nel buffer output
             * e avanza l'indice di lettura.
             */
            _snwprintf_s(
                outputBuffer,
                outputBufferSize / sizeof(WCHAR),
                _TRUNCATE,
                L"%ls",
                g_LogBuffer.Messages[g_LogBuffer.ReadIndex]);

            bytesWritten = (ULONG)(wcslen(outputBuffer) * sizeof(WCHAR));

            g_LogBuffer.ReadIndex = (g_LogBuffer.ReadIndex + 1) % BUFFER_SIZE;
        }
        else
        {
            /*
             * Buffer vuoto: nessun nuovo messaggio.
             * Restituiamo 0 byte — il programma user mode
             * lo interpreta come "riprova più tardi".
             */
            outputBuffer[0] = L'\0';
            bytesWritten     = 0;
        }

        KeReleaseSpinLock(&g_LogBuffer.Lock, oldIrql);
    }
    else
    {
        status = STATUS_INVALID_DEVICE_REQUEST;
    }

Complete:
    Irp->IoStatus.Status      = status;
    Irp->IoStatus.Information = bytesWritten;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}


/*
 * =============================================================
 * UNLOAD: DriverUnload
 * =============================================================
 *
 * Chiamata dal kernel quando il driver viene scaricato.
 * OBBLIGATORIO: deregistrare la callback e rimuovere il device.
 * L'ordine è importante: prima la callback, poi il device.
 * =============================================================
 */
VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symbolicName;

    UNREFERENCED_PARAMETER(DriverObject);

    /*
     * 1. Deregistra la callback.
     * Il kernel garantisce che al ritorno di questa chiamata
     * nessun thread stia ancora eseguendo ProcessCallback().
     * È quindi sicuro procedere con la pulizia del device.
     */
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
}


/*
 * =============================================================
 * ENTRY POINT: DriverEntry
 * =============================================================
 *
 * Punto di ingresso del driver, equivalente del main().
 * Chiamato dal kernel una sola volta al caricamento.
 *
 * Parametri:
 *   DriverObject  : oggetto kernel che rappresenta questo driver
 *   RegistryPath  : path nel registro delle impostazioni driver
 *
 * Ritorna STATUS_SUCCESS se tutto ok, altrimenti il driver
 * non viene caricato.
 * =============================================================
 */
NTSTATUS DriverEntry(
    PDRIVER_OBJECT  DriverObject,
    PUNICODE_STRING RegistryPath)
{
    NTSTATUS        status;
    UNICODE_STRING  deviceName;
    UNICODE_STRING  symbolicName;

    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[ProcessMonitor] Inizializzazione...\n");

    /* --- 1. Inizializza il buffer circolare --- */

    /*
     * Azzera tutta la struttura: WriteIndex=0, ReadIndex=0,
     * tutti i messaggi vuoti.
     */
    RtlZeroMemory(&g_LogBuffer, sizeof(LOG_BUFFER));

    /*
     * Inizializza lo spinlock prima di qualsiasi utilizzo.
     * KeInitializeSpinLock imposta lo stato interno su "libero".
     */
    KeInitializeSpinLock(&g_LogBuffer.Lock);

    /* --- 2. Crea il device object --- */

    RtlInitUnicodeString(&deviceName, DEVICE_NAME);

    /*
     * IoCreateDevice crea l'oggetto device nel kernel.
     *   DriverObject       : questo driver
     *   0                  : nessuna estensione privata
     *   &deviceName        : nome nel namespace kernel
     *   FILE_DEVICE_UNKNOWN: tipo generico
     *   0                  : nessuna caratteristica speciale
     *   FALSE              : non esclusivo (più processi possono aprirlo)
     *   &g_DeviceObject    : output: puntatore al device creato
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
     * Collega \Device\ProcessMonitor a \DosDevices\ProcessMonitor
     * rendendo il device accessibile in user mode come \\.\ProcessMonitor
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
     * Dichiara le funzioni che gestiscono le operazioni sul device:
     *   IRP_MJ_CREATE/CLOSE   : apertura e chiusura (CreateFile/CloseHandle)
     *   IRP_MJ_DEVICE_CONTROL : richieste IOCTL (DeviceIoControl)
     */
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = IrpCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = IrpCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IrpDeviceControl;

    /* --- 5. Registra la funzione di unload --- */
    DriverObject->DriverUnload = DriverUnload;

    /* --- 6. Registra la callback per gli eventi di processo --- */

    /*
     * PsSetCreateProcessNotifyRoutineEx registra ProcessCallback
     * nel kernel. Da questo momento verrà chiamata ad ogni
     * creazione o terminazione di processo nel sistema.
     *
     * REQUISITO: il driver deve essere compilato con /integritycheck
     * altrimenti questa chiamata restituisce STATUS_ACCESS_DENIED.
     */
    status = PsSetCreateProcessNotifyRoutineEx(ProcessCallback, FALSE);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("[ProcessMonitor] Errore registrazione callback: 0x%X\n", status);
        IoDeleteSymbolicLink(&symbolicName);
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    DbgPrint("[ProcessMonitor] Driver caricato e operativo.\n");
    return STATUS_SUCCESS;
}