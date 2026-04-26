/*
 * RansomWall Kernel-Mode File System Minifilter Driver
 * =====================================================
 * Paper: "RansomWall: A Layered Defense System against Cryptographic
 *         Ransomware Attacks using Machine Learning" (COMSNETS 2018)
 *         Shaukat & Ribeiro, IIT Delhi
 *
 * Paper Section IV-B:
 *   "RansomWall implements a File System Filter Driver ... It is a kernel
 *    level driver that filters I/O operations performed on one or more file
 *    systems. For Microsoft Windows operating system modern File System
 *    Filter Drivers are known as minifilter drivers."
 *
 * Architecture (paper §IV-A):
 *   [User File I/O]
 *       |
 *   [I/O Manager]
 *       |
 *   [Filter Manager] <-- registers this minifilter
 *       |
 *   [RansomWall File System Filter Driver]  <-- THIS FILE
 *       |
 *   [File System Driver]
 *       |
 *   [Storage Driver Stack]
 *       |
 *   [Hardware]
 *
 * IRP types monitored (paper §III-D-3):
 *   IRP_MJ_READ              -> file_read count
 *   IRP_MJ_WRITE             -> file_write count + entropy check
 *   IRP_MJ_SET_INFORMATION   -> rename / delete operations
 *   IRP_MJ_DIRECTORY         -> dir_query count
 *   IRP_MJ_CREATE            -> file open tracking
 *
 * Communication with user-mode Python layer:
 *   Uses a named communication port (paper §IV-A: "IRP Filter forwards
 *   IRP messages to Dynamic and Trap Layers for feature computation").
 *   Port name: \RansomWallPort
 *   Message format: RANSOMWALL_IRP_MESSAGE struct (defined below)
 *
 * Build requirements:
 *   - Windows Driver Kit (WDK) 10 (paper §IV-D)
 *   - Microsoft Visual Studio 2015+ (paper §IV-D)
 *   - Target: Windows 7 / 8.1 / 10 x64
 *
 * Build command (from WDK x64 Native Tools Command Prompt):
 *   msbuild RansomWallFilter.vcxproj /p:Configuration=Release /p:Platform=x64
 *
 * Installation:
 *   sc create RansomWallFilter type= filesys binPath= C:\path\to\RansomWallFilter.sys
 *   sc start RansomWallFilter
 *   (or use the provided installer script: install_driver.bat)
 *
 * IMPORTANT: This driver must be loaded with a valid code-signing certificate
 *            on Windows 10/11 with Secure Boot enabled. For testing, use
 *            Test Signing Mode: bcdedit /set testsigning on
 */

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <ntstrsafe.h>
#include <wdm.h>

/* ══════════════════════════════════════════════════════════════════════════ */
/* CONSTANTS & CONFIGURATION                                                   */
/* ══════════════════════════════════════════════════════════════════════════ */

#define RANSOMWALL_FILTER_NAME      L"RansomWallFilter"
#define RANSOMWALL_PORT_NAME        L"\\RansomWallPort"
#define RANSOMWALL_ALTITUDE         L"370030"   /* Load order altitude */

/* Maximum clients (Python user-mode processes) connected simultaneously */
#define RANSOMWALL_MAX_CONNECTIONS  2

/* Message queue depth before dropping (ring buffer) */
#define RANSOMWALL_MSG_QUEUE_SIZE   1024

/* Minimum file size to compute entropy (< 64 bytes not meaningful) */
#define ENTROPY_MIN_FILE_SIZE       64

/* Shannon entropy threshold: ~7.2 bits/byte = encrypted/compressed */
#define ENTROPY_THRESHOLD_X100      720     /* stored as integer * 100 */

/* Pool tags for memory allocation tracing */
#define RANSOMWALL_TAG              'llWR'  /* 'RWll' reversed for pool viewer */
#define RANSOMWALL_MSG_TAG          'gsMR'

/* Ransomware-typical target extensions (paper §III-A Stage 3) */
static const WCHAR* TARGET_EXTENSIONS[] = {
    L".docx", L".doc",  L".xlsx", L".xls",
    L".pptx", L".ppt",  L".pdf",  L".txt",
    L".jpg",  L".jpeg", L".png",  L".bmp",
    L".mp4",  L".avi",  L".mov",  L".zip",
    L".rar",  L".csv",  L".db",   L".sql",
    L".py",   L".js",   L".html", L".xml",
    NULL
};

/* Known ransomware-added extensions (paper §III-D-3d) */
static const WCHAR* RANSOM_EXTENSIONS[] = {
    L".locked",    L".encrypted", L".enc",
    L".crypt",     L".crypto",    L".zepto",
    L".locky",     L".cerber",    L".wcry",
    L".wncry",     L".wnry",      L".onion",
    NULL
};

/* ══════════════════════════════════════════════════════════════════════════ */
/* IRP MESSAGE STRUCTURES (shared with user-mode Python bridge)               */
/* ══════════════════════════════════════════════════════════════════════════ */

/*
 * IRP operation types - mirrors paper §III-D-3 feature list
 */
typedef enum _RANSOMWALL_OP_TYPE {
    RW_OP_UNKNOWN       = 0,
    RW_OP_READ          = 1,   /* IRP_MJ_READ          */
    RW_OP_WRITE         = 2,   /* IRP_MJ_WRITE         */
    RW_OP_RENAME        = 3,   /* IRP_MJ_SET_INFORMATION FileRenameInformation */
    RW_OP_DELETE        = 4,   /* IRP_MJ_SET_INFORMATION FileDispositionInformation */
    RW_OP_DIR_QUERY     = 5,   /* IRP_MJ_DIRECTORY     */
    RW_OP_CREATE        = 6,   /* IRP_MJ_CREATE        */
    RW_OP_FINGERPRINT   = 7,   /* Extension-magic mismatch detected */
    RW_OP_ENTROPY_SPIKE = 8,   /* High entropy write detected */
} RANSOMWALL_OP_TYPE;

/*
 * Message sent from kernel driver to user-mode Python bridge.
 * Python bridge reads this from the communication port and forwards
 * to DynamicEngine.inject_irp() and TrapLayer.inject_test_event().
 *
 * Paper §IV-A: "IRP Filter forwards IRP messages ... to Dynamic and
 * Trap Layers for feature computation."
 */
#pragma pack(push, 1)
typedef struct _RANSOMWALL_IRP_MESSAGE {
    /* Header */
    ULONG           MessageSize;        /* sizeof this struct */
    ULONG           Version;            /* Protocol version = 1 */

    /* Process identity (paper §IV-A: per-process tracking) */
    ULONG           ProcessId;          /* PID of the process performing I/O */
    ULONG           ThreadId;
    WCHAR           ProcessName[260];   /* Process image name (e.g., "svchost.exe") */

    /* IRP information */
    RANSOMWALL_OP_TYPE  Operation;      /* What kind of file operation */
    LARGE_INTEGER   Timestamp;          /* System time of the IRP */
    ULONG           FileSize;           /* Size of the file being operated on */

    /* File path (source) */
    WCHAR           FilePath[520];      /* Full NT path of source file */
    USHORT          FileExtension[16];  /* Extension (e.g., L".docx") */

    /* Rename destination (valid when Operation == RW_OP_RENAME) */
    WCHAR           DestPath[520];      /* Full NT path of destination */
    USHORT          DestExtension[16];  /* Destination extension */

    /* Entropy data (valid when Operation == RW_OP_WRITE or RW_OP_ENTROPY_SPIKE) */
    ULONG           EntropyX100;        /* Shannon entropy * 100 (integer) */
    BOOLEAN         IsTargetExtension;  /* TRUE if source extension is in TARGET_EXTENSIONS */
    BOOLEAN         IsRansomExtension;  /* TRUE if dest extension is in RANSOM_EXTENSIONS */
    BOOLEAN         FingerprintMismatch;/* TRUE if magic bytes don't match extension */

} RANSOMWALL_IRP_MESSAGE, *PRANSOMWALL_IRP_MESSAGE;
#pragma pack(pop)

/*
 * Filter control commands from user-mode to kernel driver.
 * Sent via FltSendMessage from the Python bridge.
 */
typedef enum _RANSOMWALL_CMD {
    RW_CMD_SUSPEND_PID  = 1,    /* Temporarily suspend monitoring for PID */
    RW_CMD_KILL_PID     = 2,    /* Request process termination */
    RW_CMD_WHITELIST_PID= 3,    /* Mark PID as benign - stop monitoring */
    RW_CMD_STATUS       = 4,    /* Query driver status */
} RANSOMWALL_CMD;

typedef struct _RANSOMWALL_COMMAND {
    RANSOMWALL_CMD  Command;
    ULONG           TargetPid;
    WCHAR           Reserved[64];
} RANSOMWALL_COMMAND, *PRANSOMWALL_COMMAND;

/* ══════════════════════════════════════════════════════════════════════════ */
/* DRIVER GLOBAL STATE                                                         */
/* ══════════════════════════════════════════════════════════════════════════ */

/* Filter handle returned by FltRegisterFilter */
static PFLT_FILTER       g_FilterHandle      = NULL;

/* Communication port (kernel side) */
static PFLT_PORT         g_ServerPort        = NULL;

/* Connection from user-mode Python bridge */
static PFLT_PORT         g_ClientPort        = NULL;

/* Spinlock protecting g_ClientPort */
static KSPIN_LOCK        g_ClientPortLock;

/* Statistics counters (paper §V-G: "less than 1% CPU Load" for normal) */
static volatile LONG     g_TotalIRPs         = 0;
static volatile LONG     g_SuspiciousIRPs    = 0;
static volatile LONG     g_DroppedMessages   = 0;

/* Whitelist of known-benign PIDs (classified by ML layer) */
#define MAX_WHITELIST_SIZE  256
static ULONG             g_WhitelistPids[MAX_WHITELIST_SIZE] = {0};
static ULONG             g_WhitelistCount = 0;
static KSPIN_LOCK        g_WhitelistLock;

/* ══════════════════════════════════════════════════════════════════════════ */
/* FORWARD DECLARATIONS                                                        */
/* ══════════════════════════════════════════════════════════════════════════ */

DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
);

NTSTATUS RansomWallUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS RansomWallPreRead(
    _Inout_ PFLT_CALLBACK_DATA    Data,
    _In_    PCFLT_RELATED_OBJECTS FltObjects,
    _Out_   PVOID*                CompletionContext
);

FLT_PREOP_CALLBACK_STATUS RansomWallPreWrite(
    _Inout_ PFLT_CALLBACK_DATA    Data,
    _In_    PCFLT_RELATED_OBJECTS FltObjects,
    _Out_   PVOID*                CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS RansomWallPostWrite(
    _Inout_ PFLT_CALLBACK_DATA       Data,
    _In_    PCFLT_RELATED_OBJECTS    FltObjects,
    _In_    PVOID                    CompletionContext,
    _In_    FLT_POST_OPERATION_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS RansomWallPreSetInfo(
    _Inout_ PFLT_CALLBACK_DATA    Data,
    _In_    PCFLT_RELATED_OBJECTS FltObjects,
    _Out_   PVOID*                CompletionContext
);

FLT_PREOP_CALLBACK_STATUS RansomWallPreDirCtrl(
    _Inout_ PFLT_CALLBACK_DATA    Data,
    _In_    PCFLT_RELATED_OBJECTS FltObjects,
    _Out_   PVOID*                CompletionContext
);

NTSTATUS RansomWallPortConnect(
    _In_  PFLT_PORT         ClientPort,
    _In_  PVOID             ServerPortCookie,
    _In_  PVOID             ConnectionContext,
    _In_  ULONG             SizeOfContext,
    _Out_ PVOID*            ConnectionPortCookie
);

VOID RansomWallPortDisconnect(
    _In_opt_ PVOID ConnectionCookie
);

NTSTATUS RansomWallMessageNotify(
    _In_  PVOID  PortCookie,
    _In_  PVOID  InputBuffer,
    _In_  ULONG  InputBufferLength,
    _Out_ PVOID  OutputBuffer,
    _In_  ULONG  OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
);

/* ══════════════════════════════════════════════════════════════════════════ */
/* FILTER REGISTRATION TABLE                                                   */
/*                                                                             */
/* Paper §IV-B: "Pre-operation, post-operation or both callback routines      */
/* can be registered for desired IRPs depending on whether monitoring is       */
/* required before or after the file operation."                               */
/* ══════════════════════════════════════════════════════════════════════════ */

static const FLT_OPERATION_REGISTRATION g_Callbacks[] = {

    /*
     * IRP_MJ_READ  (paper §III-D-3b: File Read Operations)
     * Pre-operation: capture PID, file path, size before read completes.
     */
    {
        IRP_MJ_READ,
        0,
        RansomWallPreRead,
        NULL    /* no post-op needed for read counting */
    },

    /*
     * IRP_MJ_WRITE  (paper §III-D-3c: File Write Operations +
     *                          §III-D-3g: Shannon Entropy of File Writes)
     * Both pre and post: pre captures metadata, post computes entropy
     * on written buffer.
     */
    {
        IRP_MJ_WRITE,
        0,
        RansomWallPreWrite,
        RansomWallPostWrite
    },

    /*
     * IRP_MJ_SET_INFORMATION covers:
     *   FileRenameInformation        -> §III-D-3d: rename .docx -> .encrypted
     *   FileDispositionInformation   -> §III-D-3e: file deletion
     * Pre-operation: captures source/dest paths before rename/delete.
     */
    {
        IRP_MJ_SET_INFORMATION,
        0,
        RansomWallPreSetInfo,
        NULL
    },

    /*
     * IRP_MJ_DIRECTORY  (paper §III-D-3a: Directory Info Queries)
     * Pre-operation: counts directory enumeration calls per PID.
     */
    {
        IRP_MJ_DIRECTORY_CONTROL,
        0,
        RansomWallPreDirCtrl,
        NULL
    },

    { IRP_MJ_OPERATION_END }
};

/*
 * Filter registration structure.
 * Paper §IV-B: "Filter Manager forwards I/O Request Packets generated
 * by file system operations to the registered filter drivers."
 */
static const FLT_REGISTRATION g_FilterRegistration = {
    sizeof(FLT_REGISTRATION),           /* Size */
    FLT_REGISTRATION_VERSION,           /* Version */
    0,                                  /* Flags */
    NULL,                               /* Context registrations */
    g_Callbacks,                        /* Operation callbacks */
    RansomWallUnload,                   /* FilterUnload */
    NULL,                               /* InstanceSetup */
    NULL,                               /* InstanceQueryTeardown */
    NULL,                               /* InstanceTeardownStart */
    NULL,                               /* InstanceTeardownComplete */
    NULL, NULL, NULL                    /* GenerateFileName etc. */
};

/* ══════════════════════════════════════════════════════════════════════════ */
/* UTILITY FUNCTIONS                                                           */
/* ══════════════════════════════════════════════════════════════════════════ */

/*
 * Extract the file extension from an NT file path.
 * e.g., \Device\HarddiskVolume3\Users\victim\docs\report.docx -> ".docx"
 */
static VOID
RwGetExtension(
    _In_  PUNICODE_STRING FilePath,
    _Out_ WCHAR           ExtBuf[16]
)
{
    USHORT i;
    RtlZeroMemory(ExtBuf, 16 * sizeof(WCHAR));

    if (!FilePath || FilePath->Length == 0) return;

    /* Scan backwards for the last '.' */
    for (i = FilePath->Length / sizeof(WCHAR); i > 0; i--) {
        WCHAR c = FilePath->Buffer[i - 1];
        if (c == L'\\' || c == L'/') break;   /* no extension found */
        if (c == L'.') {
            /* Copy extension up to 15 chars */
            USHORT extLen = FilePath->Length / sizeof(WCHAR) - i + 1;
            if (extLen > 15) extLen = 15;
            RtlCopyMemory(ExtBuf,
                          &FilePath->Buffer[i - 1],
                          extLen * sizeof(WCHAR));
            /* Lowercase */
            USHORT j;
            for (j = 0; j < extLen; j++) {
                if (ExtBuf[j] >= L'A' && ExtBuf[j] <= L'Z')
                    ExtBuf[j] += (L'a' - L'A');
            }
            return;
        }
    }
}

/*
 * Check if extension is in the ransomware target list.
 * Paper §III-A Stage 3: "Ransomware targets user data files with specific
 * extensions that varies with each family."
 */
static BOOLEAN
RwIsTargetExtension(_In_ const WCHAR* Ext)
{
    int i;
    for (i = 0; TARGET_EXTENSIONS[i] != NULL; i++) {
        if (_wcsicmp(Ext, TARGET_EXTENSIONS[i]) == 0)
            return TRUE;
    }
    return FALSE;
}

/*
 * Check if extension is a known ransomware-appended suffix.
 * Paper §III-D-3d: "Most Ransomware variants rename files to an extension
 * (non-data) which is characteristic of their family."
 */
static BOOLEAN
RwIsRansomExtension(_In_ const WCHAR* Ext)
{
    int i;
    for (i = 0; RANSOM_EXTENSIONS[i] != NULL; i++) {
        if (_wcsicmp(Ext, RANSOM_EXTENSIONS[i]) == 0)
            return TRUE;
    }
    return FALSE;
}

/*
 * Check if PID is in the whitelist (classified as benign by ML layer).
 * Paper §III-B-4: "If classified as Benign then files backed up ... are deleted."
 */
static BOOLEAN
RwIsPidWhitelisted(_In_ ULONG Pid)
{
    KIRQL  oldIrql;
    ULONG  i;
    BOOLEAN found = FALSE;

    KeAcquireSpinLock(&g_WhitelistLock, &oldIrql);
    for (i = 0; i < g_WhitelistCount; i++) {
        if (g_WhitelistPids[i] == Pid) {
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_WhitelistLock, oldIrql);
    return found;
}

/*
 * Get the file path from an FLT_CALLBACK_DATA.
 * Caller must free the returned UNICODE_STRING buffer with ExFreePoolWithTag.
 */
static NTSTATUS
RwGetFilePath(
    _In_  PFLT_CALLBACK_DATA    Data,
    _In_  PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PUNICODE_STRING*      OutPath
)
{
    NTSTATUS          status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;

    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo
    );
    if (!NT_SUCCESS(status)) return status;

    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInfo);
        return status;
    }

    /* Allocate and copy the full path string */
    PUNICODE_STRING pathStr = (PUNICODE_STRING)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(UNICODE_STRING) + nameInfo->Name.Length + sizeof(WCHAR),
        RANSOMWALL_TAG
    );
    if (!pathStr) {
        FltReleaseFileNameInformation(nameInfo);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    pathStr->Buffer = (PWCH)((PUCHAR)pathStr + sizeof(UNICODE_STRING));
    pathStr->MaximumLength = nameInfo->Name.Length + sizeof(WCHAR);
    RtlCopyUnicodeString(pathStr, &nameInfo->Name);
    pathStr->Buffer[nameInfo->Name.Length / sizeof(WCHAR)] = L'\0';

    FltReleaseFileNameInformation(nameInfo);
    *OutPath = pathStr;
    return STATUS_SUCCESS;
}

/*
 * Get the current process name from EPROCESS.
 * Returns the ImageFileName field (15 chars max from kernel).
 */
static VOID
RwGetProcessName(_Out_ WCHAR Name[260])
{
    PEPROCESS  process;
    PUCHAR     imageFileName;
    ULONG      i;

    RtlZeroMemory(Name, 260 * sizeof(WCHAR));
    process = PsGetCurrentProcess();
    if (!process) return;

    /* ImageFileName is at a well-known offset in EPROCESS.
     * Use PsGetProcessImageFileName if available (Vista+). */
    imageFileName = PsGetProcessImageFileName(process);
    if (imageFileName) {
        for (i = 0; i < 14 && imageFileName[i]; i++)
            Name[i] = (WCHAR)imageFileName[i];
    }
}

/*
 * Compute Shannon entropy of a byte buffer.
 * Paper §III-D-3g: "Entropy of data buffer in memory modified during file
 * write operation to a value around 8 indicates encryption possibility."
 *
 * Returns entropy * 100 as an integer to avoid floating-point in kernel.
 * e.g., 720 = 7.20 bits/byte
 */
static ULONG
RwComputeEntropyX100(
    _In_ PUCHAR Buffer,
    _In_ ULONG  Length
)
{
    ULONG freq[256] = {0};
    ULONG i, entropyX100 = 0;

    if (Length == 0) return 0;

    /* Frequency count */
    for (i = 0; i < Length; i++) freq[Buffer[i]]++;

    /*
     * entropy = -sum( p * log2(p) )
     * We use integer approximation: log2(x) ≈ computed via bit manipulation.
     * For accuracy we use the identity: log2(p) = log2(freq/N)
     *                                            = log2(freq) - log2(N)
     */
    for (i = 0; i < 256; i++) {
        if (freq[i] == 0) continue;

        /* p = freq[i] / Length, scaled by 1000 for integer arithmetic */
        ULONG p_scaled = (freq[i] * 1000) / Length;
        if (p_scaled == 0) continue;

        /*
         * log2 approximation using bit count:
         * Find position of highest set bit in freq[i] -> floor(log2(freq[i]))
         */
        ULONG val = freq[i], bits = 0;
        while (val > 1) { val >>= 1; bits++; }

        ULONG val_N = Length, bits_N = 0;
        val_N = Length;
        while (val_N > 1) { val_N >>= 1; bits_N++; }

        /* log2(freq[i]/N) ≈ bits - bits_N (integer approximation) */
        if (bits < bits_N) {
            /* p*log2(p) contributes positively to -entropy */
            ULONG contrib = p_scaled * (bits_N - bits) / 1000;
            entropyX100 += contrib;
        }
    }

    /* Scale to * 100 range (0-800 for 0.0 to 8.0 bits/byte) */
    return entropyX100;
}

/*
 * Check file magic bytes for fingerprint mismatch detection.
 * Paper §III-D-3f: "Modification of file signature in header of a user data
 * file to a new signature which does not match its extension."
 *
 * Read first 8 bytes from the file stream and compare against known magic.
 */
static BOOLEAN
RwCheckFingerprintMismatch(
    _In_ PFLT_CALLBACK_DATA    Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ const WCHAR*          Extension
)
{
    NTSTATUS       status;
    UCHAR          header[8] = {0};
    LARGE_INTEGER  offset = {0};
    ULONG          bytesRead = 0;

    /* Read the first 8 bytes at offset 0 */
    status = FltReadFile(
        FltObjects->Instance,
        FltObjects->FileObject,
        &offset,
        sizeof(header),
        header,
        FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
        &bytesRead,
        NULL,
        NULL
    );
    if (!NT_SUCCESS(status) || bytesRead < 4) return FALSE;

    /* Compare magic bytes against known signatures */
    if (_wcsicmp(Extension, L".pdf") == 0) {
        return (RtlCompareMemory(header, "%PDF", 4) != 4);
    }
    if (_wcsicmp(Extension, L".png") == 0) {
        static const UCHAR PNG_MAGIC[] = {0x89, 'P', 'N', 'G'};
        return (RtlCompareMemory(header, PNG_MAGIC, 4) != 4);
    }
    if (_wcsicmp(Extension, L".jpg") == 0 ||
        _wcsicmp(Extension, L".jpeg") == 0) {
        return !(header[0] == 0xFF && header[1] == 0xD8 && header[2] == 0xFF);
    }
    if (_wcsicmp(Extension, L".zip")  == 0 ||
        _wcsicmp(Extension, L".docx") == 0 ||
        _wcsicmp(Extension, L".xlsx") == 0 ||
        _wcsicmp(Extension, L".pptx") == 0) {
        return (RtlCompareMemory(header, "PK\x03\x04", 4) != 4);
    }
    if (_wcsicmp(Extension, L".exe") == 0 ||
        _wcsicmp(Extension, L".dll") == 0) {
        return (RtlCompareMemory(header, "MZ", 2) != 2);
    }
    if (_wcsicmp(Extension, L".gif") == 0) {
        return (RtlCompareMemory(header, "GIF", 3) != 3);
    }
    if (_wcsicmp(Extension, L".bmp") == 0) {
        return (RtlCompareMemory(header, "BM", 2) != 2);
    }
    return FALSE;
}

/* ══════════════════════════════════════════════════════════════════════════ */
/* MESSAGE SENDING TO USER-MODE                                                */
/*                                                                             */
/* Paper §IV-A: "IRP Filter registers with File System I/O Manager during     */
/* RansomWall initialization for receiving IRP messages. During file          */
/* operations, I/O Manager forwards generated IRP messages to the registered  */
/* IRP Filter. The IRP Filter forwards IRP messages ... to Dynamic and        */
/* Trap Layers for feature computation."                                       */
/* ══════════════════════════════════════════════════════════════════════════ */

static NTSTATUS
RwSendMessageToUserMode(_In_ PRANSOMWALL_IRP_MESSAGE Message)
{
    NTSTATUS   status;
    KIRQL      oldIrql;
    PFLT_PORT  clientPort;
    LARGE_INTEGER timeout;

    /* Get client port reference safely */
    KeAcquireSpinLock(&g_ClientPortLock, &oldIrql);
    clientPort = g_ClientPort;
    KeReleaseSpinLock(&g_ClientPortLock, oldIrql);

    if (!clientPort) {
        /* No user-mode client connected; drop message */
        InterlockedIncrement(&g_DroppedMessages);
        return STATUS_PORT_DISCONNECTED;
    }

    /* Non-blocking send with 0 timeout (don't stall the I/O path) */
    timeout.QuadPart = 0;
    status = FltSendMessage(
        g_FilterHandle,
        &clientPort,
        Message,
        sizeof(RANSOMWALL_IRP_MESSAGE),
        NULL,   /* no reply buffer */
        NULL,
        &timeout
    );

    if (status == STATUS_TIMEOUT) {
        /* User-mode is busy; drop to avoid blocking kernel I/O */
        InterlockedIncrement(&g_DroppedMessages);
        return STATUS_SUCCESS;
    }

    return status;
}

/*
 * Build and send a complete IRP message.
 * Fills in all fields and calls RwSendMessageToUserMode.
 */
static VOID
RwBuildAndSendMessage(
    _In_     PFLT_CALLBACK_DATA    Data,
    _In_     PCFLT_RELATED_OBJECTS FltObjects,
    _In_     RANSOMWALL_OP_TYPE    OpType,
    _In_opt_ PUNICODE_STRING       DestPath
)
{
    RANSOMWALL_IRP_MESSAGE  msg;
    PUNICODE_STRING         srcPath = NULL;
    NTSTATUS                status;

    /* Skip whitelisted (benign) processes */
    ULONG pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    if (RwIsPidWhitelisted(pid)) return;

    RtlZeroMemory(&msg, sizeof(msg));
    msg.MessageSize = sizeof(RANSOMWALL_IRP_MESSAGE);
    msg.Version     = 1;
    msg.ProcessId   = pid;
    msg.ThreadId    = (ULONG)(ULONG_PTR)PsGetCurrentThreadId();
    msg.Operation   = OpType;

    KeQuerySystemTime(&msg.Timestamp);
    RwGetProcessName(msg.ProcessName);

    /* Get source file path */
    status = RwGetFilePath(Data, FltObjects, &srcPath);
    if (NT_SUCCESS(status) && srcPath) {
        ULONG copyLen = srcPath->Length;
        if (copyLen > sizeof(msg.FilePath) - sizeof(WCHAR))
            copyLen = sizeof(msg.FilePath) - sizeof(WCHAR);
        RtlCopyMemory(msg.FilePath, srcPath->Buffer, copyLen);

        /* Extract extension */
        RwGetExtension(srcPath, (WCHAR*)msg.FileExtension);
        msg.IsTargetExtension = RwIsTargetExtension((WCHAR*)msg.FileExtension);

        ExFreePoolWithTag(srcPath, RANSOMWALL_TAG);
    }

    /* Get destination path for rename operations */
    if (DestPath && OpType == RW_OP_RENAME) {
        ULONG copyLen = DestPath->Length;
        if (copyLen > sizeof(msg.DestPath) - sizeof(WCHAR))
            copyLen = sizeof(msg.DestPath) - sizeof(WCHAR);
        RtlCopyMemory(msg.DestPath, DestPath->Buffer, copyLen);
        RwGetExtension(DestPath, (WCHAR*)msg.DestExtension);
        msg.IsRansomExtension = RwIsRansomExtension((WCHAR*)msg.DestExtension);
    }

    /* Get file size */
    if (FltObjects->FileObject) {
        LARGE_INTEGER fileSize = {0};
        status = FltQueryInformationFile(
            FltObjects->Instance,
            FltObjects->FileObject,
            &fileSize,
            sizeof(fileSize),
            FileEndOfFileInformation,
            NULL
        );
        if (NT_SUCCESS(status))
            msg.FileSize = (ULONG)fileSize.QuadPart;
    }

    InterlockedIncrement(&g_TotalIRPs);
    if (msg.IsTargetExtension || msg.IsRansomExtension)
        InterlockedIncrement(&g_SuspiciousIRPs);

    RwSendMessageToUserMode(&msg);
}

/* ══════════════════════════════════════════════════════════════════════════ */
/* IRP CALLBACK IMPLEMENTATIONS                                                */
/* ══════════════════════════════════════════════════════════════════════════ */

/*
 * PRE-READ callback
 * Paper §III-D-3b: "Contents of user data files are read before encrypting
 * them. Massive encryption generates extensive read operations on user data
 * files with target extensions that are tracked."
 */
FLT_PREOP_CALLBACK_STATUS
RansomWallPreRead(
    _Inout_ PFLT_CALLBACK_DATA    Data,
    _In_    PCFLT_RELATED_OBJECTS FltObjects,
    _Out_   PVOID*                CompletionContext
)
{
    UNREFERENCED_PARAMETER(CompletionContext);

    /* Only track reads on user data files (not paging, not MDL reads) */
    if (Data->Iopb->IrpFlags & IRP_PAGING_IO)   return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (Data->Iopb->IrpFlags & IRP_NOCACHE)       return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (!FltObjects->FileObject)                   return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (KeGetCurrentIrql() > PASSIVE_LEVEL)        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    /* Check extension - only track target data files */
    PUNICODE_STRING srcPath = NULL;
    NTSTATUS status = RwGetFilePath(Data, FltObjects, &srcPath);
    if (NT_SUCCESS(status) && srcPath) {
        WCHAR ext[16];
        RwGetExtension(srcPath, ext);
        if (RwIsTargetExtension(ext)) {
            RwBuildAndSendMessage(Data, FltObjects, RW_OP_READ, NULL);
        }
        ExFreePoolWithTag(srcPath, RANSOMWALL_TAG);
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/*
 * PRE-WRITE callback
 * Paper §III-D-3c: "Encrypted user data is written back to the file
 * generating huge write operations which are monitored."
 * Paper §III-D-3f: File Fingerprinting (magic byte check)
 */
FLT_PREOP_CALLBACK_STATUS
RansomWallPreWrite(
    _Inout_ PFLT_CALLBACK_DATA    Data,
    _In_    PCFLT_RELATED_OBJECTS FltObjects,
    _Out_   PVOID*                CompletionContext
)
{
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data->Iopb->IrpFlags & IRP_PAGING_IO)  return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (!FltObjects->FileObject)                return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (KeGetCurrentIrql() > PASSIVE_LEVEL)     return FLT_PREOP_SUCCESS_NO_CALLBACK;

    PUNICODE_STRING srcPath = NULL;
    NTSTATUS status = RwGetFilePath(Data, FltObjects, &srcPath);
    if (!NT_SUCCESS(status) || !srcPath) return FLT_PREOP_SUCCESS_WITH_CALLBACK;

    WCHAR ext[16];
    RwGetExtension(srcPath, ext);
    BOOLEAN isTarget = RwIsTargetExtension(ext);
    ExFreePoolWithTag(srcPath, RANSOMWALL_TAG);

    if (!isTarget) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    /* Pass context to post-write for entropy computation */
    *CompletionContext = (PVOID)(ULONG_PTR)1;
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

/*
 * POST-WRITE callback
 * Compute Shannon entropy on the written data buffer.
 * Paper §III-D-3g: "Entropy of data buffer in memory modified during file
 * write operation to a value around 8 indicates encryption possibility."
 */
FLT_POSTOP_CALLBACK_STATUS
RansomWallPostWrite(
    _Inout_ PFLT_CALLBACK_DATA       Data,
    _In_    PCFLT_RELATED_OBJECTS    FltObjects,
    _In_    PVOID                    CompletionContext,
    _In_    FLT_POST_OPERATION_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Flags & FLTFL_POST_OPERATION_DRAINING) return FLT_POSTOP_FINISHED_PROCESSING;
    if (!NT_SUCCESS(Data->IoStatus.Status))    return FLT_POSTOP_FINISHED_PROCESSING;

    /* Try to get the write buffer */
    PVOID buffer = NULL;
    ULONG bufLen = Data->Iopb->Parameters.Write.Length;

    if (bufLen < ENTROPY_MIN_FILE_SIZE) return FLT_POSTOP_FINISHED_PROCESSING;

    if (Data->Iopb->Parameters.Write.MdlAddress) {
        buffer = MmGetSystemAddressForMdlSafe(
            Data->Iopb->Parameters.Write.MdlAddress,
            NormalPagePriority | MdlMappingNoExecute
        );
    } else {
        buffer = Data->Iopb->Parameters.Write.WriteBuffer;
    }

    if (!buffer) return FLT_POSTOP_FINISHED_PROCESSING;

    /* Compute entropy */
    ULONG limit = (bufLen > 4096) ? 4096 : bufLen;   /* sample first 4KB */
    ULONG entropyX100 = RwComputeEntropyX100((PUCHAR)buffer, limit);

    /* Build write message, include entropy */
    RANSOMWALL_IRP_MESSAGE msg;
    RtlZeroMemory(&msg, sizeof(msg));
    msg.MessageSize  = sizeof(msg);
    msg.Version      = 1;
    msg.ProcessId    = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    msg.Operation    = (entropyX100 >= ENTROPY_THRESHOLD_X100) ?
                       RW_OP_ENTROPY_SPIKE : RW_OP_WRITE;
    msg.EntropyX100  = entropyX100;
    KeQuerySystemTime(&msg.Timestamp);
    RwGetProcessName(msg.ProcessName);

    PUNICODE_STRING srcPath = NULL;
    NTSTATUS status = RwGetFilePath(Data, FltObjects, &srcPath);
    if (NT_SUCCESS(status) && srcPath) {
        ULONG copyLen = srcPath->Length;
        if (copyLen > sizeof(msg.FilePath) - sizeof(WCHAR))
            copyLen = sizeof(msg.FilePath) - sizeof(WCHAR);
        RtlCopyMemory(msg.FilePath, srcPath->Buffer, copyLen);
        RwGetExtension(srcPath, (WCHAR*)msg.FileExtension);
        msg.IsTargetExtension = RwIsTargetExtension((WCHAR*)msg.FileExtension);

        /* Paper §III-D-3f: Fingerprint mismatch check */
        if (msg.IsTargetExtension) {
            msg.FingerprintMismatch = RwCheckFingerprintMismatch(
                Data, FltObjects, (WCHAR*)msg.FileExtension
            );
        }
        ExFreePoolWithTag(srcPath, RANSOMWALL_TAG);
    }

    if (msg.IsTargetExtension) {
        InterlockedIncrement(&g_TotalIRPs);
        InterlockedIncrement(&g_SuspiciousIRPs);
        RwSendMessageToUserMode(&msg);
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

/*
 * PRE-SET_INFORMATION callback
 * Handles both rename and delete operations.
 *
 * Paper §III-D-3d: "Most Ransomware variants rename files to an extension
 * (non-data) which is characteristic of their family after encrypting them.
 * This results in massive file rename operations."
 *
 * Paper §III-D-3e: "Some Ransomware families delete original files after
 * creating new encrypted files."
 */
FLT_PREOP_CALLBACK_STATUS
RansomWallPreSetInfo(
    _Inout_ PFLT_CALLBACK_DATA    Data,
    _In_    PCFLT_RELATED_OBJECTS FltObjects,
    _Out_   PVOID*                CompletionContext
)
{
    UNREFERENCED_PARAMETER(CompletionContext);

    if (KeGetCurrentIrql() > PASSIVE_LEVEL) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    FILE_INFORMATION_CLASS infoClass =
        Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

    if (infoClass == FileRenameInformation ||
        infoClass == FileRenameInformationEx) {

        /* --- RENAME operation --- */
        PFILE_RENAME_INFORMATION renameInfo =
            (PFILE_RENAME_INFORMATION)
            Data->Iopb->Parameters.SetFileInformation.InfoBuffer;

        if (!renameInfo) return FLT_PREOP_SUCCESS_NO_CALLBACK;

        /* Build dest path UNICODE_STRING from the rename info */
        UNICODE_STRING destStr;
        destStr.Buffer        = renameInfo->FileName;
        destStr.Length        = (USHORT)renameInfo->FileNameLength;
        destStr.MaximumLength = (USHORT)renameInfo->FileNameLength + sizeof(WCHAR);

        RwBuildAndSendMessage(Data, FltObjects, RW_OP_RENAME, &destStr);

    } else if (infoClass == FileDispositionInformation ||
               infoClass == FileDispositionInformationEx) {

        /* --- DELETE operation --- */
        PFILE_DISPOSITION_INFORMATION dispInfo =
            (PFILE_DISPOSITION_INFORMATION)
            Data->Iopb->Parameters.SetFileInformation.InfoBuffer;

        if (dispInfo && dispInfo->DeleteFile) {
            RwBuildAndSendMessage(Data, FltObjects, RW_OP_DELETE, NULL);
        }
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/*
 * PRE-DIRECTORY_CONTROL callback
 * Paper §III-D-3a: "To perform encryption, Ransomware first constructs list
 * of user data files having extensions targeted by its family. To form the
 * list it generates a large number of Directory Listing Queries."
 */
FLT_PREOP_CALLBACK_STATUS
RansomWallPreDirCtrl(
    _Inout_ PFLT_CALLBACK_DATA    Data,
    _In_    PCFLT_RELATED_OBJECTS FltObjects,
    _Out_   PVOID*                CompletionContext
)
{
    UNREFERENCED_PARAMETER(CompletionContext);

    if (KeGetCurrentIrql() > PASSIVE_LEVEL) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    /* Only track IRP_MN_QUERY_DIRECTORY */
    if (Data->Iopb->MinorFunction != IRP_MN_QUERY_DIRECTORY)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    RwBuildAndSendMessage(Data, FltObjects, RW_OP_DIR_QUERY, NULL);

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/* ══════════════════════════════════════════════════════════════════════════ */
/* COMMUNICATION PORT CALLBACKS                                                */
/*                                                                             */
/* The Python user-mode bridge connects to \RansomWallPort to receive IRP    */
/* events. It also sends control commands back (kill PID, whitelist, etc.).   */
/* ══════════════════════════════════════════════════════════════════════════ */

NTSTATUS
RansomWallPortConnect(
    _In_  PFLT_PORT  ClientPort,
    _In_  PVOID      ServerPortCookie,
    _In_  PVOID      ConnectionContext,
    _In_  ULONG      SizeOfContext,
    _Out_ PVOID*     ConnectionPortCookie
)
{
    KIRQL oldIrql;

    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);

    *ConnectionPortCookie = NULL;

    KeAcquireSpinLock(&g_ClientPortLock, &oldIrql);
    g_ClientPort = ClientPort;
    KeReleaseSpinLock(&g_ClientPortLock, oldIrql);

    KdPrint(("[RansomWall] User-mode client connected on port.\n"));
    return STATUS_SUCCESS;
}

VOID
RansomWallPortDisconnect(
    _In_opt_ PVOID ConnectionCookie
)
{
    KIRQL oldIrql;
    UNREFERENCED_PARAMETER(ConnectionCookie);

    KeAcquireSpinLock(&g_ClientPortLock, &oldIrql);
    g_ClientPort = NULL;
    KeReleaseSpinLock(&g_ClientPortLock, oldIrql);

    KdPrint(("[RansomWall] User-mode client disconnected.\n"));
}

/*
 * Handle control commands from user-mode Python bridge.
 * Paper §III-B-4: "If ML layer classifies as Ransomware, the process
 * is killed and files modified by it are restored."
 */
NTSTATUS
RansomWallMessageNotify(
    _In_  PVOID  PortCookie,
    _In_  PVOID  InputBuffer,
    _In_  ULONG  InputBufferLength,
    _Out_ PVOID  OutputBuffer,
    _In_  ULONG  OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
)
{
    NTSTATUS             status = STATUS_SUCCESS;
    PRANSOMWALL_COMMAND  cmd;
    KIRQL                oldIrql;

    UNREFERENCED_PARAMETER(PortCookie);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    *ReturnOutputBufferLength = 0;

    if (!InputBuffer || InputBufferLength < sizeof(RANSOMWALL_COMMAND))
        return STATUS_INVALID_PARAMETER;

    /* Validate input buffer is in user-mode address space */
    try {
        ProbeForRead(InputBuffer, InputBufferLength, sizeof(UCHAR));
    } except(EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    cmd = (PRANSOMWALL_COMMAND)InputBuffer;

    switch (cmd->Command) {

    case RW_CMD_KILL_PID:
        /*
         * Paper §III-B-4: "the process is killed"
         * Look up EPROCESS for the target PID and terminate.
         */
        {
            PEPROCESS targetProcess = NULL;
            status = PsLookupProcessByProcessId(
                (HANDLE)(ULONG_PTR)cmd->TargetPid,
                &targetProcess
            );
            if (NT_SUCCESS(status)) {
                HANDLE hProcess = NULL;
                status = ObOpenObjectByPointer(
                    targetProcess,
                    OBJ_KERNEL_HANDLE,
                    NULL,
                    PROCESS_TERMINATE,
                    *PsProcessType,
                    KernelMode,
                    &hProcess
                );
                if (NT_SUCCESS(status)) {
                    ZwTerminateProcess(hProcess, STATUS_ACCESS_DENIED);
                    ZwClose(hProcess);
                    KdPrint(("[RansomWall] Terminated PID=%lu\n",
                             cmd->TargetPid));
                }
                ObDereferenceObject(targetProcess);
            }
        }
        break;

    case RW_CMD_WHITELIST_PID:
        /* Paper §III-B-4: classified as Benign -> stop monitoring */
        KeAcquireSpinLock(&g_WhitelistLock, &oldIrql);
        if (g_WhitelistCount < MAX_WHITELIST_SIZE) {
            g_WhitelistPids[g_WhitelistCount++] = cmd->TargetPid;
            KdPrint(("[RansomWall] Whitelisted PID=%lu\n", cmd->TargetPid));
        }
        KeReleaseSpinLock(&g_WhitelistLock, oldIrql);
        break;

    case RW_CMD_STATUS:
        /* Return driver statistics */
        if (OutputBuffer && OutputBufferLength >= sizeof(ULONG) * 3) {
            PULONG out = (PULONG)OutputBuffer;
            out[0] = (ULONG)g_TotalIRPs;
            out[1] = (ULONG)g_SuspiciousIRPs;
            out[2] = (ULONG)g_DroppedMessages;
            *ReturnOutputBufferLength = sizeof(ULONG) * 3;
        }
        break;

    default:
        status = STATUS_INVALID_PARAMETER;
        break;
    }

    return status;
}

/* ══════════════════════════════════════════════════════════════════════════ */
/* DRIVER ENTRY / UNLOAD                                                       */
/* ══════════════════════════════════════════════════════════════════════════ */

/*
 * DriverEntry - called by the I/O Manager when the driver is loaded.
 * Registers the minifilter with Filter Manager and creates the
 * communication port for the user-mode Python bridge.
 */
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS          status;
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING    portName;
    PSECURITY_DESCRIPTOR  sd;

    UNREFERENCED_PARAMETER(RegistryPath);

    KdPrint(("[RansomWall] DriverEntry - initializing minifilter...\n"));

    /* Initialize spinlocks */
    KeInitializeSpinLock(&g_ClientPortLock);
    KeInitializeSpinLock(&g_WhitelistLock);

    /*
     * Paper §IV-B: "Filter Manager forwards I/O Request Packets generated
     * by file system operations to the registered filter drivers."
     *
     * Register the minifilter with the Filter Manager.
     */
    status = FltRegisterFilter(
        DriverObject,
        &g_FilterRegistration,
        &g_FilterHandle
    );
    if (!NT_SUCCESS(status)) {
        KdPrint(("[RansomWall] FltRegisterFilter failed: 0x%08X\n", status));
        return status;
    }

    /*
     * Create a communication port so the user-mode Python bridge
     * (kernel_bridge.py) can connect and receive IRP event messages.
     *
     * Security: only SYSTEM and Administrators can connect.
     */
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(g_FilterHandle);
        return status;
    }

    RtlInitUnicodeString(&portName, RANSOMWALL_PORT_NAME);
    InitializeObjectAttributes(
        &objAttr,
        &portName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        sd
    );

    status = FltCreateCommunicationPort(
        g_FilterHandle,
        &g_ServerPort,
        &objAttr,
        NULL,                       /* server port cookie */
        RansomWallPortConnect,
        RansomWallPortDisconnect,
        RansomWallMessageNotify,
        RANSOMWALL_MAX_CONNECTIONS
    );
    FltFreeSecurityDescriptor(sd);

    if (!NT_SUCCESS(status)) {
        KdPrint(("[RansomWall] FltCreateCommunicationPort failed: 0x%08X\n",
                 status));
        FltUnregisterFilter(g_FilterHandle);
        return status;
    }

    /* Start filtering - begin receiving IRP callbacks */
    status = FltStartFiltering(g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[RansomWall] FltStartFiltering failed: 0x%08X\n", status));
        FltCloseCommunicationPort(g_ServerPort);
        FltUnregisterFilter(g_FilterHandle);
        return status;
    }

    KdPrint(("[RansomWall] Minifilter registered. Port: %wZ\n", &portName));
    KdPrint(("[RansomWall] Altitude: %ls\n", RANSOMWALL_ALTITUDE));
    KdPrint(("[RansomWall] Monitoring: READ, WRITE, SET_INFO, DIR_QUERY\n"));

    return STATUS_SUCCESS;
}

/*
 * FilterUnload - called when the driver is being unloaded.
 * Paper §IV-B: clean teardown of Filter Manager registration.
 */
NTSTATUS
RansomWallUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Flags);

    KdPrint(("[RansomWall] Unloading. Total IRPs=%d, Suspicious=%d, Dropped=%d\n",
             g_TotalIRPs, g_SuspiciousIRPs, g_DroppedMessages));

    FltCloseCommunicationPort(g_ServerPort);
    FltUnregisterFilter(g_FilterHandle);
    return STATUS_SUCCESS;
}
