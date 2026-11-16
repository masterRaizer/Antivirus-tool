/*
 * SentinelDrv — драйвер телеметрии и защиты дескрипторов Sentinel (WDM, без minifilter).
 *
 * Что делает (docs/ARCHITECTURE_V2_KERNEL_SPEC.md):
 *   1. Устройство \Device\SentinelDrv (+ \DosDevices\SentinelDrv) с SDDL "только SYSTEM и Administrators".
 *   2. IOCTL: статус, список защищаемых PID (только LocalSystem), чтение событий.
 *   3. ObRegisterCallbacks (процессы и потоки, создание и дублирование дескрипторов): у посторонних процессов
 *      снимаются права завершения, записи памяти, создания потоков и приостановки для защищаемых PID.
 *      Запросы самой ОС (System, csrss, smss, lsass, services, wininit из System32) не изменяются.
 *   4. PsSetCreateProcessNotifyRoutineEx: асинхронная телеметрия старта/завершения процессов в кольцевой буфер.
 *      Драйвер никогда не блокирует создание процесса (Fail-Open): решения принимает служба в User-Mode.
 *
 * Требует флага компоновщика /INTEGRITYCHECK — без него ObRegisterCallbacks и PsSetCreateProcessNotifyRoutineEx
 * возвращают STATUS_ACCESS_DENIED.
 */
#include <ntifs.h>   /* ntddk.h + SeLocateProcessImageName */
#include <wdmsec.h>
#include "SentinelDrv.h"

C_ASSERT(sizeof(SENTINEL_STATUS) == 48);
C_ASSERT(sizeof(SENTINEL_PROTECTED_PIDS) == 264);
C_ASSERT(sizeof(SENTINEL_EVENT_BATCH) == 16);
C_ASSERT(sizeof(SENTINEL_PROCESS_EVENT) == 1576);
C_ASSERT(FIELD_OFFSET(SENTINEL_PROCESS_EVENT, ImagePath) == 32);
C_ASSERT(FIELD_OFFSET(SENTINEL_PROCESS_EVENT, CommandLine) == 552);

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE         0x0001
#endif
#ifndef PROCESS_CREATE_THREAD
#define PROCESS_CREATE_THREAD     0x0002
#endif
#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION      0x0008
#endif
#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE          0x0020
#endif
#ifndef PROCESS_SUSPEND_RESUME
#define PROCESS_SUSPEND_RESUME    0x0800
#endif
#ifndef THREAD_TERMINATE
#define THREAD_TERMINATE          0x0001
#endif
#ifndef THREAD_SUSPEND_RESUME
#define THREAD_SUSPEND_RESUME     0x0002
#endif
#ifndef THREAD_SET_CONTEXT
#define THREAD_SET_CONTEXT        0x0010
#endif

#define SENTINEL_PROCESS_STRIP_MASK \
    (PROCESS_TERMINATE | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_SUSPEND_RESUME)
#define SENTINEL_THREAD_STRIP_MASK  (THREAD_TERMINATE | THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT)

#define SENTINEL_OB_ALTITUDE        L"385201.7341"
#define SENTINEL_DEVICE_SDDL        L"D:P(A;;GA;;;SY)(A;;GA;;;BA)"

/* Не задокументирована в заголовках, но экспортируется ядром начиная с Windows XP: 15-символьное имя образа. */
NTKERNELAPI PCHAR NTAPI PsGetProcessImageFileName(_In_ PEPROCESS Process);

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD SentinelUnload;
_Dispatch_type_(IRP_MJ_CREATE) _Dispatch_type_(IRP_MJ_CLOSE) DRIVER_DISPATCH SentinelCreateClose;
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL) DRIVER_DISPATCH SentinelDeviceControl;

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, SentinelUnload)
#pragma alloc_text(PAGE, SentinelCreateClose)
#endif

/* Класс устройства для IoCreateDeviceSecure (уникален для Sentinel). */
static const GUID SentinelDeviceClassGuid =
    { 0x6f1d3b2a, 0x4c1e, 0x4b8a, { 0x9e, 0x51, 0x2a, 0x7c, 0x53, 0x41, 0x8a, 0x53 } };

typedef struct _SENTINEL_GLOBALS {
    PDEVICE_OBJECT DeviceObject;
    BOOLEAN SymlinkCreated;
    BOOLEAN ProcessNotifyRegistered;
    PVOID ObRegistrationHandle;

    /* Список защищаемых PID: читается в каждом Ob-колбэке (shared), меняется по IOCTL и при выходе процесса. */
    EX_SPIN_LOCK PidLock;
    ULONG ProtectedPidCount;
    HANDLE ProtectedPids[SENTINEL_MAX_PROTECTED_PIDS];

    /* Кольцевой буфер событий. */
    KSPIN_LOCK RingLock;
    ULONG RingHead;
    ULONG RingCount;

    volatile LONG64 ProcessEventsTotal;
    volatile LONG64 EventsDropped;
    volatile LONG64 HandleStripsTotal;
} SENTINEL_GLOBALS;

static SENTINEL_GLOBALS g_Sentinel;

/* Неподкачиваемые данные образа: ~400 КБ, без выделений пула в горячем пути. */
static SENTINEL_PROCESS_EVENT g_Ring[SENTINEL_EVENT_RING_CAPACITY];

/* ---- Список защищаемых PID ------------------------------------------------------------------------- */

static BOOLEAN SentinelIsProtectedPid(_In_ HANDLE ProcessId)
{
    BOOLEAN found = FALSE;
    KIRQL irql = ExAcquireSpinLockShared(&g_Sentinel.PidLock);
    for (ULONG i = 0; i < g_Sentinel.ProtectedPidCount; i++) {
        if (g_Sentinel.ProtectedPids[i] == ProcessId) {
            found = TRUE;
            break;
        }
    }
    ExReleaseSpinLockShared(&g_Sentinel.PidLock, irql);
    return found;
}

static ULONG SentinelProtectedPidCount(VOID)
{
    KIRQL irql = ExAcquireSpinLockShared(&g_Sentinel.PidLock);
    ULONG count = g_Sentinel.ProtectedPidCount;
    ExReleaseSpinLockShared(&g_Sentinel.PidLock, irql);
    return count;
}

static VOID SentinelReplaceProtectedPids(_In_reads_(Count) const ULONG* Pids, _In_ ULONG Count)
{
    HANDLE accepted[SENTINEL_MAX_PROTECTED_PIDS];
    ULONG acceptedCount = 0;

    /* Копия собирается вне блокировки: PID 0 и 4 (Idle/System) не защищаются, повторы отбрасываются. */
    for (ULONG i = 0; i < Count && acceptedCount < SENTINEL_MAX_PROTECTED_PIDS; i++) {
        HANDLE pid = ULongToHandle(Pids[i]);
        BOOLEAN duplicate = FALSE;
        if (Pids[i] <= 4) {
            continue;
        }
        for (ULONG j = 0; j < acceptedCount; j++) {
            if (accepted[j] == pid) {
                duplicate = TRUE;
                break;
            }
        }
        if (!duplicate) {
            accepted[acceptedCount++] = pid;
        }
    }

    KIRQL irql = ExAcquireSpinLockExclusive(&g_Sentinel.PidLock);
    RtlZeroMemory(g_Sentinel.ProtectedPids, sizeof(g_Sentinel.ProtectedPids));
    for (ULONG i = 0; i < acceptedCount; i++) {
        g_Sentinel.ProtectedPids[i] = accepted[i];
    }
    g_Sentinel.ProtectedPidCount = acceptedCount;
    ExReleaseSpinLockExclusive(&g_Sentinel.PidLock, irql);
}

/* Завершившийся процесс убирается из списка, чтобы повторно выданный PID не унаследовал защиту. */
static BOOLEAN SentinelForgetPid(_In_ HANDLE ProcessId)
{
    BOOLEAN removed = FALSE;
    KIRQL irql = ExAcquireSpinLockExclusive(&g_Sentinel.PidLock);
    for (ULONG i = 0; i < g_Sentinel.ProtectedPidCount; i++) {
        if (g_Sentinel.ProtectedPids[i] == ProcessId) {
            g_Sentinel.ProtectedPidCount--;
            g_Sentinel.ProtectedPids[i] = g_Sentinel.ProtectedPids[g_Sentinel.ProtectedPidCount];
            g_Sentinel.ProtectedPids[g_Sentinel.ProtectedPidCount] = NULL;
            removed = TRUE;
            break;
        }
    }
    ExReleaseSpinLockExclusive(&g_Sentinel.PidLock, irql);
    return removed;
}

/* ---- Доверенные системные инициаторы ---------------------------------------------------------------- */

static BOOLEAN SentinelAsciiEqualsIgnoreCase(_In_z_ const char* Left, _In_z_ const char* Right)
{
    while (*Left != '\0' && *Right != '\0') {
        char a = *Left++;
        char b = *Right++;
        if (a >= 'A' && a <= 'Z') {
            a = (char)(a - 'A' + 'a');
        }
        if (b >= 'A' && b <= 'Z') {
            b = (char)(b - 'A' + 'a');
        }
        if (a != b) {
            return FALSE;
        }
    }
    return *Left == *Right;
}

static BOOLEAN SentinelIsInSystem32(_In_ PCUNICODE_STRING Path)
{
    static const WCHAR Marker[] = L"\\WINDOWS\\SYSTEM32\\";
    const USHORT markerChars = (USHORT)(sizeof(Marker) / sizeof(WCHAR) - 1);
    const USHORT pathChars = (USHORT)(Path->Length / sizeof(WCHAR));

    if (Path->Buffer == NULL || pathChars < markerChars) {
        return FALSE;
    }

    for (USHORT start = 0; start + markerChars <= pathChars; start++) {
        USHORT k = 0;
        while (k < markerChars && RtlUpcaseUnicodeChar(Path->Buffer[start + k]) == Marker[k]) {
            k++;
        }
        if (k == markerChars) {
            return TRUE;
        }
    }
    return FALSE;
}

/*
 * Запросы самой ОС не изменяются (иначе возможны взаимоблокировки и отказы служб). Имя образа сверяется с белым
 * списком, а на PASSIVE_LEVEL дополнительно проверяется, что образ лежит в \Windows\System32\ — так маскировка
 * под csrss.exe из другого каталога иммунитета не получает (зеркало CriticalProcessGuard в User-Mode).
 */
static BOOLEAN SentinelIsTrustedSystemCaller(_In_ HANDLE CallerPid)
{
    static const char* const TrustedNames[] = { "csrss.exe", "smss.exe", "lsass.exe", "services.exe", "wininit.exe" };
    PEPROCESS caller;
    const char* name;
    BOOLEAN nameMatches = FALSE;

    if (CallerPid == ULongToHandle(4)) {
        return TRUE; /* System */
    }

    caller = PsGetCurrentProcess();
    name = PsGetProcessImageFileName(caller);
    if (name == NULL) {
        return FALSE;
    }

    for (ULONG i = 0; i < RTL_NUMBER_OF(TrustedNames); i++) {
        if (SentinelAsciiEqualsIgnoreCase(name, TrustedNames[i])) {
            nameMatches = TRUE;
            break;
        }
    }

    if (!nameMatches) {
        return FALSE;
    }

    if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
        PUNICODE_STRING imagePath = NULL;
        BOOLEAN inSystem32 = FALSE;
        if (NT_SUCCESS(SeLocateProcessImageName(caller, &imagePath)) && imagePath != NULL) {
            inSystem32 = SentinelIsInSystem32(imagePath);
            ExFreePool(imagePath);
        }
        return inSystem32;
    }

    /* На APC_LEVEL путь получить нельзя — решение по имени (эти процессы и так защищены ОС как PPL). */
    return TRUE;
}

/* ---- Ob-колбэки ------------------------------------------------------------------------------------- */

static VOID SentinelStripAccess(_Inout_ POB_PRE_OPERATION_INFORMATION Info, _In_ HANDLE TargetPid, _In_ ACCESS_MASK Mask)
{
    HANDLE callerPid = PsGetCurrentProcessId();
    PACCESS_MASK desired;

    if (callerPid == TargetPid || !SentinelIsProtectedPid(TargetPid)) {
        return;
    }

    /* Защищённые процессы (служба/приложение Sentinel и ядро ОС) друг друга не ограничивают. */
    if (SentinelIsProtectedPid(callerPid) || SentinelIsTrustedSystemCaller(callerPid)) {
        return;
    }

    desired = (Info->Operation == OB_OPERATION_HANDLE_CREATE)
        ? &Info->Parameters->CreateHandleInformation.DesiredAccess
        : &Info->Parameters->DuplicateHandleInformation.DesiredAccess;

    if ((*desired & Mask) != 0) {
        *desired &= ~Mask;
        InterlockedIncrement64(&g_Sentinel.HandleStripsTotal);
    }
}

static OB_PREOP_CALLBACK_STATUS SentinelPreProcessHandle(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION Info)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (!Info->KernelHandle) {
        SentinelStripAccess(Info, PsGetProcessId((PEPROCESS)Info->Object), SENTINEL_PROCESS_STRIP_MASK);
    }
    return OB_PREOP_SUCCESS;
}

static OB_PREOP_CALLBACK_STATUS SentinelPreThreadHandle(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION Info)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (!Info->KernelHandle) {
        SentinelStripAccess(Info, PsGetThreadProcessId((PETHREAD)Info->Object), SENTINEL_THREAD_STRIP_MASK);
    }
    return OB_PREOP_SUCCESS;
}

/* ---- Телеметрия процессов ---------------------------------------------------------------------------- */

static VOID SentinelCopyString(
    _In_opt_ PCUNICODE_STRING Source,
    _Out_writes_(Capacity) WCHAR* Destination,
    _In_ ULONG Capacity,
    _Out_ USHORT* Length,
    _In_ ULONG TruncatedFlag,
    _Inout_ ULONG* Flags)
{
    ULONG chars;

    *Length = 0;
    if (Source == NULL || Source->Buffer == NULL || Source->Length == 0) {
        return;
    }

    chars = Source->Length / sizeof(WCHAR);
    if (chars > Capacity) {
        chars = Capacity;
        *Flags |= TruncatedFlag;
    }

    RtlCopyMemory(Destination, Source->Buffer, chars * sizeof(WCHAR));
    *Length = (USHORT)chars;
}

static VOID SentinelPushEvent(_In_ const SENTINEL_PROCESS_EVENT* Event)
{
    KIRQL irql;
    ULONG index;

    KeAcquireSpinLock(&g_Sentinel.RingLock, &irql);
    if (g_Sentinel.RingCount == SENTINEL_EVENT_RING_CAPACITY) {
        /* Служба не успевает забирать события — вытесняется самое старое. */
        g_Sentinel.RingHead = (g_Sentinel.RingHead + 1) % SENTINEL_EVENT_RING_CAPACITY;
        g_Sentinel.RingCount--;
        InterlockedIncrement64(&g_Sentinel.EventsDropped);
    }
    index = (g_Sentinel.RingHead + g_Sentinel.RingCount) % SENTINEL_EVENT_RING_CAPACITY;
    RtlCopyMemory(&g_Ring[index], Event, sizeof(*Event));
    g_Sentinel.RingCount++;
    KeReleaseSpinLock(&g_Sentinel.RingLock, irql);

    InterlockedIncrement64(&g_Sentinel.ProcessEventsTotal);
}

static VOID SentinelProcessNotify(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    SENTINEL_PROCESS_EVENT event;
    LARGE_INTEGER now;

    UNREFERENCED_PARAMETER(Process);

    /* Колбэк вызывается на PASSIVE_LEVEL; строки CreateInfo могут лежать в подкачиваемой памяти, поэтому
       событие собирается здесь, а под спин-блокировку копируется уже готовая структура. */
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;
    }

    RtlZeroMemory(&event, sizeof(event));
    KeQuerySystemTimePrecise(&now);
    event.ProcessId = HandleToULong(ProcessId);
    event.TimestampUtc = now.QuadPart;

    if (CreateInfo != NULL) {
        event.Kind = SENTINEL_EVENT_PROCESS_CREATE;
        event.ParentProcessId = HandleToULong(CreateInfo->ParentProcessId);
        SentinelCopyString(CreateInfo->ImageFileName, event.ImagePath, SENTINEL_IMAGE_PATH_CHARS,
            &event.ImagePathLength, SENTINEL_EVENT_IMAGE_TRUNCATED, &event.Flags);
        SentinelCopyString(CreateInfo->CommandLine, event.CommandLine, SENTINEL_COMMAND_LINE_CHARS,
            &event.CommandLineLength, SENTINEL_EVENT_COMMAND_TRUNCATED, &event.Flags);
        /* Fail-Open: CreateInfo->CreationStatus не изменяется — запуск никогда не блокируется драйвером. */
    } else {
        event.Kind = SENTINEL_EVENT_PROCESS_EXIT;
        if (SentinelForgetPid(ProcessId)) {
            event.Flags |= SENTINEL_EVENT_WAS_PROTECTED;
        }
    }

    SentinelPushEvent(&event);
}

static ULONG_PTR SentinelDrainEvents(_Out_writes_bytes_(OutputLength) PVOID Buffer, _In_ ULONG OutputLength)
{
    PSENTINEL_EVENT_BATCH batch = (PSENTINEL_EVENT_BATCH)Buffer;
    PSENTINEL_PROCESS_EVENT out = (PSENTINEL_PROCESS_EVENT)((PUCHAR)Buffer + sizeof(SENTINEL_EVENT_BATCH));
    ULONG capacity = (OutputLength - (ULONG)sizeof(SENTINEL_EVENT_BATCH)) / (ULONG)sizeof(SENTINEL_PROCESS_EVENT);
    ULONG copied = 0;
    ULONG remaining;
    KIRQL irql;

    /* Системный буфер METHOD_BUFFERED лежит в неподкачиваемом пуле — копировать под спин-блокировкой безопасно. */
    KeAcquireSpinLock(&g_Sentinel.RingLock, &irql);
    while (copied < capacity && g_Sentinel.RingCount > 0) {
        RtlCopyMemory(&out[copied], &g_Ring[g_Sentinel.RingHead], sizeof(SENTINEL_PROCESS_EVENT));
        g_Sentinel.RingHead = (g_Sentinel.RingHead + 1) % SENTINEL_EVENT_RING_CAPACITY;
        g_Sentinel.RingCount--;
        copied++;
    }
    remaining = g_Sentinel.RingCount;
    KeReleaseSpinLock(&g_Sentinel.RingLock, irql);

    batch->ProtocolVersion = SENTINEL_PROTOCOL_VERSION;
    batch->Count = copied;
    batch->Remaining = remaining;
    batch->Reserved = 0;
    return sizeof(SENTINEL_EVENT_BATCH) + (ULONG_PTR)copied * sizeof(SENTINEL_PROCESS_EVENT);
}

static VOID SentinelFillStatus(_Out_ PSENTINEL_STATUS Status)
{
    KIRQL irql;

    RtlZeroMemory(Status, sizeof(*Status));
    Status->ProtocolVersion = SENTINEL_PROTOCOL_VERSION;
    Status->DriverVersion = SENTINEL_DRIVER_VERSION;
    Status->Flags = (g_Sentinel.ObRegistrationHandle != NULL ? SENTINEL_STATUS_OB_CALLBACKS : 0u)
        | (g_Sentinel.ProcessNotifyRegistered ? SENTINEL_STATUS_PROCESS_NOTIFY : 0u);
    Status->ProtectedPidCount = SentinelProtectedPidCount();
    Status->ProcessEventsTotal = (unsigned long long)InterlockedCompareExchange64(&g_Sentinel.ProcessEventsTotal, 0, 0);
    Status->EventsDropped = (unsigned long long)InterlockedCompareExchange64(&g_Sentinel.EventsDropped, 0, 0);
    Status->HandleStripsTotal = (unsigned long long)InterlockedCompareExchange64(&g_Sentinel.HandleStripsTotal, 0, 0);

    KeAcquireSpinLock(&g_Sentinel.RingLock, &irql);
    Status->EventsQueued = g_Sentinel.RingCount;
    KeReleaseSpinLock(&g_Sentinel.RingLock, irql);
}

/* ---- Диспетчеризация IRP ------------------------------------------------------------------------------ */

static NTSTATUS SentinelComplete(_Inout_ PIRP Irp, _In_ NTSTATUS Status, _In_ ULONG_PTR Information)
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

NTSTATUS SentinelCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PAGED_CODE();

    /* Открыть устройство могут только SYSTEM и Administrators — это обеспечивает SDDL IoCreateDeviceSecure. */
    return SentinelComplete(Irp, STATUS_SUCCESS, 0);
}

NTSTATUS SentinelDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG inputLength = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outputLength = stack->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return SentinelComplete(Irp, STATUS_INVALID_DEVICE_STATE, 0);
    }

    switch (code) {
    case IOCTL_SENTINEL_GET_STATUS:
        if (buffer == NULL || outputLength < sizeof(SENTINEL_STATUS)) {
            return SentinelComplete(Irp, STATUS_BUFFER_TOO_SMALL, 0);
        }
        SentinelFillStatus((PSENTINEL_STATUS)buffer);
        return SentinelComplete(Irp, STATUS_SUCCESS, sizeof(SENTINEL_STATUS));

    case IOCTL_SENTINEL_SET_PROTECTED_PIDS: {
        PSENTINEL_PROTECTED_PIDS request = (PSENTINEL_PROTECTED_PIDS)buffer;
        const ULONG header = (ULONG)FIELD_OFFSET(SENTINEL_PROTECTED_PIDS, Pids);

        /* Менять список может только служба (LocalSystem обладает SeTcbPrivilege); администратор — только читать. */
        if (Irp->RequestorMode != KernelMode
            && !SeSinglePrivilegeCheck(RtlConvertLongToLuid(SE_TCB_PRIVILEGE), Irp->RequestorMode)) {
            return SentinelComplete(Irp, STATUS_PRIVILEGE_NOT_HELD, 0);
        }
        if (request == NULL || inputLength < header) {
            return SentinelComplete(Irp, STATUS_BUFFER_TOO_SMALL, 0);
        }
        if (request->ProtocolVersion != SENTINEL_PROTOCOL_VERSION) {
            return SentinelComplete(Irp, STATUS_REVISION_MISMATCH, 0);
        }
        if (request->Count > SENTINEL_MAX_PROTECTED_PIDS || inputLength < header + request->Count * (ULONG)sizeof(ULONG)) {
            return SentinelComplete(Irp, STATUS_INVALID_PARAMETER, 0);
        }
        SentinelReplaceProtectedPids(request->Pids, request->Count);
        return SentinelComplete(Irp, STATUS_SUCCESS, 0);
    }

    case IOCTL_SENTINEL_READ_EVENTS:
        if (buffer == NULL || outputLength < sizeof(SENTINEL_EVENT_BATCH)) {
            return SentinelComplete(Irp, STATUS_BUFFER_TOO_SMALL, 0);
        }
        return SentinelComplete(Irp, STATUS_SUCCESS, SentinelDrainEvents(buffer, outputLength));

    default:
        return SentinelComplete(Irp, STATUS_INVALID_DEVICE_REQUEST, 0);
    }
}

/* ---- Загрузка и выгрузка ------------------------------------------------------------------------------ */

static NTSTATUS SentinelRegisterObCallbacks(VOID)
{
    OB_OPERATION_REGISTRATION operations[2];
    OB_CALLBACK_REGISTRATION registration;

    RtlZeroMemory(operations, sizeof(operations));
    RtlZeroMemory(&registration, sizeof(registration));

    operations[0].ObjectType = PsProcessType;
    operations[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operations[0].PreOperation = SentinelPreProcessHandle;

    operations[1].ObjectType = PsThreadType;
    operations[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operations[1].PreOperation = SentinelPreThreadHandle;

    registration.Version = OB_FLT_REGISTRATION_VERSION;
    registration.OperationRegistrationCount = (USHORT)RTL_NUMBER_OF(operations);
    RtlInitUnicodeString(&registration.Altitude, SENTINEL_OB_ALTITUDE);
    registration.RegistrationContext = NULL;
    registration.OperationRegistration = operations;

    return ObRegisterCallbacks(&registration, &g_Sentinel.ObRegistrationHandle);
}

VOID SentinelUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symlink = RTL_CONSTANT_STRING(SENTINEL_SYMLINK_NAME);

    UNREFERENCED_PARAMETER(DriverObject);
    PAGED_CODE();

    /* Сначала снимаются колбэки (система дожидается завершения выполняющихся), затем устройство. */
    if (g_Sentinel.ObRegistrationHandle != NULL) {
        ObUnRegisterCallbacks(g_Sentinel.ObRegistrationHandle);
        g_Sentinel.ObRegistrationHandle = NULL;
    }
    if (g_Sentinel.ProcessNotifyRegistered) {
        PsSetCreateProcessNotifyRoutineEx(SentinelProcessNotify, TRUE);
        g_Sentinel.ProcessNotifyRegistered = FALSE;
    }
    if (g_Sentinel.SymlinkCreated) {
        IoDeleteSymbolicLink(&symlink);
        g_Sentinel.SymlinkCreated = FALSE;
    }
    if (g_Sentinel.DeviceObject != NULL) {
        IoDeleteDevice(g_Sentinel.DeviceObject);
        g_Sentinel.DeviceObject = NULL;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "SentinelDrv: unloaded\n");
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(SENTINEL_DEVICE_NAME);
    UNICODE_STRING symlink = RTL_CONSTANT_STRING(SENTINEL_SYMLINK_NAME);
    UNICODE_STRING sddl = RTL_CONSTANT_STRING(SENTINEL_DEVICE_SDDL);
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    RtlZeroMemory(&g_Sentinel, sizeof(g_Sentinel));
    KeInitializeSpinLock(&g_Sentinel.RingLock);
    g_Sentinel.PidLock = 0;

    DriverObject->DriverUnload = SentinelUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = SentinelCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = SentinelCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = SentinelDeviceControl;

    status = IoCreateDeviceSecure(DriverObject, 0, &deviceName, SENTINEL_DEVICE_TYPE, FILE_DEVICE_SECURE_OPEN, FALSE,
        &sddl, &SentinelDeviceClassGuid, &g_Sentinel.DeviceObject);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "SentinelDrv: IoCreateDeviceSecure 0x%08X\n", status);
        return status;
    }

    status = IoCreateSymbolicLink(&symlink, &deviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "SentinelDrv: IoCreateSymbolicLink 0x%08X\n", status);
        SentinelUnload(DriverObject);
        return status;
    }
    g_Sentinel.SymlinkCreated = TRUE;

    /* Телеметрия и защита дескрипторов независимы: отказ одной подсистемы не мешает другой (флаги — в статусе). */
    status = PsSetCreateProcessNotifyRoutineEx(SentinelProcessNotify, FALSE);
    if (NT_SUCCESS(status)) {
        g_Sentinel.ProcessNotifyRegistered = TRUE;
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "SentinelDrv: PsSetCreateProcessNotifyRoutineEx 0x%08X (missing /INTEGRITYCHECK?)\n", status);
    }

    status = SentinelRegisterObCallbacks();
    if (!NT_SUCCESS(status)) {
        g_Sentinel.ObRegistrationHandle = NULL;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "SentinelDrv: ObRegisterCallbacks 0x%08X\n", status);
    }

    if (!g_Sentinel.ProcessNotifyRegistered && g_Sentinel.ObRegistrationHandle == NULL) {
        SentinelUnload(DriverObject);
        return STATUS_ACCESS_DENIED; /* ни одна подсистема не зарегистрирована — загружаться незачем */
    }

    g_Sentinel.DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "SentinelDrv: loaded, protocol %u\n", SENTINEL_PROTOCOL_VERSION);
    return STATUS_SUCCESS;
}
