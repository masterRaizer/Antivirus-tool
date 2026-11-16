/*
 * SentinelDrv — драйвер телеметрии и защиты дескрипторов Sentinel (v1.3.0).
 *
 * Протокол Ring 0 <-> Ring 3 (docs/ARCHITECTURE_V2_KERNEL_SPEC.md, раздел 2). Этот заголовок — единственный
 * источник имён, кодов IOCTL и раскладки структур; C#-сторона (src/Sentinel.Core/Kernel/KernelProtocol.cs)
 * повторяет их байт в байт, а тесты xUnit проверяют размеры и смещения.
 *
 * Все структуры упакованы по 1 байту и содержат только типы фиксированного размера, поэтому раскладка
 * одинакова для x64-драйвера и любой разрядности клиента.
 */
#pragma once

#define SENTINEL_PROTOCOL_VERSION      1u

/* Версия драйвера: старший байт — major, затем minor и patch (1.3.0 -> 0x00010300). */
#define SENTINEL_DRIVER_VERSION_MAJOR  1u
#define SENTINEL_DRIVER_VERSION_MINOR  3u
#define SENTINEL_DRIVER_VERSION_PATCH  0u
#define SENTINEL_DRIVER_VERSION \
    ((SENTINEL_DRIVER_VERSION_MAJOR << 16) | (SENTINEL_DRIVER_VERSION_MINOR << 8) | SENTINEL_DRIVER_VERSION_PATCH)

#define SENTINEL_DEVICE_NAME           L"\\Device\\SentinelDrv"
#define SENTINEL_SYMLINK_NAME          L"\\DosDevices\\SentinelDrv"
/* Из пользовательского режима: \\.\SentinelDrv */

/* Тип устройства из диапазона производителя (0x8000-0xFFFF). */
#define SENTINEL_DEVICE_TYPE           0x8A53u

#define SENTINEL_CTL_CODE(function, access) \
    (((SENTINEL_DEVICE_TYPE) << 16) | ((access) << 14) | ((function) << 2) | 0u /* METHOD_BUFFERED */)

#define SENTINEL_FILE_READ_DATA        0x0001u
#define SENTINEL_FILE_WRITE_DATA       0x0002u

/* 0x8A536000: статус драйвера (выход SENTINEL_STATUS). */
#define IOCTL_SENTINEL_GET_STATUS          SENTINEL_CTL_CODE(0x800u, SENTINEL_FILE_READ_DATA)
/* 0x8A53A004: заменить список защищаемых PID (вход SENTINEL_PROTECTED_PIDS). Только LocalSystem (SeTcbPrivilege). */
#define IOCTL_SENTINEL_SET_PROTECTED_PIDS  SENTINEL_CTL_CODE(0x801u, SENTINEL_FILE_WRITE_DATA)
/* 0x8A536008: забрать события из кольцевого буфера (выход SENTINEL_EVENT_BATCH + N * SENTINEL_PROCESS_EVENT). */
#define IOCTL_SENTINEL_READ_EVENTS         SENTINEL_CTL_CODE(0x802u, SENTINEL_FILE_READ_DATA)

#define SENTINEL_MAX_PROTECTED_PIDS    64u
#define SENTINEL_IMAGE_PATH_CHARS      260u
#define SENTINEL_COMMAND_LINE_CHARS    512u
#define SENTINEL_EVENT_RING_CAPACITY   256u

/* Флаги SENTINEL_STATUS.Flags. */
#define SENTINEL_STATUS_OB_CALLBACKS       0x00000001u
#define SENTINEL_STATUS_PROCESS_NOTIFY     0x00000002u

/* Виды событий SENTINEL_PROCESS_EVENT.Kind. */
#define SENTINEL_EVENT_PROCESS_CREATE      1u
#define SENTINEL_EVENT_PROCESS_EXIT        2u

/* Флаги SENTINEL_PROCESS_EVENT.Flags. */
#define SENTINEL_EVENT_IMAGE_TRUNCATED     0x00000001u
#define SENTINEL_EVENT_COMMAND_TRUNCATED   0x00000002u
#define SENTINEL_EVENT_WAS_PROTECTED       0x00000004u

#pragma pack(push, 1)

/* 48 байт. */
typedef struct _SENTINEL_STATUS {
    unsigned long ProtocolVersion;
    unsigned long DriverVersion;
    unsigned long Flags;
    unsigned long ProtectedPidCount;
    unsigned long long ProcessEventsTotal;
    unsigned long long EventsDropped;
    unsigned long long HandleStripsTotal;
    unsigned long EventsQueued;
    unsigned long Reserved;
} SENTINEL_STATUS, *PSENTINEL_STATUS;

/* 8 + 4 * 64 = 264 байта. Count — число действительных элементов Pids. */
typedef struct _SENTINEL_PROTECTED_PIDS {
    unsigned long ProtocolVersion;
    unsigned long Count;
    unsigned long Pids[SENTINEL_MAX_PROTECTED_PIDS];
} SENTINEL_PROTECTED_PIDS, *PSENTINEL_PROTECTED_PIDS;

/* 16 байт; за заголовком следуют Count событий. */
typedef struct _SENTINEL_EVENT_BATCH {
    unsigned long ProtocolVersion;
    unsigned long Count;
    unsigned long Remaining;
    unsigned long Reserved;
} SENTINEL_EVENT_BATCH, *PSENTINEL_EVENT_BATCH;

/* 32 + 520 + 1024 = 1576 байт (ImagePath — смещение 32, CommandLine — 552). Строки UTF-16 без завершающего нуля, длина — в символах. */
typedef struct _SENTINEL_PROCESS_EVENT {
    unsigned long Kind;
    unsigned long ProcessId;
    unsigned long ParentProcessId;
    unsigned long Flags;
    long long TimestampUtc;                /* FILETIME (100 нс с 1601-01-01, UTC) */
    unsigned short ImagePathLength;
    unsigned short CommandLineLength;
    unsigned long Reserved;
    wchar_t ImagePath[SENTINEL_IMAGE_PATH_CHARS];
    wchar_t CommandLine[SENTINEL_COMMAND_LINE_CHARS];
} SENTINEL_PROCESS_EVENT, *PSENTINEL_PROCESS_EVENT;

#pragma pack(pop)
