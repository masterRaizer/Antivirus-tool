# Sentinel v2.0 — связка Ring 0 / Ring 3 (спецификация; реализация v1.3.0 — раздел 6)

> Разделы 1–5 — исходный проект драйверного уровня (этап 7/6). С версии **1.3.0** в репозитории есть драйвер
> `driver/SentinelDrv` (C, WDM) — он **не входит в `Sentinel.sln`**: решение по-прежнему собирается `dotnet build Sentinel.sln`
> на Linux, а драйвер компилируется и подписывается тестовым сертификатом только на `windows-latest` в GitHub Actions.
> Нормативное описание реализованного протокола (имена, IOCTL, структуры, модель безопасности) — раздел 6; там, где
> разделы 2 и 4 расходятся с ним (транспорт, имя класса моста), действует раздел 6.

## 1. Разделение ответственности

| Уровень | Компонент | Задача |
|---|---|---|
| Ring 0 | `SentinelDrv.sys` (minifilter + коллбэки) | Перехват файловых операций, запуска процессов/потоков, загрузки образов; защита дескрипторов и реестра; синхронные вердикты и асинхронная телеметрия |
| Ring 3 | `Sentinel.Service` (`LocalSystem`) | Принятие решений: статический скоринг (v1.1.0), поведенческая корреляция (v1.2.0), базы угроз, карантин/откат |
| Ring 3 | `Sentinel.App` / `Sentinel.Cli` | Интерфейс, отчёты, ручные проверки |

Драйвер **не принимает решений** о вредоносности: он задаёт вопрос и исполняет вердикт. Вся аналитика — в User-Mode,
что сохраняет текущую тестируемость на Linux (движки `BehavioralCorrelationEngine`, `FalsePositiveGuard`, `ThreatScoringEngine`
не зависят от ядра).

## 2. Протокол обмена через FilterCommunicationPort

- Порт: `FltCreateCommunicationPort(\SentinelFilterPort)` на стороне драйвера; `FilterConnectCommunicationPort` на стороне службы.
- Кадры — фиксированные структуры `#pragma pack(push,1)` с полем `ProtocolVersion` (см. `SENTINEL_KERNEL_EVENT`/`SENTINEL_KERNEL_REPLY`).
- **Таймауты против зависания ядра:** синхронный `FltSendMessage` — 350 мс для файловых операций, 1500 мс для создания процесса.
  При таймауте или отсутствии подключённого клиента (`ClientPort == NULL`) — политика **Fail-Open** (разрешить, записать в кольцевой
  буфер диагностики), чтобы не подвесить загрузку системы.
- **Защита от взаимоблокировки:** драйвер никогда не шлёт синхронный запрос, если инициатор — сам `Sentinel.Service`/`App`/`Cli`
  или системные процессы (`System` PID 4, `smss`, `csrss`, `wininit`, `lsass`, `services`). Это зеркалит правило самозащиты User-Mode.
- Ядерный LRU-кэш чистых объектов по `(VolumeSerialNumber, FileId, LastWriteTime)`; сброс командой `SentinelCmdFlushCleanCache`
  при обновлении баз (User-Mode `ThreatFeedUpdater`).

## 3. Матрица самозащиты

| Цель | Механизм ядра | Правило |
|---|---|---|
| Системные процессы (`csrss`, `smss`, `lsass`, `wininit`, `services`, `explorer`, `ntoskrnl`, `winload.efi`) | `ObRegisterCallbacks` | Снятие опасных прав (`PROCESS_TERMINATE`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`, `PROCESS_CREATE_THREAD`), иммунитет только для файла в System32/Windows (защита от маскировки — зеркалит `FalsePositiveGuard`/`SelfProtection`) |
| Дескрипторы `Sentinel.Service`/`App` | `ObRegisterCallbacks` | Запрет `PROCESS_TERMINATE`/`PROCESS_VM_WRITE` от посторонних процессов |
| Файлы `C:\Program Files\Sentinel`, `C:\ProgramData\Sentinel` | minifilter `IRP_MJ_CREATE`/`IRP_MJ_SET_INFORMATION` | Запрет записи/удаления/переименования не от доверенных PID Sentinel |
| Реестр: `Services\SentinelService`/`SentinelDrv`, `SafeBoot`, `IFEO`, автозагрузка | `CmRegisterCallbackEx` | Запрет правки не от процессов Sentinel; высокорисковые изменения — на скоринг в `Sentinel.Core` |

## 4. Мост User-Mode (`IKernelBridge`) — план

- Интерфейс `IKernelBridge : IAsyncDisposable` c синхронным событием `OnSyncDecisionRequired` и асинхронным `OnAsyncTelemetryReceived`.
- Реализация `NullKernelBridge` — для Linux и для Windows без загруженного драйвера (WinRE, не установлен): рантайм продолжает
  работать как в v1.1.1, без ошибок. **В v1.2.0 поставляется только `NullKernelBridge`** — это сохраняет кросс-сборку.
- Нативная реализация `FltPortKernelBridge` (через `fltlib.dll`, `[SupportedOSPlatform("windows")]`) — предмет отдельной ветки.

## 5. Отображение возможностей v1.2.0 на будущее ядро

| v1.2.0 (User-Mode, есть сейчас) | v2.0 (ядро, план) |
|---|---|
| `NativePersistenceParser` — периодический аудит | `CmRegisterCallbackEx` — перехват правки автозагрузки в момент записи |
| `RansomwareBehaviorShield` + `CanaryFileGuard` поверх `FileSystemWatcher` | minifilter `IRP_MJ_WRITE` — счётчик массовой перезаписи до записи на диск |
| `RemovableMediaShield` — опрос `DriveInfo` | minifilter на томах съёмных носителей |
| `BehavioralCorrelationEngine` — корреляция событий | синхронные вердикты `PsSetCreateProcessNotifyRoutineEx` |

Переход на ядро не меняет аналитические движки — они уже изолированы от источника событий, поэтому добавление драйвера
сведётся к новому поставщику событий для существующего `SentinelRuntime`.

## 6. Реализация v1.3.0 (нормативно)

Первая итерация — **WDM-драйвер с объектом устройства и IOCTL**, а не minifilter с `FilterCommunicationPort`:
файловые колбэки и синхронные вердикты (раздел 2) остаются планом v2.0. Драйвер ничего не блокирует (Fail-Open):
он защищает дескрипторы и отдаёт телеметрию, все решения — в User-Mode.

| Параметр | Значение |
|---|---|
| Объект устройства | `\Device\SentinelDrv`, символьная ссылка `\DosDevices\SentinelDrv`, из User-Mode — `\\.\SentinelDrv` |
| Создание | `IoCreateDeviceSecure`, SDDL `D:P(A;;GA;;;SY)(A;;GA;;;BA)` — открыть могут только SYSTEM и Administrators; `FILE_DEVICE_SECURE_OPEN` |
| Тип устройства | `0x8A53` (диапазон производителя), `METHOD_BUFFERED` |
| Служба ядра | `SentinelDrv`, `type= kernel`, `start= demand` |
| Компоновка | `/INTEGRITYCHECK` (обязателен для `ObRegisterCallbacks` и `PsSetCreateProcessNotifyRoutineEx`), `/ENTRY:GsDriverEntry` |

**IOCTL** (`CTL_CODE(0x8A53, функция, METHOD_BUFFERED, доступ)`):

| Код | Имя | Доступ | Буферы | Права вызывающего |
|---|---|---|---|---|
| `0x8A536000` | `IOCTL_SENTINEL_GET_STATUS` (0x800) | `FILE_READ_DATA` | выход ≥ 48 байт `SENTINEL_STATUS` | SYSTEM / Administrators |
| `0x8A53A004` | `IOCTL_SENTINEL_SET_PROTECTED_PIDS` (0x801) | `FILE_WRITE_DATA` | вход ≥ 8 + 4·Count байт `SENTINEL_PROTECTED_PIDS`, Count ≤ 64 | только LocalSystem (`SeTcbPrivilege`), иначе `STATUS_PRIVILEGE_NOT_HELD` |
| `0x8A536008` | `IOCTL_SENTINEL_READ_EVENTS` (0x802) | `FILE_READ_DATA` | выход ≥ 16 байт: `SENTINEL_EVENT_BATCH` + N · `SENTINEL_PROCESS_EVENT` | SYSTEM / Administrators |

Короткий буфер — `STATUS_BUFFER_TOO_SMALL`, чужая версия протокола — `STATUS_REVISION_MISMATCH`, лишний Count — `STATUS_INVALID_PARAMETER`.

**Структуры** (`#pragma pack(push, 1)`, только типы фиксированного размера, `ProtocolVersion = 1`;
источник — `driver/SentinelDrv/SentinelDrv.h`, зеркало — `src/Sentinel.Core/Kernel/KernelProtocol.cs`, проверка — `C_ASSERT` и xUnit):

| Структура | Размер | Поля (смещение) |
|---|---|---|
| `SENTINEL_STATUS` | 48 | ProtocolVersion (0), DriverVersion (4, `major<<16 \| minor<<8 \| patch`), Flags (8: 1 — Ob, 2 — process notify), ProtectedPidCount (12), ProcessEventsTotal (16, u64), EventsDropped (24, u64), HandleStripsTotal (32, u64), EventsQueued (40), Reserved (44) |
| `SENTINEL_PROTECTED_PIDS` | 264 | ProtocolVersion (0), Count (4), Pids[64] (8) |
| `SENTINEL_EVENT_BATCH` | 16 | ProtocolVersion (0), Count (4), Remaining (8), Reserved (12) |
| `SENTINEL_PROCESS_EVENT` | 1576 | Kind (0: 1 — создание, 2 — завершение), ProcessId (4), ParentProcessId (8), Flags (12: 1/2 — усечение пути/командной строки, 4 — PID был защищён), TimestampUtc (16, FILETIME), ImagePathLength (24, символы), CommandLineLength (26), Reserved (28), ImagePath[260] (32, UTF-16), CommandLine[512] (552, UTF-16) |

**Модель безопасности.**
- `ObRegisterCallbacks` (`PsProcessType`, `PsThreadType`; `OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE`, высота `385201.7341`):
  для защищаемых PID у пользовательских дескрипторов посторонних процессов снимаются `PROCESS_TERMINATE`, `PROCESS_CREATE_THREAD`,
  `PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, `PROCESS_SUSPEND_RESUME`, `THREAD_TERMINATE`, `THREAD_SUSPEND_RESUME`, `THREAD_SET_CONTEXT`.
  Не изменяются: дескрипторы ядра, обращение процесса к себе, запросы защищаемых процессов друг к другу и запросы ОС
  (System, а также `csrss`, `smss`, `lsass`, `services`, `wininit` — по имени и, на PASSIVE_LEVEL, по пути в `\Windows\System32\`).
- Список защищаемых PID ведёт служба (`KernelProtectionSync`, раз в 10 с): собственный процесс, процессы Sentinel из каталога
  установки и `csrss`/`smss`/`wininit`/`services`/`lsass`/`winlogon` из System32. `svchost.exe` и `explorer.exe` не защищаются
  ядром (их штатно перезапускают SCM и пользователь). PID 0 и 4 драйвер не принимает; завершившийся PID удаляется из списка
  в колбэке завершения процесса, чтобы повторно выданный PID не унаследовал защиту. Тот же список публикуется в
  `CriticalProcessGuard` — User-Mode не приостанавливает, не завершает и не читает память этих процессов.
- `PsSetCreateProcessNotifyRoutineEx`: событие собирается на PASSIVE_LEVEL (строки `PS_CREATE_NOTIFY_INFO` могут быть
  в подкачиваемой памяти) и копируется в неподкачиваемый кольцевой буфер на 256 событий под спин-блокировкой; при переполнении
  вытесняется самое старое (`EventsDropped`). `CreationStatus` не изменяется никогда.
- Выгрузка: `ObUnRegisterCallbacks` → снятие process-notify → `IoDeleteSymbolicLink` → `IoDeleteDevice`.

**User-Mode.** `IKernelBridge` (`NullKernelBridge` — профиль User-Mode EDR, `WindowsKernelBridge` — `CreateFile` + `DeviceIoControl`).
`ERROR_FILE_NOT_FOUND`/`ERROR_PATH_NOT_FOUND`/`ERROR_ACCESS_DENIED` или другая версия протокола при открытии — служба пишет
`Kernel driver not loaded, running in User-Mode EDR profile` и работает дальше без драйвера; потеря драйвера во время работы
(`ERROR_INVALID_HANDLE`, `ERROR_DEVICE_NOT_CONNECTED` и т. п.) — тот же переход (Fail-Open), а `ProcessStartMonitor`
переключается с телеметрии ядра (`KernelProcessCreationEventSource`) на WMI/опрос. Диагностика — `sentinel kernel-status`.
