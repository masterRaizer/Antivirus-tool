# Sentinel v2.0 — проект связки Ring 0 / Ring 3 (спецификация, не реализация)

> Этот документ — **проект** будущего драйверного уровня. В репозитории нет и не должно быть файлов `.vcxproj`/C++:
> решение остаётся на 100% собираемым через `dotnet build Sentinel.sln` на Linux. Весь код v1.2.0 — User-Mode (.NET 8).
> Реализация ядра (WDK) появится отдельной веткой, собираемой только на `windows-latest`, и в `Sentinel.sln` не войдёт.

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
