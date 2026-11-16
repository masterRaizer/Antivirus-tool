# HANDOFF — Sentinel

Обновлено: 2026-11-16 (UTC). Ведёт `repo-scout`; правила — скиллы `sentinel-stage-flow` и `av-core-engineer`.

## Ветка и коммит
- Основная ветка: `main` — включает этапы 1–7 (релиз `v1.2.0` + `SelfProtection` DACL и `CriticalProcessGuard`), скиллы `.claude/skills/` и актуальную документацию.
- Все новые работы для этапа 8 (`v1.3.0`) вести от актуального `main` по одному модулю за итерацию.

## Статус этапов
| Этап | Содержание | Статус |
|---|---|---|
| 1 | Sentinel.Core: анализ PE, хеши, энтропия, 5 правил, CLI, selftest 7/7 | Готов. WinVerifyTrust проверяется на Windows |
| 2 | ProcessAuditor, PersistenceAuditor, ConfigIntegrityAuditor, CLI `audit-*` | Готов. 234 теста зелёные, 3 пропущены на Linux |
| 3 | QuarantineManager, RemediationEngine (манифесты отката), JSON/HTML-отчёты, CLI remediation/quarantine/rollback, сквозной тест | Готов (6/6). Тесты после этапа 3: 331 всего, 327 passed, 0 failed, 4 skipped (`WindowsFact`) |
| 4 | `allowed_exclusions.json`, диспетчер «опасное сразу, спорное спросить», IPC по Named Pipes, `SentinelRuntime`, `Sentinel.Service`, `Sentinel.App` (WPF), `scripts/publish-windows.ps1` | Готов (5/5). Linux: build 0 ошибок / 0 предупреждений; 403 теста — 399 passed, 4 skipped (`WindowsFact`). |
| 5 | Релизы в GitHub Actions: `.github/workflows/release.yml` (windows-latest: тесты, `publish-windows.ps1`, MSI на WiX 5.0.2, GitHub Release с `.msi` и `Sentinel.App.exe`), `installer/Sentinel.Installer/` (вне `Sentinel.sln`), шаблон `allowed_exclusions.json` | Release `v1.0.0` опубликован (run на `main` зелёный: тесты, publish, MSI). |
| 6 | Версия 1.1.0 / 1.1.1: скоринг угроз (0–100), потоковый `FileAnalyzer`, импорт PE и .NET, режимы Quick/Full/Custom с защитой от ReparsePoint, кэш чистых файлов, самозащита; база угроз `data/threat_hashes.bin` (11 743 SHA-256, MemoryMappedFile) с обновлятором и облачной проверкой; пул проверки; исправления по отчёту 1.0.0; ACL канала для AuthenticatedUsers, автоподключение 2 с, «Запустить службу»; WPF 1.1.0; WiX 1.1.0; Безопасный режим и WinRE (1.1.1) | Готов, слит в `main`. Linux, Release: build 0/0, 538 тестов — 533 passed, 5 skipped (`WindowsFact`). |
| 7 | Версия 1.2.0: `NativePersistenceParser` (7/1), `RansomwareBehaviorShield` + `CanaryFileGuard` (7/2), `BehavioralCorrelationEngine` + `FalsePositiveGuard` (7/3), `RemovableMediaShield` — USB-щит (7/4), интеграция в Service/CLI/WPF (7/5), спецификация `docs/ARCHITECTURE_V2_KERNEL_SPEC.md` (7/6), DACL-самозащита (`SelfProtection`) и `CriticalProcessGuard` (7/7) | Готов, слит в `main`. Release build 0/0, 632+ теста зелёные. |
| 8 | Версия 1.3.0 (В работе): написание в Linux-контейнере с компиляцией на `windows-latest` в GitHub Actions и живой проверкой пользователем на ноутбуке с Windows: (8/1) `ProcessStartMonitor` (подписка на события старта процессов через `IProcessCreationEventSource`); (8/2) `MemoryIntegrityScanner` в `ProcessAuditor` (потоковая проверка регионов `MEM_PRIVATE`/`PAGE_EXECUTE_READWRITE` буфером 64 КБ через `IMemoryReader`); (8/3) изоляция потоков в `RemediationEngine` перед карантином (строго под защитой `CriticalProcessGuard`); (8/4) `IKernelBridge` и исходный код драйвера `driver/SentinelDrv` (вне `Sentinel.sln`) со сборкой на `windows-latest` в `.github/workflows/release.yml` | В работе |

## Следующие шаги (Этап 8 — v1.3.0)
> **Важное правило для агента:** Все модули этапа 8 пишутся в Linux-контейнере. То, что физически нельзя запустить на Linux (Win32 API, WMI/ETW, WDK драйвер `SentinelDrv.sys`), НЕ является заглушкой: C#-логика закрывается интерфейсами и тестируется на Linux моками (`dotnet test Sentinel.sln`), а компиляция нативных частей проверяется через GitHub Actions (`windows-latest`). Живой запуск на Windows делает пользователь на своём ноутбуке.

1. ~~**Модуль 8/1 (`ProcessStartMonitor`)**~~ — **готов** (см. «Этап 8: сделано» ниже).
2. ~~**Модуль 8/2 (`MemoryIntegrityScanner`)**~~ — **готов** (см. «Этап 8: сделано» ниже).
3. ~~**Модуль 8/3 (изоляция потоков перед карантином)**~~ — **готов** (см. «Этап 8: сделано» ниже).
4. **Модуль 8/4 (`IKernelBridge` + `driver/SentinelDrv`)**: реализация `IKernelBridge` (с `NullKernelBridge` / graceful fallback в User-Mode, если драйвер не загружен) по спецификации `docs/ARCHITECTURE_V2_KERNEL_SPEC.md`, создание `driver/SentinelDrv` (вне `Sentinel.sln`) и добавление шага его компиляции и тестовой подписи на `windows-latest` в `.github/workflows/release.yml`.
5. После каждого модуля обновлять этот файл.

## Этап 8: сделано
### 8/1 `ProcessStartMonitor` (Linux: build 0/0 Debug и Release; 657 тестов — 652 passed, 5 skipped `WindowsFact`)
- `src/Sentinel.Core/Monitoring/`: `ProcessCreationEvent`, `IProcessCreationEventSource`, `ProcessCreationEventSourceFactory`;
  `PollingProcessCreationEventSource` (кросс-платформенный дельта-опрос: базовая линия на первом тике, подробности только для новых PID);
  `WindowsProcessCreationEventSource` (`[SupportedOSPlatform("windows")]`, пакет `System.Management` 8.0.0): `Win32_ProcessStartTrace` →
  `__InstanceCreationEvent WITHIN 1` → опрос Toolhelp раз в 1 с; путь — `QueryFullProcessImageName`, командная строка — PEB, при отказе — `Win32_Process`;
  время старта — `GetProcessTimes`, чтобы ключ находки совпадал с периодическим аудитом (без дублей в диспетчере); при остановке WMI — переход на опрос.
- `ProcessStartMonitor`: `CriticalProcessGuard` (мгновенный пропуск системных процессов в системном каталоге и Sentinel) → `allowed_exclusions.json` →
  `ProcessAuditor` + потоковый `FileAnalyzer`/`ThreatScoringEngine` → маскировка (системное имя вне System32: +25 к баллу, находка `PROC-START-MASQUERADE`) →
  `BehavioralCorrelationEngine.ReportProcessStart` (BH-02 обфускация, BH-03 сработавший свежий автозапуск, новая цепочка BH-04 «сброшен и запущен») →
  `FalsePositiveGuard` (белый список, подпись, теневой режим) → диспетчер: `Act` — `RemediationEngine.TerminateProcessTree` + карантин образа, `AskUser` — очередь решений.
- `SentinelRuntime.RunProcessStartMonitorAsync` / `CreateProcessStartMonitor`, `SentinelRuntimeOptions.ProcessStartSource`; служба — `ProcessStartMonitorWorker`.
- Окружение контейнера: в сеть окружения добавлены `dot.net` и `builds.dotnet.microsoft.com` — без них `scripts/setup-linux.sh` не ставит SDK с WindowsDesktop и `Sentinel.App` не собирается на Linux.

### 8/2 `MemoryIntegrityScanner` (Linux: build 0/0 Debug и Release; 685 тестов — 680 passed, 5 skipped `WindowsFact`)
- `src/Sentinel.Core/Auditors/Memory/`: `MemoryConstants` (имена Win32), `MemoryRegionInfo`, `IMemoryReader`;
  `WindowsMemoryReader` (`[SupportedOSPlatform("windows")]`): `OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)` на время одного вызова
  с `CloseHandle` в `finally`, `VirtualQueryEx`, `ReadProcessMemory` не более 64 КБ за вызов, `ERROR_PARTIAL_COPY` → прочитанная часть.
- `MemoryIntegrityScanner`: сначала `CriticalProcessGuard` и собственный PID (до `EnumerateRegions` — 0 обращений к памяти защищённых процессов);
  кандидаты — `MEM_COMMIT` без `PAGE_GUARD`/`PAGE_NOACCESS`: `MEM_PRIVATE` с RWX/WCX (текущая защита или при выделении) и `MEM_IMAGE` с RWX;
  окна по 64 КБ из `ArrayPool` (очистка при возврате) с перекрытием 4 КБ; бюджет 4 МБ на регион и 16 МБ на процесс.
  Находки: `MEM-REFLECTIVE-PE` (MZ на границе страницы, `e_lfanew` 0x40..0x400 в окне, `PE\0\0`, известный Machine; +50),
  `MEM-YARA-MATCH` (EICAR в любом месте буфера + все правила `rules/`; +70), `MEM-RWX-IMAGE-PATCH` (Low, +10).
  Чистый JIT-регион RWX (.NET/браузеры/PowerShell) — ни находки, ни баллов. Баллы — новые факторы `ThreatScoringEngine`.
- Встраивание: `ProcessAuditorOptions.MemoryScanner` → `ProcessAuditEntry.MemoryScan` и находки; `SentinelRuntimeOptions.MemoryScanner` (Windows) —
  периодический аудит новых процессов и `ProcessStartMonitor`; `BehavioralCorrelationEngine.ReportMemoryAnomaly` — новая цепочка
  BH-05 «полезная нагрузка в памяти» (обфусцированный запуск или «сброшен и запущен» + PE/сигнатура в памяти, 85 баллов).
- CLI: `sentinel audit-memory [PID] [--json]` — ручной аудит памяти (только чтение).
- `scripts/test-memory-scanner.ps1` — синтетический стенд для ноутбука (EICAR и заголовок MZ/PE без кода в RWX-памяти собственного PowerShell).

### 8/2 — живая проверка (Windows 11 10.0.26100 x64, администратор, коммит `14cf194`) и исправления
- Пройдено: синтетический процесс — `MEM-REFLECTIVE-PE` (PE x64) и `MEM-YARA-MATCH` (EICAR) точно по адресам RWX-региона, код выхода 1;
  `System` (4), `lsass.exe`, `csrss.exe` пропущены `CriticalProcessGuard` до `OpenProcess`; полный аудит 212 процессов за 4,51 с —
  0 ложных `MEM-REFLECTIVE-PE`/`MEM-YARA-MATCH` (в т.ч. 34 процесса Chrome и .NET 8).
- Найдено и исправлено: 9 ложных `MEM-RWX-IMAGE-PATCH` на странице write barrier `clr.dll` (.NET Framework 4.8.1) → RWX-страницы
  `clr.dll`/`coreclr.dll` из `\Windows\Microsoft.NET\` и `\Program Files\dotnet\` (путь — `K32GetMappedFileNameW`, новый метод
  `IMemoryReader.GetMappedFileName`) не становятся находкой, если в процессе нет PE/сигнатуры в памяти (счётчик `SuppressedRuntimePatches`);
  `audit-memory` возвращает 1 только при угрозе (`MemoryScanResult.IsThreat`: PE/сигнатура или Medium+), одиночный патч образа (Low) — 0.
- Исправлен `scripts/test-memory-scanner.ps1`: `($size / 1KB)`, UTF-8 с BOM (Windows PowerShell 5.1), EICAR по смещению 0x200, имя `sentinel.exe`.
- Совместимость с SDK 9.0.102: устранены 2 предупреждения CA1859 (`RemediationEngine.RollbackHosts`, `scan-usb` в CLI); проверено сборкой под SDK 9.
- **Не проверено:** работа сканера внутри `SentinelService` (служба на стенде была `Stopped`/`Disabled`) — запустить службу и повторить.

### 8/3 Изоляция потоков перед завершением и карантином (Linux: build 0/0 Debug, Release и под SDK 9.0.102; 727 тестов — 721 passed, 6 skipped `WindowsFact`)
- `src/Sentinel.Core/Remediation/ProcessContainment.cs`: `IProcessContainment` (`SuspendProcess`/`ResumeProcess`/`SuspendProcessTree`; добавлен
  необязательный параметр `executablePath` — без пути системное имя защищается всегда), `ContainmentResult`, `ContainmentBarrier`
  (PID ≤ 4, собственный PID, `CriticalProcessGuard`), `NullProcessContainment`, RAII `ProcessSuspensionScope` (возобновляет всё, что
  приостановлено и не завершено, — в том числе при исключении).
- `WindowsProcessContainment` (`[SupportedOSPlatform("windows")]`): барьер до любых дескрипторов; `TH32CS_SNAPTHREAD` → `OpenThread(0x0002)` →
  `SuspendThread`, `CloseHandle` в `finally`; до 5 проходов, пока проход не найдёт новых потоков; ID приостановленных потоков в `HashSet<uint>`
  (повторный вызов не накручивает счётчик, `ResumeProcess` возобновляет только свои); `ERROR_INVALID_PARAMETER` (87) — не ошибка,
  `ERROR_ACCESS_DENIED` (5) — в `FailedThreadCount`; дерево — по `TH32CS_SNAPPROCESS`, каждый потомок через барьер.
- `RemediationEngine.TerminateProcessTree(pid, GuardContext?, userConfirmed)`: (1) `CriticalProcessGuard` → самозащита/белый список →
  (2) `FalsePositiveGuard` (`RemediationOptions.FalsePositiveGuard`, по умолчанию из `allowed_exclusions.json` каталога данных; спорный
  вердикт блокирует только автоматическое действие) → (3) приостановка всего допустимого дерева → (4) завершение (корень первым, ожидание выхода)
  → незавершённые возобновляются. Итог (`SuspendedThreadCount`, PID) — в сообщении действия, в событии и в причине записи карантина
  `quarantine_manifest.json` («потоки приостановлены до завершения: N»). Конструктор обратно совместим (`containment` — последний необязательный
  параметр, по умолчанию `NullProcessContainment`); `RemediationEngine.CreateDefault` подключает `WindowsProcessContainment` — значит, служба,
  рантайм и CLI (`--remediate`) получают изоляцию автоматически. Диспетчер передаёт балл/подпись и признак решения пользователя.
- Интеграционный `[WindowsFact]` `WindowsProcessContainmentIntegrationTests` (PING.EXE: приостановка ≥ 1 потока, повтор без накрутки, возобновление,
  барьер для PID 4 и собственного процесса) выполняется на `windows-latest` в шаге Test.

## На проверку пользователю на ноутбуке с Windows (Hardware-in-the-Loop)
- **8/2:** окно 1: `powershell -ExecutionPolicy Bypass -File .\scripts\test-memory-scanner.ps1 -WithPeHeader` (печатает PID);
  окно 2 (администратор): `sentinel.exe audit-memory <PID>` → `MEM-YARA-MATCH` (EICAR-Test-File) и `MEM-REFLECTIVE-PE` (PE (x64)), код выхода 1.
  `sentinel.exe audit-memory 4` / PID `lsass` → «пропущен: CriticalProcessGuard». `sentinel.exe audit-memory` (все процессы) при открытых
  браузере и .NET-приложениях — без аномалий у них (контроль ложных срабатываний на JIT); заметить время выполнения.
  Служба использует тот же сканер при периодическом аудите новых процессов и в `ProcessStartMonitor`.
- **8/1:** в журнале службы при старте — «Мониторинг старта процессов: подписка WMI (SELECT * FROM Win32_ProcessStartTrace)». Запуск `powershell -enc <base64>` даёт
  в разделе «Поведенческий щит и USB» цепочку `Process: … (BH-02)` и событие с источником `process-start`. Маскировка: копия безвредного .exe,
  запущенная как `C:\Temp\svchost.exe`, — находка `PROC-IMPERSONATION`; неподписанная копия завершается и уходит в карантин, копия с действительной
  подписью Microsoft — только запрос решения (AskUser). Безопасный режим: в журнале — переход на опрос.
- **8/3:** скопировать `C:\Windows\System32\PING.EXE` в `C:\Temp\svchost.exe`, запустить `C:\Temp\svchost.exe -n 300 127.0.0.1`,
  затем от администратора `sentinel.exe audit-processes --remediate`: у `svchost.exe` из `C:\Temp` — находка `PROC-IMPERSONATION`, в итоге действия —
  «Перед завершением приостановлено потоков: N в 1 процесс(ах)», процесс завершён. Контроль: настоящие `svchost.exe`/`lsass.exe` не затронуты
  (Диспетчер задач). При запущенной службе тот же запуск должен быть пойман `ProcessStartMonitor` (событие `process-start`, статус «Завершён»).
- `WinVerifyTrust`, реестровые и сервисные аудиторы, удаление исключений Defender.
- `Sentinel.App` (WPF) и `Sentinel.Service` (установка MSI, DACL-самозащита, автоподключение Named Pipe, раздел «Поведенческий щит и USB»).
- Безопасный режим и WinRE (1.1.1).
- Модули 1.3.0 после сборки в GitHub Actions (`ProcessStartMonitor`, `MemoryIntegrityScanner`, `SentinelDrv.sys` в режиме Test Signing).

## Команды
```bash
bash scripts/setup-linux.sh
dotnet build Sentinel.sln
dotnet test Sentinel.sln
