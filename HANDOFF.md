# HANDOFF — Sentinel

Обновлено: 2026-11-16 (UTC). Ведёт `repo-scout`; правила — скиллы `sentinel-stage-flow` и `av-core-engineer`.

## Ветка и коммит
- Основная ветка: `main` — включает этапы 1–8 (релиз `v1.3.0`: `ProcessStartMonitor`, `MemoryIntegrityScanner`, `IProcessContainment`, драйвер `SentinelDrv`), скиллы `.claude/skills/` и актуальную документацию.
- Релиз `v1.3.0` — аннотированный тег на `main`; GitHub Release публикуется workflow по тегу. Новые работы вести от актуального `main` по одному модулю за итерацию.

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
| 8 | Версия 1.3.0 (8/1–8/4 + стабилизация D1–D7): написание в Linux-контейнере с компиляцией на `windows-latest` в GitHub Actions и живой проверкой пользователем на ноутбуке с Windows: (8/1) `ProcessStartMonitor` (подписка на события старта процессов через `IProcessCreationEventSource`); (8/2) `MemoryIntegrityScanner` в `ProcessAuditor` (потоковая проверка регионов `MEM_PRIVATE`/`PAGE_EXECUTE_READWRITE` буфером 64 КБ через `IMemoryReader`); (8/3) изоляция потоков в `RemediationEngine` перед карантином (строго под защитой `CriticalProcessGuard`); (8/4) `IKernelBridge` и исходный код драйвера `driver/SentinelDrv` (вне `Sentinel.sln`) со сборкой на `windows-latest` в `.github/workflows/release.yml` | Готов и верифицирован на реальном ядре Windows 11 26100 (контрольная проверка `f77f5b7`); релиз `v1.3.0` |

## Следующие шаги (Этап 8 — v1.3.0)
> **Важное правило для агента:** Все модули этапа 8 пишутся в Linux-контейнере. То, что физически нельзя запустить на Linux (Win32 API, WMI/ETW, WDK драйвер `SentinelDrv.sys`), НЕ является заглушкой: C#-логика закрывается интерфейсами и тестируется на Linux моками (`dotnet test Sentinel.sln`), а компиляция нативных частей проверяется через GitHub Actions (`windows-latest`). Живой запуск на Windows делает пользователь на своём ноутбуке.

1. ~~**Модуль 8/1 (`ProcessStartMonitor`)**~~ — **готов** (см. «Этап 8: сделано» ниже).
2. ~~**Модуль 8/2 (`MemoryIntegrityScanner`)**~~ — **готов** (см. «Этап 8: сделано» ниже).
3. ~~**Модуль 8/3 (изоляция потоков перед карантином)**~~ — **готов** (см. «Этап 8: сделано» ниже).
4. ~~**Модуль 8/4 (`IKernelBridge` + `driver/SentinelDrv`)**~~ — **готов** (см. «Этап 8: сделано» ниже); версия продукта — **1.3.0**.
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

### 8/4 `IKernelBridge` и драйвер `driver/SentinelDrv` (Linux: build 0/0 Debug, Release и под SDK 9.0.102; 754 теста — 747 passed, 7 skipped `WindowsFact`)
- Протокол — `docs/ARCHITECTURE_V2_KERNEL_SPEC.md`, раздел 6 (нормативный): устройство `\Device\SentinelDrv` / `\\.\SentinelDrv`,
  IOCTL `0x8A536000` (статус), `0x8A53A004` (защищаемые PID, только LocalSystem), `0x8A536008` (события); структуры Pack=1:
  `SENTINEL_STATUS` 48, `SENTINEL_PROTECTED_PIDS` 264, `SENTINEL_EVENT_BATCH` 16, `SENTINEL_PROCESS_EVENT` 1576 байт.
  Транспорт v1.3.0 — объект устройства + IOCTL (а не `FilterCommunicationPort` из исходного проекта); драйвер ничего не блокирует (Fail-Open).
- `driver/SentinelDrv/` (вне `Sentinel.sln`, `driver/Directory.Build.props` отсекает настройки .NET): `SentinelDrv.h` (единый источник протокола),
  `SentinelDrv.c` (WDM: `IoCreateDeviceSecure` с SDDL SYSTEM+Administrators, CREATE/CLOSE/DEVICE_CONTROL с проверкой размеров и `SeTcbPrivilege`,
  `ObRegisterCallbacks` для процессов и потоков — снятие TERMINATE/VM_WRITE/VM_OPERATION/CREATE_THREAD/SUSPEND_RESUME у посторонних,
  запросы System/csrss/smss/lsass/services/wininit из System32 не меняются; `PsSetCreateProcessNotifyRoutineEx` → кольцевой буфер на 256 событий;
  выход процесса снимает его PID с защиты; `DriverUnload` снимает всё в обратном порядке), `SentinelDrv.inf`, `SentinelDrv.vcxproj`
  (штатный C++-тулсет VS + `/kernel`, `/INTEGRITYCHECK`, `/ENTRY:GsDriverEntry`, `/W4 /WX`).
  Перед пушем драйвер проверен в контейнере: `clang -fsyntax-only -Wall -Wextra` с заголовками WDK 10.0.26100 из NuGet, все `C_ASSERT` раскладки проходят.
- CI: на образе `windows-latest` (`windows-2025-vs2026`) установлено только расширение WDK для VS, поэтому `scripts/build-driver-windows.ps1` берёт
  `Microsoft.Windows.WDK.x64` + `Microsoft.Windows.SDK.CPP` 10.0.26100.6584 из NuGet (кэш `driver/.wdk`), собирает vcxproj через MSBuild, проверяет
  флаг FORCE_INTEGRITY в PE, создаёт сертификат `CN=Sentinel Test Driver`, подписывает `signtool` и кладёт в `dist/driver/` `SentinelDrv.sys`, `.inf`,
  `SentinelDrvTest.cer`, `install-driver-testmode.ps1` (+ архив `dist/SentinelDrv-v1.3.0-x64-testsigned.zip`). Каждый прогон выкладывает `dist/`
  артефактом `Sentinel-v1.3.0-<sha>` (`actions/upload-artifact@v4`); GitHub Release публикуется только по тегу `v*` или вручную.
- User-Mode (`src/Sentinel.Core/Kernel/`): `KernelProtocol` (кодек, сверка с `SentinelDrv.h`/`.c` в тестах), `IKernelBridge`, `NullKernelBridge`,
  `WindowsKernelBridge` (`CreateFile` → `SafeFileHandle`, `DeviceIoControl`; ERROR_FILE_NOT_FOUND/PATH_NOT_FOUND/ACCESS_DENIED и потеря драйвера —
  «Kernel driver not loaded, running in User-Mode EDR profile»), `KernelProtectionSync` (раз в 10 с: свои процессы из каталога установки + csrss/smss/
  wininit/services/lsass/winlogon из System32; тот же набор — в `CriticalProcessGuard`), `KernelProcessCreationEventSource` (телеметрия ядра для
  `ProcessStartMonitor` с откатом на WMI/опрос). Служба — `KernelBridgeWorker`; `ServiceStatus.KernelDriver`; CLI — `sentinel kernel-status [--json]`.
- Версия 1.3.0: `Directory.Build.props`, `Sentinel.Installer.wixproj`, `release.yml`.

### 8/4 — живая проверка (Windows 11, `PCARKNIGHT`, Test Mode, коммит `7553165`) и стабилизация перед тегом `v1.3.0`
- Пройдено: `SentinelDrv.sys` загружен без BSOD (`STATE 4 RUNNING`), `kernel-status` — Ob-колбэки и process-notify активны; после синхронизации
  (8 защищаемых PID) `taskkill /F /IM Sentinel.Service.exe` → `Access is denied`, служба жива, «Снято опасных прав» 0 → 1.
- Исправлено по дефектам D1–D7:
  - **D4 (критичный):** пути из ядра (`\SystemRoot\System32\Conhost.exe`, `\??\C:\…`, `\GLOBAL??\…`, `\DosDevices\…`) приводятся к Win32
    (`NtPath.ToWin32`) в `ProcessStartMonitor`, `SystemProcessPolicy`, `CriticalProcessGuard`; путь `\Device\HarddiskVolumeN\…` — по таблице
    `QueryDosDevice`, а если не удалось — `QueryFullProcessImageName` по PID (`KernelProcessCreationEventSource`). Ложный `PROC-IMPERSONATION` на conhost устранён.
  - **D2:** все рабочие процессы службы начинают с `await Task.Yield()`, периодический аудит идёт в `Task.Run`, `HostOptions.ServicesStartConcurrently`;
    `KernelBridgeWorker` и `IpcServerWorker` регистрируются первыми — драйвер и IPC поднимаются в первые секунды.
  - **D3:** пока у драйвера открыт дескриптор, Windows не вызывает `DriverUnload` и IOCTL продолжают проходить, поэтому мост раз в 2 с спрашивает у SCM
    состояние службы `SentinelDrv` и при `STOP_PENDING`/`STOPPED` сразу закрывает `\\.\SentinelDrv` (плюс немедленное отключение по кодам
    2/6/21/31/433/995/1167 от `DeviceIoControl`). Без драйвера служба раз в 10 с пробует подключиться снова (`sc start SentinelDrv` подхватывается
    без перезапуска службы); `KernelBridgeWorker.StopAsync` отпускает драйвер сразу.
  - **D5:** `SelfProtection.IsOwnInstallationFile` — сам `Environment.ProcessPath` (если это образ Sentinel), соседние образы Sentinel и `rules\`/`data\`
    рядом с ним защищены в `CriticalProcessGuard`, `FalsePositiveGuard`, карантине; каталог целиком не защищается (запуск из «Загрузок» не делает их
    неприкосновенными). Службы `SentinelService`/`SentinelDrv` не «откатываются» `RemediationEngine` (Blocked) и не становятся находками диспетчера.
  - **D1:** `install-driver-testmode.ps1` вычисляет каталог источника в теле скрипта (`$PSScriptRoot` в `param()` пуст в Windows PowerShell 5.1).
  - **D6:** `publish-windows.ps1` копирует содержимое `rules`/`data`, а не сами каталоги (раньше второй и третий проект давали `rules\rules`, `data\data`),
    и падает, если вложенный каталог всё же появился.
  - **D7:** событие рантайма `Info` (подключение/отключение драйвера, синхронизация PID, источник монитора старта) пишется с уровнем Information;
    журнал службы — `%ProgramData%\Sentinel\Logs\service-ГГГГММДД.log` (14 дней; `Sentinel.*` с Information, прочее с Warning) и EventLog
    (`Sentinel.*` с Information). `ProcessStartMonitor` через 1,75 с повторно проверяет память интерпретаторов (`powershell`, `pwsh`, `cmd`, `mshta`,
    `rundll32`, `regsvr32`, `wscript`, `cscript`) и неподписанных `.exe` (не более 2 одновременно, очередь до 32) — ловит RWX-нагрузку, выделенную после старта.

### Контрольная проверка `f77f5b7` (Windows 11 26100, `PCARKNIGHT`, администратор, Test Mode) — D1–D7 закрыты, этап 8 верифицирован на реальном ядре
- D6: `dist\rules` и `dist\data` плоские, `Sentinel.Cli.exe rules` — «Итого: 5 правил, 0 ошибок», дублей id нет.
- D1: `install-driver-testmode.ps1 -Action Install` без `-SourceDirectory` — сертификат импортирован, `SentinelDrv` `RUNNING`, `kernel-status` — kernel, 1.3.0 / 1.
- D2/D5/D7: `Start-Service` за 0,7 с, все рабочие процессы стартовали одновременно, 8 PID в ядре через 74 мс; `taskkill /F /IM Sentinel.Service.exe` —
  `Access is denied`; служба из `C:\Sentinel-v1.3.0-fix\` себя не детектирует и не отключает; журнал `service-*.log` пишется.
- D4: `cmd.exe` с порождением `conhost.exe` (`\SystemRoot\System32\conhost.exe`) — без ложных `PROC-IMPERSONATION`.
- D3: `sc stop SentinelDrv` — `STOPPED` за 3,2 с без зависания, служба продолжила в user-mode; после `sc start SentinelDrv` — переподключение и
  синхронизация 8 PID через ~12–14 с без перезапуска службы.
- D7 (служба): `test-memory-scanner.ps1 -WithPeHeader` — автоматически `MEM-REFLECTIVE-PE`, `MEM-YARA-MATCH`, `MEM-RWX-IMAGE-PATCH`, решение
  AskUser / PendingDecision (powershell.exe подписан Microsoft — `FalsePositiveGuard`).
- По итогам: при решении AskUser `ProcessStartMonitor` больше не занижает критичность находок до Medium — `MEM-YARA-MATCH`/`MEM-REFLECTIVE-PE`
  остаются Critical в событии и журнале, а автоматическое действие запрещает явный маршрут диспетчера
  `DispatchProcessForDecisionAsync` (статус PendingDecision, «Ожидает решения пользователя: <причина FalsePositiveGuard>»). Тесты `AskUserSeverityTests`.

### 1.3.1 — исправления после установки на MSI Katana (Windows 11 Pro 24H2, DESKTOP-DF557E0)
- **MSI 1939 → 1603 (откат установки).** Встроенное действие Windows Installer `MsiConfigureServices` (таблица `MsiServiceConfigFailureActions`)
  открывает службу без `SERVICE_START`, нужного для действий «restart», и получает ACCESS_DENIED (5); при `Vital="yes"` это откатывает всю
  установку (WiX предупреждал об этом в каждой сборке, `Package.wxs#45`). `ServiceConfigFailureActions` из пакета убран; политику
  восстановления (перезапуск через 5/30/60 с, сброс за сутки, также при ненулевом коде выхода) служба выставляет себе сама при старте
  (`Sentinel.Service/ServiceRecovery.cs`, `ChangeServiceConfig2` с правом `SERVICE_START`); сбой этой настройки только журналируется.
  Версия 1.3.1, чтобы MajorUpgrade встал поверх временной установки. Проверка: `sc.exe qfailure SentinelService`.
- **Ложные срабатывания на служебных командах powershell/cmd** (PROC-PS-BYPASS + PROC-CMD-IEX + BH-02 у powershell.exe и cmd.exe, подписанных Microsoft):
  BH-02 больше не считает одиночный `iex`/`Invoke-Expression` бесфайловым запуском (только вместе с загрузкой из сети), а `-enc` — только как
  отдельный ключ `-e/-ec/-enc…/-EncodedCommand` с base64 (раньше совпадал с `-Encoding UTF8`); `PROC-CMD-IEX` — High лишь для download cradle
  или base64, одиночный — Medium; `PROC-PS-BYPASS` — Low. Периодический аудит процессов проходит `FalsePositiveGuard`, как и монитор старта:
  слабые признаки у образа с доверенной подписью — не событие. В карточке события процесса показывается командная строка («Команда: …»).
- **«Полная» проверка «висела» на 95 % на этапе «Автозагрузка и реестр» со «204 из ≈204»:** 204 — это процессы (файлы ещё не начинались), а процент
  считался от всех известных объектов с потолком 95 %; аудит автозагрузки — один синхронный вызов на 1–3 мин без обновлений. Теперь процент по этапам
  (процессы 0–4 %, автозагрузка 4–12 %, конфигурация 12–15 %, файлы 15–100 %), аудит автозагрузки идёт в фоне с отображением прошедшего времени,
  а свежий (≤ 5 мин) результат фонового аудита службы используется повторно; находки этапа «Процессы» тоже проходят `FalsePositiveGuard`.
- **Sentinel ловил сам себя** (17 событий «Ждёт решения»: Sentinel.Cli/App/Service.exe, `PROC-FILE-HEURISTIC`, балл 65): однофайловый бандл .NET
  давал «высокую энтропию нативного PE» (+15) и «патчинг AMSI/ETW» (+40) — строки AmsiScanBuffer/EtwEventWrite и импорт VirtualProtect принадлежат
  рантайму .NET. `FileAnalyzer` распознаёт сигнатуру бандла apphost (проверено на собственном single-file `sentinel.exe`), `ThreatScoringEngine` для
  бандла не начисляет энтропию и AMSI/ETW по строкам (прямой импорт AmsiScanBuffer/EtwEventWrite по-прежнему учитывается) — это убирает ложные
  срабатывания на любые однофайловые .NET-приложения. Плюс доверие по хешу: служба при старте регистрирует SHA-256 своих `Sentinel*.exe`; файл
  или процесс с таким хешем (например, копия `F:\Sentinel.App.exe`) — не находка (`FalsePositiveGuard` → Protected, диспетчер пропускает).
- Источник ложных `PROC-PS-BYPASS`/`PROC-CMD-IEX`/BH-02 подтверждён сессией на Katana: обёртка Claude Code
  `powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "...; Invoke-Expression -Command $__claudeCodeScript"` (родитель `claude.exe` → `cmd.exe`);
  дословно добавлена в регрессионные тесты. Родителю по имени не доверяем (обход через подмену родителя).
- **Счётчик проверки «рос» вместе с обходом («76 148 из ≈76 412», 95 %), непонятно, сколько осталось:** параллельно с проверкой идёт быстрый
  подсчёт файлов тем же обходом (метаданные каталогов, те же исключения и пропуск ReparsePoint); когда он закончен, итог окончательный
  (`ScanProgress.TotalCounted`, знак «≈» снимается) и считается оценка оставшегося времени (`RemainingSeconds`, в приложении — «осталось ≈ …»
  под «ВРЕМЯ»; пока идёт подсчёт — «идёт подсчёт файлов…»). Разметка `ScanView.xaml` на Windows не проверялась.

### 1.3.2 — ложные находки на Защитник Windows (отчёт быстрой проверки 1.3.1 с Katana, DESKTOP-DF557E0)
- 5 находок Medium (`PERS-SERVICE-USERWRITABLE` у `MpKslbffc8b48`, `PERS-TASK-USERWRITABLE` у 4 задач Windows Defender) с путём
  «C:\ProgramData\Microsoft\Windows»: команда без кавычек «C:\ProgramData\Microsoft\Windows Defender\Platform\…\MpCmdRun.exe -IdleTask …» и
  ImagePath «\??\C:\ProgramData\Microsoft\Windows Defender\Definition Updates\…\MpKslDrv.sys» обрезались на первом пробеле, файл не находился,
  подпись не проверялась. Теперь `CommandLineParser.ResolveExecutable` разбирает путь без кавычек по правилам CreateProcess (слева направо по
  пробелам до существующего файла, с подстановкой `.exe`), префиксы ядра снимаются со всей строки до разбора, а каталоги
  `ProgramData\Microsoft\Windows Defender\Platform` и `…\Definition Updates` (запись только SYSTEM/TrustedInstaller) — доверенные.
  Две информационные находки о старых корневых сертификатах Microsoft — штатное поведение (Info, без действий).
- Скорость проверки (баг-репорт с Katana: «скорость нулевая», 1 ядро 100%, 19 ГБ чтения, 0 рабочих процессов; быстрая проверка 1.3.1 —
  244 объекта за 209 с ≈ 1,2 об/с). Причина: этапы «Процессы» и «Автозагрузка» шли последовательно внутри службы и хешировали один и тот же
  образ много раз (svchost.exe у сотен служб и десятков процессов). Теперь `ProcessAuditor` и `PersistenceAuditor` анализируют каждый файл
  за прогон один раз, процессы проверяются параллельно (`DefaultWorkerCount`), в `ScanProgress` добавлены `BytesPerSecond` (окно ~10 с) и
  `BytesScanned`, интерфейс показывает «об/с · МБ/с», служба раз в 30 с пишет в журнал строку «Проверка (этап): N из M, …, сейчас: …».

### 1.3.3 — по отчёту 1.3.2 с Katana (быстрая проверка 24 с вместо 209 с, 231 объект, 9,6 об/с)
- Служба Защитника `MpKsl…` снова помечалась PERS-SERVICE-USERWRITABLE: её драйвер `MpKslDrv.sys` лежит во временной папке
  `Definition Updates\{GUID}`, которую Защитник удаляет, а ключ службы остаётся. Файла нет — разбор по правилам CreateProcess ничего не находил
  и откатывался к первому токену «C:\ProgramData\Microsoft\Windows». Теперь для несуществующего файла путь берётся до первого слова с
  расширением исполняемого файла (`.exe/.sys/.dll/.com/.scr/.bat/.cmd/.ps1`) — цель попадает в доверенный каталог Защитника.
- Журнал прогресса: первая строка — через 30 с после старта (а не сразу с нулями), в конце — итоговая строка «Проверка завершена (…):
  объектов, секунд, об/с, МБ, по кэшу, находок, ошибок, отчёт».
- Служебные команды доверенных образов (powershell/cmd с подписью Microsoft) со слабыми признаками больше не попадают в отчёт быстрой
  проверки находками: как и в реальном времени, только журнал (`IsSuppressedProcess`).

### 1.3.4 — по сводному отчёту с Katana (16–17.11)
- `sentinel service-scan quick|full|custom <путь> [--wait] [--json]`: проверка силами службы через IPC (для замеров без UI Automation);
  с `--wait` — прогресс раз в 5 с и итог (секунды, объекты, об/с, МБ, находки, ошибки, отчёт).
- Журнал действий с файлами `%ProgramData%\Sentinel\Logs\file-actions.jsonl` (только дописывается): изоляция, восстановление и удаление из
  карантина с путём, SHA-256 и причиной — доказательство того, что Sentinel делал и не делал с файлами пользователя.
- Отчёт: справочные Info-записи конфигурации (штатные устаревшие корни Windows и т.п.) не выводятся находками, только счётчиком
  «справочных записей скрыто: N» в примечании области; в число находок проверки не входят.
- Базы угроз: в журнал пишется, какие источники не обновились и почему («Не обновлены: имя — статус: причина»).
- Доступность/автотесты: у всех кнопок окна задан `AutomationProperties.Name` (у кнопок-иконок — из подсказки), у «В карантин»,
  «В исключения», «Игнорировать» — `AutomationId` (QuarantineButton, AllowButton, IgnoreButton).
- Регресс скорости на 1.3.3 (284 объекта за 134 с, ~100 с на «Автозагрузке»): проверка запущена через 28 с после старта службы, когда
  фоновый аудит автозагрузки ещё шёл, и запустила второй такой же параллельно (в 1.3.2 замер попал на готовый кэш — 24 с). Теперь аудит
  общий (`RunPersistenceAuditSharedAsync`: проверка ждёт идущий фоновый), а цели служб и задач анализируются параллельно заранее
  (`PersistenceAuditor.Prefetch`, потокобезопасный кэш).
- Слабые находки (LogOnly) у образа с действительной подписью любого издателя (Termius, установщики Electron/NSIS: MEM-RWX-IMAGE-PATCH [Low])
  больше не становятся событием и строкой отчёта; правило брандмауэра для подписанной программы неизвестного издателя остаётся Info
  и с 1.3.4 скрыто в отчёте.
- Не сделано (нужна Windows/решение): обновление MSI с интерфейсом при запущенной службе и окне (Restart Manager), подпись Authenticode,
  память Sentinel.App 450–470 МБ, замер полной проверки на 1.3.3+.

### 1.3.5 — вычистка семейств и удаление из карантина
- В main слита ветка семейств CAAService/techias (PR masterRaizer/Antivirus-tool#10): правила `rules/families.json`, поведенческие находки
  аудиторов, корреляция и плейбук `sentinel family-scan` / `family-clean --confirm [--block-ioc]` с откатом — см. `docs/THREAT_FAMILIES.md`.
  При слиянии: проверка процессов в сканировании идёт параллельно и с контекстом (родитель, таблица TCP — `AuditInContext`), политика
  «поведенческие находки семейства — решение за пользователем» встроена в общий маршрут `DispatchAuditedProcessAsync`.
- `sentinel quarantine delete <id> --confirm` — удалить файл из карантина навсегда (без `--confirm` — только показать, что будет удалено);
  в окне это кнопка «Удалить навсегда» в разделе «Карантин». Каждое удаление пишется в `Logs\file-actions.jsonl`.

- Раздел «Автозагрузка и службы» был пустым: сводку собирал отдельный полный аудит (1–3 мин, без индикации и без обработки ошибок),
  а службы и задачи без находок в таблицу не попадали; колонка оценки заполнялась только у помеченных записей. Теперь сводка берёт общий
  аудит службы (кэш/идущий), аудит службы включает штатные записи (`IncludeCleanEntries`: включённые задачи и автозапускаемые службы
  пользовательского режима, без драйверов), у каждой записи есть оценка (`StartupItem.Assessment`: уровень находки, «Норма»,
  «Без подписи», «Разрешено»), ошибка загрузки показывается текстом.

### 1.3.6 — ложные срабатывания правила майнинг-пулов на списках блокировки
- На ноутбуке 1.3.3 отправил в карантин 8 файлов расширения AdBlock (`gighmmpiobklfepjocnamgkkbiglidom\…\data\rules\abp\…`) и
  подписки Edge (`Subresource Filter\Unindexed Rules\…\Part-FR`, `WebExperience\…\EBWebView`) по `SNT-MINER-0002 CryptoMiner_Pool_Domains`:
  списки блокировки перечисляют домены пулов, чтобы их блокировать, а тип `config` включал файлы без расширения.
- `SNT-MINER-0002` теперь только для исполняемых файлов (PE или исполняемое расширение). Скрипты и конфигурации — новое правило
  `SNT-MINER-0003 CryptoMiner_Pool_Endpoint`: адрес пула с портом (`host:`) или адрес пула вместе с параметрами майнера
  (`"pools"`, `donate-level`, `rig-id`, `--coin`, `--url`, `--user`). Голые домены в фильтрах ABP/uBlock/hosts/DNR — не находка (тесты `PoolRules_DoNotFire_OnBlocklists`).
- **На проверку:** после установки 1.3.6 восстановить 8 файлов AdBlock кнопкой «Восстановить»; повторная полная проверка не должна их трогать.

## На проверку пользователю на ноутбуке с Windows (Hardware-in-the-Loop)
- **1.3.1 на Katana:** чистая установка MSI и обновление поверх 1.3.0 — код 0, `SentinelService` Running/Automatic, `sc.exe qfailure SentinelService`
  показывает RESTART 5000/30000/60000 и сброс 86400; в `service-*.log` — «Восстановление службы: Политика восстановления выставлена…»;
  служебные команды powershell/cmd (Bypass, Invoke-Expression, -Encoding UTF8) не порождают событий; `powershell -enc <base64>` и
  `iwr … | iex` — по-прежнему находки (для подписанного powershell.exe — AskUser с командной строкой в карточке).
  «Полная» проверка: процент растёт по этапам, на «Автозагрузке» — «результат фонового аудита службы (N с назад)» или «идёт аудит, N с», затем «Файлы» от 15 %.
- **Контрольная проверка 1.3.0 — пройдена на `f77f5b7` (см. выше); чек-лист для повторных проверок:**
  1. Журнал `%ProgramData%\Sentinel\Logs\service-*.log`: в первые секунды после `sc start SentinelService` — «Драйвер ядра [kernel]: …»,
     «Драйвер ядра: защищаемых процессов N (…)», «Мониторинг старта процессов запущен (источник: драйвер ядра)»; `sentinel.exe service-status` отвечает сразу.
  2. Запуск `cmd.exe`/`conhost.exe` — никаких `PROC-IMPERSONATION` и завершений системных процессов.
  3. `sc stop SentinelDrv` при работающей службе — `STATE 1 STOPPED` за 2–3 с; в журнале «Драйвер ядра отключён: …»; `sc start SentinelDrv` —
     через ≈15 с «Драйвер ядра подключён» и снова «защищаемых процессов N» (переподключение раз в 10 с + синхронизация PID).
  4. Служба, запущенная из `C:\Sentinel-v1.3.0\`, не отключает сама себя (в журнале нет `SentinelService [Service] … Cleaned`).
  5. `powershell -ExecutionPolicy Bypass -File .\scripts\test-memory-scanner.ps1 -WithPeHeader` при работающей службе — через ~2 с событие по
     `powershell.exe` с `MEM-YARA-MATCH`/`MEM-REFLECTIVE-PE` (критичность Critical) без ручного `audit-memory`; ожидаемый итог — AskUser /
     PendingDecision: powershell.exe подписан Microsoft, поэтому `FalsePositiveGuard` оставляет решение пользователю.
  6. В `dist` нет `rules\rules` и `data\data`; `sentinel.exe rules` — без «Дублирующийся id правила».
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
- **8/4 — драйвер в режиме Test Signing** (только тестовый ноутбук; драйвер запускается вручную — `start= demand`, при сбое перезагрузка его не поднимет):
  1. Скачать со страницы прогона GitHub Actions артефакт `Sentinel-v1.3.0-<sha>` → `driver\` (`SentinelDrv.sys`, `SentinelDrvTest.cer`,
     `install-driver-testmode.ps1`, `SentinelDrv.inf`) и `Sentinel-v1.3.0-setup-win-x64.msi`. Сертификат и драйвер — из одного прогона.
  2. PowerShell от администратора: `Confirm-SecureBootUEFI` — при `True` отключить Secure Boot в UEFI (иначе testsigning не включится).
  3. `bcdedit /set testsigning on`, перезагрузка (в углу рабочего стола — «Тестовый режим»).
  4. `certutil -addstore Root SentinelDrvTest.cer` и `certutil -addstore TrustedPublisher SentinelDrvTest.cer`.
  5. `copy SentinelDrv.sys C:\Windows\System32\drivers\`, затем `sc create SentinelDrv type= kernel start= demand binPath= System32\drivers\SentinelDrv.sys`
     и `sc start SentinelDrv` (шаги 4–5 делает `powershell -ExecutionPolicy Bypass -File .\install-driver-testmode.ps1 -Action Install`).
  6. `sentinel.exe kernel-status` → «Режим: kernel», защита дескрипторов и телеметрия «активна», версия 1.3.0 / протокол 1.
  7. Установить MSI 1.3.0, `sc start SentinelService`; через ~10 с `sentinel.exe kernel-status` — «Защищаемых PID» ≥ 6, в журнале службы
     «Драйвер ядра [kernel]: …» и «Драйвер ядра: защищаемых процессов N (…)».
  8. Защита: запомнить «Снято опасных прав», выполнить `taskkill /F /IM Sentinel.Service.exe` (и попытку завершить службу из Process Explorer) —
     ожидается «Отказано в доступе», служба жива, счётчик «Снято опасных прав» вырос. `taskkill /F /IM notepad.exe` работает как обычно.
  9. Телеметрия: запустить `notepad.exe` и `powershell -enc <base64>` — «Событий всего» растёт, по powershell — событие `process-start` с BH-02.
  10. Fail-Open: `sc stop SentinelDrv` при работающей службе — в журнале «Kernel driver not loaded, running in User-Mode EDR profile», мониторинг
      старта продолжается через WMI; `sentinel.exe kernel-status` — «Режим: user-mode». Удаление: `install-driver-testmode.ps1 -Action Uninstall`,
      `bcdedit /set testsigning off`, перезагрузка.
  11. При BSOD — прислать `C:\Windows\Minidump\*.dmp` (или `MEMORY.DMP`) и вывод `sentinel.exe kernel-status --json` до сбоя.
- `WinVerifyTrust`, реестровые и сервисные аудиторы, удаление исключений Defender.
- `Sentinel.App` (WPF) и `Sentinel.Service` (установка MSI, DACL-самозащита, автоподключение Named Pipe, раздел «Поведенческий щит и USB»).
- Безопасный режим и WinRE (1.1.1).
- Модули 1.3.0 после сборки в GitHub Actions (`ProcessStartMonitor`, `MemoryIntegrityScanner`, `SentinelDrv.sys` в режиме Test Signing).

## Команды
```bash
bash scripts/setup-linux.sh
dotnet build Sentinel.sln
dotnet test Sentinel.sln
