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
2. **Модуль 8/2 (`MemoryIntegrityScanner`)**: расширение `ProcessAuditor` для потоковой проверки секций памяти с `PAGE_EXECUTE_READWRITE` чанками по 64 КБ через интерфейс `IMemoryReader` (поиск заголовков `MZ`/`PE` в приватной памяти и прогон по правилам YARA) с обязательным пропуском защищённых процессов через `CriticalProcessGuard`.
3. **Модуль 8/3 (Изоляция потоков перед карантином)**: в `RemediationEngine` перед завершением дерева процессов и перемещением файла в `QuarantineManager` добавить предварительную приостановку потоков процесса (через интерфейс `IProcessContainment`), получившего финальный вердикт `Malicious`, строго после проверки `CriticalProcessGuard` и `FalsePositiveGuard`.
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

## На проверку пользователю на ноутбуке с Windows (Hardware-in-the-Loop)
- **8/1:** в журнале службы при старте — «Мониторинг старта процессов: подписка WMI (SELECT * FROM Win32_ProcessStartTrace)». Запуск `powershell -enc <base64>` даёт
  в разделе «Поведенческий щит и USB» цепочку `Process: … (BH-02)` и событие с источником `process-start`. Маскировка: копия безвредного .exe,
  запущенная как `C:\Temp\svchost.exe`, — находка `PROC-IMPERSONATION`; неподписанная копия завершается и уходит в карантин, копия с действительной
  подписью Microsoft — только запрос решения (AskUser). Безопасный режим: в журнале — переход на опрос.
- `WinVerifyTrust`, реестровые и сервисные аудиторы, удаление исключений Defender.
- `Sentinel.App` (WPF) и `Sentinel.Service` (установка MSI, DACL-самозащита, автоподключение Named Pipe, раздел «Поведенческий щит и USB»).
- Безопасный режим и WinRE (1.1.1).
- Модули 1.3.0 после сборки в GitHub Actions (`ProcessStartMonitor`, `MemoryIntegrityScanner`, `SentinelDrv.sys` в режиме Test Signing).

## Команды
```bash
bash scripts/setup-linux.sh
dotnet build Sentinel.sln
dotnet test Sentinel.sln
