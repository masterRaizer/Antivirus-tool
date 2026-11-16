# HANDOFF — Sentinel

Обновлено: 2026-11-16 (UTC). Ведёт `repo-scout`; правила — скиллы `sentinel-stage-flow` и `av-core-engineer`.

## Ветка и коммит
- Основная ветка: `main` — включает этапы 1–7 (релиз `v1.2.0` + `SelfProtection` DACL и `CriticalProcessGuard`), скиллы `.claude/skills/` и актуальную документацию.
- Старые ветки этапов 1–4 устарели; все новые работы для этапа 8 (`v1.3.0`) вести от актуального `main` по одному модулю за итерацию.

## Статус этапов
| Этап | Содержание | Статус |
|---|---|---|
| 1 | Sentinel.Core: анализ PE, хеши, энтропия, 5 правил, CLI, selftest 7/7 | Готов. WinVerifyTrust не проверен на Windows |
| 2 | ProcessAuditor, PersistenceAuditor, ConfigIntegrityAuditor, CLI `audit-*` | Готов. 234 теста зелёные, 3 пропущены на Linux (после этапа 2) |
| 3 | QuarantineManager, RemediationEngine (манифесты отката), JSON/HTML-отчёты, CLI remediation/quarantine/rollback, сквозной тест | Готов (6/6). Тесты после этапа 3 (Linux, SDK 8.0.134): 331 всего, 327 passed, 0 failed, 4 skipped (все 4 — Windows-only `WindowsFact`) |
| 4 | `allowed_exclusions.json`, диспетчер «опасное сразу, спорное спросить», IPC по Named Pipes, `SentinelRuntime`, `Sentinel.Service`, `Sentinel.App` (WPF), `scripts/publish-windows.ps1` | Готов (5/5). Linux, SDK 8.0.428: build 0 ошибок / 0 предупреждений; 403 теста — 399 passed, 0 failed, 4 skipped (`WindowsFact`). |
| 5 | Релизы в GitHub Actions: `.github/workflows/release.yml` (windows-latest: тесты, `publish-windows.ps1`, MSI на WiX 5.0.2, GitHub Release с `.msi` и `Sentinel.App.exe`), `installer/Sentinel.Installer/` (вне `Sentinel.sln`), шаблон `allowed_exclusions.json` | Release `v1.0.0` опубликован (run на `main` зелёный: тесты, publish, MSI). Linux: build 0/0, 411 тестов — 407 passed, 4 skipped. |
| 6 | Версия 1.1.0 / 1.1.1: скоринг угроз (0–100), потоковый `FileAnalyzer`, импорт PE и .NET, режимы Quick/Full/Custom с защитой от ReparsePoint, кэш чистых файлов, самозащита; база угроз `data/threat_hashes.bin` (11 743 SHA-256, MemoryMappedFile) с обновлятором (GitHub IOC, Feodo, abuse.ch API по ключу) и облачной проверкой по ключу; пул проверки (процессы `Sentinel.Cli.exe --scan-worker` или потоки); исправления по отчёту 1.0.0 (hosts, брандмауэр, сертификаты, WMI, IEX, geosite.dat); ACL канала для AuthenticatedUsers, автоподключение 2 с, «Запустить службу»; WPF — контраст, виртуализация, группировка Info, раздел «Настройки и базы»; WiX 1.1.0 с базой и восстановлением службы; Безопасный режим и WinRE (1.1.1) | Готов, слит в `main`. Linux, Release: build 0/0, 538 тестов — 533 passed, 5 skipped (Windows-only). |
| 7 | Версия 1.2.0: `NativePersistenceParser` (7/1), `RansomwareBehaviorShield` + `CanaryFileGuard` (7/2), `BehavioralCorrelationEngine` + `FalsePositiveGuard` (7/3), `RemovableMediaShield` — USB-щит (7/4), интеграция в Service/CLI/WPF (7/5), спецификация `docs/ARCHITECTURE_V2_KERNEL_SPEC.md` (7/6), DACL-самозащита (`SelfProtection`) и `CriticalProcessGuard` (7/7) | Готов, слит в `main`. Release build 0/0, 632+ теста зелёные. |
| 8 | Версия 1.3.0 (В работе): реализация активных модулей по спецификации `docs/ARCHITECTURE_V2_KERNEL_SPEC.md` и двухконтурной схеме верификации (Dual-Target CI): (8/1) `ProcessStartMonitor` (подписка на события старта процессов в реальном времени); (8/2) `MemoryIntegrityScanner` в `ProcessAuditor` (потоковая проверка регионов `MEM_PRIVATE`/`PAGE_EXECUTE_READWRITE` буфером 64 КБ через `IMemoryReader`); (8/3) изоляция потоков в `RemediationEngine` перед карантином (строго под защитой `CriticalProcessGuard`); (8/4) `IKernelBridge`/`DriverTelemetryBridge` и сборка нативного драйвера `driver/SentinelDrv` (вне `Sentinel.sln`) на раннере `windows-latest` в `.github/workflows/release.yml` | В работе |

## Следующие шаги (Этап 8 — v1.3.0)
1. **Модуль 8/1 (`ProcessStartMonitor`)**: подписка на события старта процессов в `Sentinel.Core` / `Sentinel.Service` через интерфейс `IProcessCreationEventSource`, фильтрация через `CriticalProcessGuard` и `allowed_exclusions.json`, передача в `FileAnalyzer`, `ProcessAuditor` и `BehavioralCorrelationEngine`.
2. **Модуль 8/2 (`MemoryIntegrityScanner`)**: расширение `ProcessAuditor` для потоковой проверки секций памяти с `PAGE_EXECUTE_READWRITE` чанками по 64 КБ через интерфейс `IMemoryReader` (поиск заголовков `MZ`/`PE` в приватной памяти и прогон по правилам YARA) с обязательным пропуском защищённых процессов через `CriticalProcessGuard`.
3. **Модуль 8/3 (Изоляция потоков перед карантином)**: в `RemediationEngine` перед завершением дерева процессов и перемещением файла в `QuarantineManager` добавить предварительную приостановку потоков процесса, получившего финальный вердикт `Malicious`, строго после проверки `CriticalProcessGuard` и `FalsePositiveGuard`.
4. **Модуль 8/4 (`IKernelBridge` + `driver/SentinelDrv`)**: реализация `IKernelBridge` (с `NullKernelBridge` / graceful fallback в User-Mode, если драйвер не загружен) по спецификации `docs/ARCHITECTURE_V2_KERNEL_SPEC.md`, создание `driver/SentinelDrv` (вне `Sentinel.sln`) и добавление шага его компиляции и тестовой подписи на `windows-latest` в `.github/workflows/release.yml`.
5. После каждого модуля прогонять `dotnet build Sentinel.sln` и `dotnet test Sentinel.sln`, а для нативных компонентов — проверять сборку в GitHub Actions (`gh run list`, `gh run view <run-id> --log-failed`) и обновлять этот файл.

## Не проверено / нужна проверка на Windows (стенд пользователя)
- `WinVerifyTrust` (проверка подписей) — реальная работа на Windows.
- Реестровые и сервисные аудиторы — интеграционные тесты `WindowsFact` пропускаются на Linux.
- Удаление исключений Defender и завершение дерева процессов — на живой системе.
- `Sentinel.App` (WPF): вёрстка, шаблоны контролов, трей, всплывающее окно решения, диалог выбора папки, экспорт отчётов, раздел «Поведенческий щит и USB».
- `Sentinel.Service`: установка через `sc.exe`/MSI, запуск под LocalSystem, DACL-самозащита, ACL каталога данных и именованного канала, подключение приложения пользователя к службе SYSTEM.
- `WindowsTelemetryProvider` (GetSystemTimes, GlobalMemoryStatusEx, PDH) и `WindowsDefenderExclusionSource` (WMI `MSFT_MpPreference` через CIM).
- Запуск в настоящем Безопасном режиме и в WinRE (1.1.1).
- Нативные источники SCM/реестра/TaskCache, поведенческий щит на живом FileSystemWatcher, USB-щит на реальной флешке (1.2.0).

## Команды
```bash
bash scripts/setup-linux.sh
dotnet build Sentinel.sln
dotnet test Sentinel.sln
