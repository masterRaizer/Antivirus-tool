# HANDOFF — Sentinel

Обновлено: 2026-11-15 (UTC). Ведёт `repo-scout`; правила — скилл `sentinel-stage-flow`.

## Ветка и коммит
- Основная ветка: `main` = этапы 1–3 (вершина этапа 3 — `5c6cd1f`, «Stage 3 (6/6)») + скиллы `.claude/skills/` + этот файл. Ветка `claude/sentinel-stage-3-quarantine-dfzize` — тот же код этапа 3.
- Старые ветки `claude/funny-cray-ckg20j` (этап 1), `claude/lucid-ride-xnd3ng` (этап 2), `claude/modest-knuth-cjvnqo` (этап 1) устарели; новые работы вести от `main`.
- Этап 4 закоммичен в ветку `claude/sentinel-stage-3-quarantine-dfzize` пятью коммитами `Stage 4 (1/5)…(5/5)` поверх этапа 3; в `main` не слит.

## Статус этапов
| Этап | Содержание | Статус |
|---|---|---|
| 1 | Sentinel.Core: анализ PE, хеши, энтропия, 5 правил, CLI, selftest 7/7 | Готов. WinVerifyTrust не проверен на Windows |
| 2 | ProcessAuditor, PersistenceAuditor, ConfigIntegrityAuditor, CLI `audit-*` | Готов. 234 теста зелёные, 3 пропущены на Linux (после этапа 2) |
| 3 | QuarantineManager, RemediationEngine (манифесты отката), JSON/HTML-отчёты, CLI remediation/quarantine/rollback, сквозной тест | Готов (6/6). Тесты после этапа 3 (Linux, SDK 8.0.134): 331 всего, 327 passed, 0 failed, 4 skipped (все 4 — Windows-only `WindowsFact`) |
| 4 | `allowed_exclusions.json`, диспетчер «опасное сразу, спорное спросить», IPC по Named Pipes, `SentinelRuntime`, `Sentinel.Service`, `Sentinel.App` (WPF), `scripts/publish-windows.ps1` | Готов (5/5). Linux, SDK 8.0.428: build 0 ошибок / 0 предупреждений; 403 теста — 399 passed, 0 failed, 4 skipped (`WindowsFact`). На Windows не запускался |

| 5 | Релизы в GitHub Actions: `.github/workflows/release.yml` (windows-latest: тесты, `publish-windows.ps1`, MSI на WiX 5.0.2, GitHub Release с `.msi` и `Sentinel.App.exe`), `installer/Sentinel.Installer/` (вне `Sentinel.sln`), шаблон `allowed_exclusions.json` | Release `v1.0.0` опубликован (run на `main` зелёный: тесты, publish, MSI). Linux: build 0/0, 411 тестов — 407 passed, 4 skipped. Запуск MSI/службы/WPF на живой Windows не проверялся |
| 6 | Версия 1.1.0: скоринг угроз (0–100), потоковый `FileAnalyzer`, импорт PE и .NET, режимы Quick/Full/Custom с защитой от ReparsePoint, кэш чистых файлов, самозащита; база угроз `data/threat_hashes.bin` (11 743 SHA-256, MemoryMappedFile) с обновлятором (GitHub IOC, Feodo, abuse.ch API по ключу) и облачной проверкой по ключу; пул проверки (процессы `Sentinel.Cli.exe --scan-worker` или потоки); исправления по отчёту 1.0.0 (hosts, брандмауэр, сертификаты, WMI, IEX, geosite.dat); ACL канала для AuthenticatedUsers, автоподключение 2 с, «Запустить службу»; WPF — контраст, виртуализация, группировка Info, раздел «Настройки и базы»; WiX 1.1.0 с базой и восстановлением службы | Linux, Release: build 0/0, 538 тестов — 533 passed, 5 skipped (Windows-only). Сканирование памяти процессов, перехват запуска процессов и USB-щит в 1.1.0 не входят |

## Следующие шаги
1. Проверка на Windows: установка MSI `v1.1.0` поверх `v1.0.0` (MajorUpgrade, сохранность `C:\ProgramData\Sentinel\allowed_exclusions.json`), запуск службы, автоподключение приложения, все 7 разделов, «Обновить базы».
2. По итогам проверки — правки UI/службы; слияние ветки в `main` по решению пользователя.
3. После каждого модуля обновлять этот файл.

## Не проверено / нужна проверка на Windows
- `WinVerifyTrust` (проверка подписей) — реальная работа на Windows.
- Реестровые и сервисные аудиторы — интеграционные тесты `WindowsFact` пропускаются на Linux.
- Удаление исключений Defender и завершение дерева процессов — на живой системе.
- `Sentinel.App` (WPF): только скомпилирован кросс-сборкой, ни разу не запускался — вёрстка, шаблоны контролов, трей, всплывающее окно решения, диалог выбора папки, экспорт отчётов.
- `Sentinel.Service`: установка через `sc.exe`, запуск под LocalSystem, ACL каталога данных и именованного канала, подключение приложения пользователя к службе SYSTEM. На Linux служба проверена как консольный процесс (канал, монитор файлов, карантин EICAR).
- `WindowsTelemetryProvider` (GetSystemTimes, GlobalMemoryStatusEx, PDH) — только компиляция.
- `WindowsDefenderExclusionSource` (WMI `MSFT_MpPreference` через CIM) — только компиляция и разбор JSON в тестах; на Windows не запускался.

## Команды
```
bash scripts/setup-linux.sh
dotnet build Sentinel.sln
dotnet test Sentinel.sln
```
SDK закреплён в `global.json` (8.0.100, rollForward latestFeature). Для сборки WPF нужен SDK с `Microsoft.NET.Sdk.WindowsDesktop`: в apt-пакете Ubuntu его нет, `setup-linux.sh` доустанавливает сборку Microsoft в `/usr/local/share/dotnet-ms`.

## Не проверено в 1.1.0 (только Linux-тесты и компиляция)
- Пул из процессов `Sentinel.Cli.exe --scan-worker` на Windows (на Linux проверен с `dotnet sentinel.dll`), скорость объектов/сек на живом диске, время замены упавшего рабочего.
- `NamedPipeServerStreamAcl` с правилом AuthenticatedUsers и подключение приложения пользователя к службе SYSTEM; кнопка «Запустить службу» (UAC).
- `WindowsDefenderExclusionSource` (CIM `MSFT_MpPreference`), чтение `LocalMachine\AuthRoot` и `CurrentUser\Root`.
- Обновление баз с реальной сетью (`api.github.com`, `raw.githubusercontent.com`, Feodo Tracker, abuse.ch API с ключом), облачные Kaspersky OpenTIP и VirusTotal.
- WPF 1.1.0: внешний вид тёмной темы, группировка Expander, раздел «Настройки и базы», PasswordBox.
- WiX: `ServiceConfigFailureActions`, обновление поверх 1.0.0.

## 1.1.1 — Безопасный режим и WinRE
- Сделано: определение Безопасного режима (`GetSystemMetrics(SM_CLEANBOOT)`, `SAFEBOOT_OPTION`) и WinRE (`X:\Windows\System32\winpeshl.ini`, `HKLM\...\Control\MiniNT`); программный рендеринг WPF и сразу автономный режим «Режим восстановления (Автономно)» без ожидания канала; каталог данных по первой доступной для записи папке (`%ProgramData%\Sentinel` → `SentinelData` рядом с exe → `%LocalAppData%\Sentinel` → `%TEMP%\SentinelData`); шаги аудита изолированы (пропуск с причиной в журнале и отчёте); ручной ввод пути в «Выборочной папке»; ключи `SafeBoot\Minimal|Network\SentinelService` в MSI.
- Не проверено: запуск в настоящем Безопасном режиме и в WinRE (программный рендеринг, отсутствие PowerShell/WMI), старт службы в Безопасном режиме по ключам SafeBoot.

## Этап 7 (v1.2.0) — User-Mode EDR
### 7/1 NativePersistenceParser (готово)
- `src/Sentinel.Core/Auditors/Persistence/`: `NativePersistenceParser`, `CommandLineSplitter`, `UnquotedServicePathDetector`, `TaskXmlStreamReader` (FileStream 64 КБ + защищённый XmlReader/XDocument, без ReadAllText), `ScheduledTaskReconciler` (Ghost/Orphan/Hidden), `TaskDirectoryWalker` (пропуск ReparsePoint), `WindowsNativePersistenceSource` (SCM P/Invoke + реестр) и `WindowsScheduledTaskSource` (`[SupportedOSPlatform("windows")]`).
- Детекты: Unquoted Service Path, ServiceDll в профиле, FailureCommand, IFEO Debugger/SilentProcessExit, SafeBoot (белый список SentinelService/SentinelDrv), AppInit_DLLs, Winlogon, ComHandler, Ghost/Orphan/Hidden задачи.
- Проверка: build 0/0, 580 тестов (575 passed, 5 Windows-only skipped). Не проверено на Windows: SCM-состояние служб, чтение реестра/TaskCache, обход System32\Tasks.
### 7/2 RansomwareBehaviorShield + CanaryFileGuard (готово)
- `src/Sentinel.Core/Behavioral/`: `CanaryFileGuard` (приманки с валидными заголовками + SHA-256, реестр путей, Inspect/RemoveUntouched, вес +85) и `RansomwareBehaviorShield` (окно 5 с, дебаунс 300 мс, исключение node_modules/.git/bin/obj/кэшей, потоковая энтропия, пороги всплеск+расширение+энтропия, тревога ≥75).
- Проверка: build 0/0, 588 тестов (583 passed, 5 Windows-only skipped). Чистый всплеск текстовых файлов и работа в .git/node_modules тревогу не вызывают.
### 7/3 BehavioralCorrelationEngine + FalsePositiveGuard (готово)
- `FalsePositiveGuard`: самозащита с защитой от маскировки (поддельный C:\Temp\lsass.exe не иммунен), белый список (путь/хеш), кэш чистых файлов, подпись −35 и запрет авто-карантина подписанного/в теневом режиме; пороги LogOnly/AskUser/Act.
- `BehavioralCorrelationEngine`: кольцевой буфер (2048, окно 60 с), цепочки BH-01 (дроппер+ярлык/автозапуск, +50), BH-02 (обфускация/fileless, +55), BH-03 (автозапуск на неподписанный профильный бинарник, +65).
- Проверка: build 0/0, 609 тестов (604 passed, 5 Windows-only skipped).
### 7/4 RemovableMediaShield — USB-щит (готово)
- `src/Sentinel.Core/Protection/`: `ShellLinkBinaryParser` ([MS-SHLLINK], Unicode/ANSI, IconLocation), `AutorunInfParser` (потоковый, секция [autorun]), `RemovableMediaShield` (обход глубиной 2 с пропуском ReparsePoint; детекторы autorun.inf, USB-червь скрытой папки, двойное расширение, вредоносный .lnk с подменой значка, инъектируемый анализатор бинарников), `PollingRemovableDriveWatcher` (опрос DriveInfo без WMI, DiffNew).
- Проверка: build 0/0, 629 тестов (624 passed, 5 Windows-only skipped). Атрибут Hidden на Linux не ставится — детект червя покрыт чистым помощником DetectWorm и WindowsFact оставлен на будущее.
### 7/5 Интеграция в Service/CLI/WPF (готово)
- `SentinelConfig`: флаги `EnableRansomwareShield`/`EnableCanaryFiles`/`EnableUsbShield`/`BehavioralShadowMode` (обратная совместимость со старым конфигом).
- `SentinelRuntime.Behavioral.cs`: приманки, наблюдение файловой активности (встроено в InspectFileAsync, приманки пропускаются сканером), `ScanRemovableAsync`, `GetBehavioralStatus(Async)`; USB-щит использует FileAnalyzer рантайма как анализатор бинарников.
- IPC: `behavioral.status`, `behavioral.scanusb` + флаги в SettingsSnapshot/Update; `BackendHub` проброс.
- CLI: `scan-usb [путь]`, `behavioral-status`. WPF: раздел «Поведенческий щит и USB» (переключатели, проверка USB, статус приманок, лента цепочек), виртуализация списков.
- Проверка: build 0/0, 632 теста (627 passed, 5 Windows-only skipped).
### 7/6 Архитектурный документ, версия 1.2.0, релиз (готово)
- `docs/ARCHITECTURE_V2_KERNEL_SPEC.md`: проект связки Ring 0/Ring 3 (minifilter, коллбэки, FilterCommunicationPort, таймауты/Fail-Open, матрица самозащиты, план IKernelBridge/NullKernelBridge). Без .vcxproj/C++ — решение остаётся кросс-сборочным.
- Версия продукта 1.2.0 (wixproj, Directory.Build.props, release.yml).
- Проверка: Release build 0/0, 632 теста (627 passed, 5 Windows-only skipped).

## Этап 7 итог: v1.2.0 — User-Mode EDR без драйвера ядра
Не входят в v1.2.0 (требуют Ring 0 или остановлены ранее): перехват запуска процессов, сканирование сырой памяти процессов. Весь поведенческий анализ — User-Mode.
Не проверено на Windows: SCM/реестр/TaskCache нативных источников, поведенческий щит на живом FileSystemWatcher, USB-щит на реальной флешке (атрибуты Hidden/ReparsePoint), WPF-раздел «Поведенческий щит и USB».


## v1.3.0 (в работе) — самозащита процесса
- Сделано (User-Mode, проверено): `CriticalProcessGuard` (предохранитель деструктивных действий: системные процессы в системных каталогах, подписанные Microsoft, сам Sentinel; маскировка под lsass в Temp НЕ защищается), `ProcessSelfProtection` (расчёт усиленного DACL — ядро, кросс-платформенно, тесты), `ProcessSelfProtectionApplier` (Windows: GetKernelObjectSecurity/SetKernelObjectSecurity на своём процессе, подключён в Program.cs). Build 0/0, 638 тестов (633 passed, 5 Windows-only skipped).
- Не проверено на Windows: применение DACL к живому процессу службы (логика расчёта прав покрыта тестами).
- НЕ реализуется в этой сессии (остановленная граница безопасности): WDK-драйвер `driver/SentinelDrv`, перехват запуска процессов, сканер виртуальной памяти чужих процессов, заморозка чужих процессов (NtSuspendProcess), ETW-перехват с блокировкой, подпись драйвера в CI. Критические инварианты самозащиты ОС в CLAUDE.md сохранены.
