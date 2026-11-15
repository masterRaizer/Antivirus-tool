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
