# CLAUDE.md — Sentinel EDR

Sentinel — защитный EDR-инструмент аудита целостности и активной защиты хоста Windows: анализ PE, сигнатуры (YARA-подобные правила и JSON-правила майнеров), потоковый аудит процессов и памяти, защита дескрипторов, автозагрузки и конфигурации, карантин с изоляцией процессов и откатом, отчёты и защита в реальном времени (User-Mode Service + Kernel-Mode Callback/Minifilter Driver). Состояние этапов — в `HANDOFF.md`.

## Архитектура

| Каталог | Назначение |
|---|---|
| `src/Sentinel.Core` | Вся логика: анализ PE, хеши и энтропия, правила, аудиторы (процессы, память, персистентность, конфигурация), ETW-телеметрия, самозащита DACL, карантинная изоляция процессов, `QuarantineManager`, `RemediationEngine`, отчёты, диспетчер событий, IPC по Named Pipes, мост к драйверу (`FilterConnectCommunicationPort`), `SentinelRuntime`. |
| `src/Sentinel.Cli` | Консольный сканер (`Sentinel.Cli.exe`, внутреннее имя сборки `sentinel`): сканирование, `audit-*`, карантин и откат. |
| `src/Sentinel.Service` | Worker Service под `LocalSystem` (`SentinelService`): защита в реальном времени, DACL-самозащита, ETW-монитор, USB-щит, IPC-сервер и обмен с `SentinelDrv.sys`. |
| `src/Sentinel.App` | Десктопное приложение WPF (`Sentinel.App.exe`): интерфейс, трей, решения пользователя, статус драйвера ядра. |
| `driver/SentinelDrv` | Драйвер ядра Windows на C / WDK (`SentinelDrv.sys`, `.vcxproj`, `.inf`). **Не входит в `Sentinel.sln`** — компилируется и подписывается тестовым сертификатом в GitHub Actions (`windows-latest`). |
| `installer/Sentinel.Installer` | MSI на WiX v5 (`WixToolset.Sdk` 5.0.2). **Не входит в `Sentinel.sln`** — собирается только на Windows в GitHub Actions. |
| `tests/Sentinel.Core.Tests` | xUnit-тесты. Windows-only тесты помечены `WindowsFact` и на Linux пропускаются. |
| `rules/` | Сигнатурные правила (`*.yar`, `miners.json`). |
| `allowed_exclusions.json` | Шаблон белого списка пользователя; копируется в `dist\` и MSI. |

## Модель сборки и верификации (Dual-Target CI + Hardware-in-the-Loop)

Проект использует двухконтурную модель проверки:
1. **Контур Linux (локальный контейнер агента):**
   - Проверка управляемого кода `.NET 8` через `dotnet build Sentinel.sln` и `dotnet test Sentinel.sln` (0 ошибок, 0 предупреждений).
   - Проекты `installer/Sentinel.Installer` и `driver/SentinelDrv` НЕ включаются в `Sentinel.sln`, чтобы не ломать кросс-сборку на Linux.
2. **Контур Windows (GitHub Actions `windows-latest` + живой стенд пользователя):**
   - Компиляция нативного драйвера `driver/SentinelDrv` (MSVC + Windows Driver Kit), генерация тестового сертификата, подпись `.sys`/`.cat` и сборка MSI-установщика выполняются автоматически в GitHub Actions (`.github/workflows/release.yml`).
   - Написание кода драйвера `SentinelDrv.sys` и P/Invoke обёрток Win32 в Linux-контейнере с последующей компиляцией через GitHub Actions **разрешено и является штатным процессом разработки** (это НЕ считается заглушкой).
   - Верификация компиляции драйвера и MSI проводится агентом по логам GitHub Actions (`gh run list`, `gh run view <id> --log-failed`).
   - Приёмочное и динамическое тестирование (`sc start`, проверка `ObRegisterCallbacks`, `PsSetCreateProcessNotifyRoutineEx`, UI и карантина) выполняет пользователь на своём ноутбуке с Windows (Test Signing Mode / VM) и передаёт логи обратно в чат.

## Правила безопасности и качества кода

- Никаких пустых `// TODO` в продакшене: каждый модуль реализуется полностью.
- Никакого `File.ReadAllBytes` для сканируемых файлов — только потоковое чтение буфером 64 КБ (`IncrementalHash` SHA-256 + потоковая энтропия).
- При обходе каталогов пропускать `ReparsePoint` (junction/symlink).
- **Строгая защита от ложных срабатываний (Critical Process Guard):** категорически запрещено приостанавливать, завершать, блокировать или модифицировать системные процессы `csrss`, `smss`, `lsass`, `wininit`, `services`, `svchost`, `explorer`, `ntoskrnl`, `winload.efi`, а также собственные процессы `SentinelService`, `Sentinel.App`, `Sentinel.Cli` и каталоги `C:\Program Files\Sentinel`, `C:\ProgramData\Sentinel`.
- В драйвере ядра (`SentinelDrv.sys`) все колбэки должны иметь строгую проверку IRQL (`PASSIVE_LEVEL`), валидацию указателей и безопасную выгрузку (`DriverUnload` / `FilterUnload`) без утечек пулов памяти, чтобы исключить BSOD.
