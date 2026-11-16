# CLAUDE.md — Sentinel

Sentinel — защитный инструмент аудита целостности и активной защиты хоста Windows: анализ PE, сигнатуры (YARA-подобные правила и
JSON-правила майнеров), потоковый аудит процессов и виртуальной памяти, поведенческая корреляция, защита дескрипторов и самозащита (DACL / Kernel Callbacks), аудит автозагрузки и конфигурации, карантин с изоляцией потоков и откатом, отчёты и защита
в реальном времени. Состояние этапов и список непроверенного — в `HANDOFF.md`, спецификация связки Ring 0 / Ring 3 — в `docs/ARCHITECTURE_V2_KERNEL_SPEC.md`.

## Архитектура

| Каталог | Назначение |
|---|---|
| `src/Sentinel.Core` | Вся логика: анализ PE, хеши и энтропия, правила, аудиторы (процессы, виртуальная память, персистентность, конфигурация), поведенческий движок, предохранители (`FalsePositiveGuard`, `CriticalProcessGuard`, DACL `SelfProtection`), USB-щит, мониторинг старта процессов, `QuarantineManager`, `RemediationEngine`, отчёты, диспетчер событий, IPC по Named Pipes, `IKernelBridge`/`NullKernelBridge`, `SentinelRuntime`. |
| `src/Sentinel.Cli` | Консольный сканер (`Sentinel.Cli.exe`, внутреннее имя сборки `sentinel`): сканирование, `audit-*`, `scan-usb`, `behavioral-status`, карантин и откат. |
| `src/Sentinel.Service` | Worker Service под `LocalSystem` (`SentinelService`): защита в реальном времени, DACL-самозащита, поведенческий щит, USB-щит, мониторинг процессов, IPC-сервер и мост к драйверу. |
| `src/Sentinel.App` | Десктопное приложение WPF (`Sentinel.App.exe`): интерфейс, трей, раздел «Поведенческий щит и USB», решения пользователя. |
| `driver/SentinelDrv` | Нативный драйвер телеметрии и защиты дескрипторов WDK (`SentinelDrv.sys`, `.inf`) по спецификации `docs/ARCHITECTURE_V2_KERNEL_SPEC.md`. **Не входит в `Sentinel.sln`** — пишется в Linux-контейнере, но компилируется и подписывается тестовым сертификатом только на Windows (`windows-latest`) в GitHub Actions, а тестируется пользователем на физическом ноутбуке с Windows. |
| `installer/Sentinel.Installer` | MSI на WiX v5 (`WixToolset.Sdk` 5.0.2). **Не входит в `Sentinel.sln`** — собирается только на Windows в GitHub Actions. |
| `tests/Sentinel.Core.Tests` | xUnit-тесты. Windows-only тесты помечены `WindowsFact` и на Linux пропускаются. |
| `rules/` | Сигнатурные правила (`*.yar`, `miners.json`). |
| `allowed_exclusions.json` | Шаблон белого списка пользователя; копируется в `dist\` и MSI. |

Служба и приложение общаются по именованному каналу; данные (карантин, манифесты отката, белый список)
лежат в `%ProgramData%\Sentinel`.

## Стек и правила сборки (Написание на Linux → Сборка в GitHub Actions → Тест пользователем на Windows)

- .NET 8 (SDK закреплён в `global.json`), C#, WPF для `Sentinel.App`, WiX v5 для установщика, C / WDK для `driver/SentinelDrv`.
- `Directory.Build.props`: `TreatWarningsAsErrors=true`, `Nullable=enable`. Допустимый результат сборки `Sentinel.sln` — **0 ошибок и 0 предупреждений**.
- Не добавляйте `.wixproj` и `driver/SentinelDrv` в `Sentinel.sln`: кросс-сборка решения на Linux не должна требовать WiX или WDK.
- **ПРАВИЛО НАПИСАНИЯ WINDOWS/KERNEL КОДА НА LINUX (БЕЗ ОТКАЗОВ):**
  - Контейнер разработки работает на Linux, поэтому скомпилировать WDK-драйвер или вызвать живое ядро Windows локально невозможно.
  - **Полный код драйвера (`driver/SentinelDrv`) и Win32 P/Invoke, написанный в Linux-контейнере без локального запуска в ядре Windows, НЕ СЧИТАЕТСЯ ЗАГЛУШКОЙ.** Заглушкой считается только пустой метод или `// TODO`.
  - Агенту **ЗАПРЕЩЕНО отказываться** от написания `driver/SentinelDrv`, `MemoryIntegrityScanner`, `ProcessStartMonitor` или `QuarantineProcessContainment` под предлогом невозможности локальной проверки на Linux.
  - Как проверяется такой код:
    1. В C# создаётся интерфейс (например, `IMemoryReader`, `IProcessCreationEventSource`, `IKernelBridge`), логика покрывается unit-тестами на Linux (`dotnet test Sentinel.sln`), а реальный Windows-класс помечается `[SupportedOSPlatform("windows")]`.
    2. Код на C для `driver/SentinelDrv` пишется в репозитории и проверяется компиляцией в GitHub Actions на раннере `windows-latest` (`.github/workflows/release.yml`) через `gh run list` и `gh run view <run-id> --log-failed`.
    3. Реальный запуск и тест драйвера и антивируса выполняет сам пользователь на своём ноутбуке с Windows через удалённую сессию и скидывает результаты в чат.
- Тесты детекта и чистки — только на безопасных синтетических артефактах (EICAR, ключи `HKCU\Software\TestAV`).
- Работайте по одному модулю за итерацию, вносите точечные правки, не переписывайте проект целиком.
- **Правила безопасности (1.1.0 — 1.3.0):** (1) никаких пустых `// TODO`; (2) никакого `File.ReadAllBytes` для сканируемых файлов и полных дампов памяти — только потоковое чтение буфером 64 КБ; (3) при обходе каталогов пропускать `ReparsePoint` (junction/symlink); (4) `CriticalProcessGuard` и самозащита: никогда не приостанавливать, не изолировать и не завершать `csrss`, `smss`, `lsass`, `wininit`, `services`, `svchost`, `explorer`, `ntoskrnl`, `winload.efi` и каталоги `C:\Program Files\Sentinel`, `C:\ProgramData\Sentinel`.
- Подробные правила: `.claude/skills/av-core-engineer/SKILL.md`; оформление интерфейса — `.claude/skills/wpf-ui-polish/SKILL.md`.

## Команды проверки

```bash
dotnet build Sentinel.sln
dotnet test Sentinel.sln
