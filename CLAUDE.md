# CLAUDE.md — Sentinel

Sentinel — защитный инструмент аудита целостности и активной защиты хоста Windows: анализ PE, сигнатуры (YARA-подобные правила и
JSON-правила майнеров), потоковый аудит процессов и виртуальной памяти, поведенческая корреляция, защита дескрипторов и самозащита (DACL / Kernel Callbacks), аудит автозагрузки и конфигурации, карантин с изоляцией потоков и откатом, отчёты и защита
в реальном времени. Состояние этапов и список непроверенного — в `HANDOFF.md`, спецификация связки Ring 0 / Ring 3 — в `docs/ARCHITECTURE_V2_KERNEL_SPEC.md`.

## Архитектура

| Каталог | Назначение |
|---|---|
| `src/Sentinel.Core` | Вся логика: анализ PE, хеши и энтропия, правила, аудиторы (процессы, виртуальная память, персистентность, конфигурация), поведенческий движок (`RansomwareBehaviorShield`, `CanaryFileGuard`, `BehavioralCorrelationEngine`), предохранители (`FalsePositiveGuard`, `CriticalProcessGuard`, DACL `SelfProtection`), USB-щит (`RemovableMediaShield`), мониторинг старта процессов, `QuarantineManager`, `RemediationEngine`, отчёты, диспетчер событий, IPC по Named Pipes, `IKernelBridge`/`NullKernelBridge`, `SentinelRuntime`. |
| `src/Sentinel.Cli` | Консольный сканер (`Sentinel.Cli.exe`, внутреннее имя сборки `sentinel`): сканирование, `audit-*`, `scan-usb`, `behavioral-status`, карантин и откат. |
| `src/Sentinel.Service` | Worker Service под `LocalSystem` (`SentinelService`): защита в реальном времени, DACL-самозащита, поведенческий щит, USB-щит, мониторинг процессов, IPC-сервер и мост к драйверу. |
| `src/Sentinel.App` | Десктопное приложение WPF (`Sentinel.App.exe`): интерфейс, трей, раздел «Поведенческий щит и USB», решения пользователя. |
| `driver/SentinelDrv` | Нативный компонент телеметрии и защиты дескрипторов WDK (`SentinelDrv.sys`, `.inf`) по спецификации `docs/ARCHITECTURE_V2_KERNEL_SPEC.md`. **Не входит в `Sentinel.sln`** — собирается и подписывается тестовым сертификатом только на Windows (`windows-latest`) в GitHub Actions. |
| `installer/Sentinel.Installer` | MSI на WiX v5 (`WixToolset.Sdk` 5.0.2). **Не входит в `Sentinel.sln`** — собирается только на Windows в GitHub Actions. |
| `tests/Sentinel.Core.Tests` | xUnit-тесты. Windows-only тесты помечены `WindowsFact` и на Linux пропускаются. |
| `rules/` | Сигнатурные правила (`*.yar`, `miners.json`). |
| `allowed_exclusions.json` | Шаблон белого списка пользователя; копируется в `dist\` и MSI. |

Служба и приложение общаются по именованному каналу; данные (карантин, манифесты отката, белый список)
лежат в `%ProgramData%\Sentinel`.

## Стек и правила двухконтурной сборки (Dual-Target CI)

- .NET 8 (SDK закреплён в `global.json`), C#, WPF для `Sentinel.App`, WiX v5 для установщика, C / WDK для `driver/SentinelDrv`.
- `Directory.Build.props`: `TreatWarningsAsErrors=true`, `Nullable=enable`. Допустимый результат любой сборки —
  **0 ошибок и 0 предупреждений**.
- Не добавляйте `.wixproj` и нативные проекты WDK (`driver/SentinelDrv`) в `Sentinel.sln`: кросс-сборка решения на Linux не должна требовать WiX или MSVC/WDK.
- **Протокол двухконтурной верификации (Linux Container + Windows CI / Hardware-in-the-Loop):**
  1. **Контур 1 (Linux):** Управляемый код (`Sentinel.sln`) собирается и тестируется локально в контейнере через `dotnet build Sentinel.sln` и `dotnet test Sentinel.sln`. Платформозависимые вызовы Win32 API закрываются интерфейсными абстракциями для unit-тестов и атрибутом `[SupportedOSPlatform("windows")]`.
  2. **Контур 2 (Windows CI + стенд пользователя):** Нативные компоненты Windows (`installer/Sentinel.Installer`, `driver/SentinelDrv`) не входят в `Sentinel.sln` и проверяются сборкой на раннере `windows-latest` в `.github/workflows/release.yml` через `gh run list` и `gh run view <run-id> --log-failed`. Динамическое тестирование собранного MSI, службы и драйвера выполняет пользователь на своей Windows-машине и передаёт логи обратно в чат.
- Никаких заглушек (`// TODO`, пустые обработчики), детекторы используют реальные механизмы Windows.
- Тесты детекта и чистки — только на безопасных синтетических артефактах (EICAR, ключи `HKCU\Software\TestAV`).
- Работайте по одному модулю за итерацию, вносите точечные правки, не переписывайте проект целиком.
- **Абсолютные правила архитектуры и безопасности (1.1.0 — 1.3.0):** (1) никаких заглушек и имитаций в продакшене — загрузчики, парсеры, IPC-команды и кнопки UI работают по-настоящему; (2) никакого `File.ReadAllBytes` для сканируемых файлов и полных дампов процессов в ОЗУ — только потоковое чтение буфером 64 КБ (`IncrementalHash` SHA-256 + потоковая энтропия + потоковое чтение регионов памяти); (3) при обходе каталогов пропускать `ReparsePoint` (junction/symlink); (4) самозащита и `CriticalProcessGuard` / `FalsePositiveGuard`: категорически запрещено приостанавливать, изолировать, модифицировать или завершать `csrss`, `smss`, `lsass`, `wininit`, `services`, `svchost`, `explorer`, `ntoskrnl`, `winload.efi` и собственные процессы/каталоги `C:\Program Files\Sentinel`, `C:\ProgramData\Sentinel`.
- Подробные правила: `.claude/skills/av-core-engineer/SKILL.md`; оформление интерфейса — `.claude/skills/wpf-ui-polish/SKILL.md`.

## Команды проверки

```bash
dotnet build Sentinel.sln
dotnet test Sentinel.sln
