# CLAUDE.md — Sentinel

Sentinel — защитный инструмент аудита целостности хоста Windows: анализ PE, сигнатуры (YARA-подобные правила и
JSON-правила майнеров), аудит процессов, автозагрузки и конфигурации, карантин с откатом, отчёты и защита
в реальном времени. Состояние этапов и список непроверенного — в `HANDOFF.md`.

## Архитектура

| Каталог | Назначение |
|---|---|
| `src/Sentinel.Core` | Вся логика: анализ PE, хеши и энтропия, правила, аудиторы (процессы, персистентность, конфигурация), `QuarantineManager`, `RemediationEngine`, отчёты, диспетчер событий, IPC по Named Pipes, `SentinelRuntime`. |
| `src/Sentinel.Cli` | Консольный сканер (`Sentinel.Cli.exe`, внутреннее имя сборки `sentinel`): сканирование, `audit-*`, карантин и откат. |
| `src/Sentinel.Service` | Worker Service под `LocalSystem` (`SentinelService`): защита в реальном времени, IPC-сервер. |
| `src/Sentinel.App` | Десктопное приложение WPF (`Sentinel.App.exe`): интерфейс, трей, решения пользователя. |
| `installer/Sentinel.Installer` | MSI на WiX v5 (`WixToolset.Sdk` 5.0.2). **Не входит в `Sentinel.sln`** — собирается только на Windows в GitHub Actions. |
| `tests/Sentinel.Core.Tests` | xUnit-тесты. Windows-only тесты помечены `WindowsFact` и на Linux пропускаются. |
| `rules/` | Сигнатурные правила (`*.yar`, `miners.json`). |
| `allowed_exclusions.json` | Шаблон белого списка пользователя; копируется в `dist\` и MSI. |

Служба и приложение общаются по именованному каналу; данные (карантин, манифесты отката, белый список)
лежат в `%ProgramData%\Sentinel`.

## Стек и правила сборки

- .NET 8 (SDK закреплён в `global.json`), C#, WPF для `Sentinel.App`, WiX v5 для установщика.
- `Directory.Build.props`: `TreatWarningsAsErrors=true`, `Nullable=enable`. Допустимый результат любой сборки —
  **0 ошибок и 0 предупреждений**.
- Не добавляйте `.wixproj` в `Sentinel.sln`: кросс-сборка решения на Linux не должна требовать WiX.
- Никаких заглушек (`// TODO`, пустые обработчики), детекторы используют реальные механизмы Windows.
- Тесты детекта и чистки — только на безопасных синтетических артефактах (EICAR, ключи `HKCU\Software\TestAV`).
- Работайте по одному модулю за итерацию, вносите точечные правки, не переписывайте проект целиком.
- **Абсолютные запреты (1.1.0):** (1) никаких заглушек и имитаций в продакшене — загрузчики, парсеры, IPC-команды и кнопки UI работают по-настоящему; (2) никакого `File.ReadAllBytes` для сканируемых файлов — только потоковое чтение буфером 64 КБ (`IncrementalHash` SHA-256 + потоковая энтропия); (3) при обходе каталогов пропускать `ReparsePoint` (junction/symlink); (4) самозащита: не изолировать и не завершать `csrss`, `smss`, `lsass`, `wininit`, `services`, `explorer`, `ntoskrnl`, `winload.efi` и каталоги `C:\Program Files\Sentinel`, `C:\ProgramData\Sentinel`.
- Подробные правила: `.claude/skills/av-core-engineer/SKILL.md`; оформление интерфейса — `.claude/skills/wpf-ui-polish/SKILL.md`.

## Команды проверки

```bash
dotnet build Sentinel.sln
dotnet test Sentinel.sln
```

Перед завершением работы оба вызова должны пройти без ошибок и предупреждений; упавшие тесты нужно исправить,
а не пропускать. На Linux подготовить окружение можно командой `bash scripts/setup-linux.sh`.

Релизная сборка выполняется только в GitHub Actions (`.github/workflows/release.yml`, `windows-latest`):
`scripts/publish-windows.ps1` → MSI → portable zip → GitHub Release.

## Диагностика упавших сборок в GitHub Actions

```bash
gh run list --limit 10
gh run view <run-id> --log-failed
```

Сначала найдите упавший запуск через `gh run list`, затем читайте только упавшие шаги через
`gh run view <run-id> --log-failed`. Исправляйте причину, а не отключайте тесты и проверки.
