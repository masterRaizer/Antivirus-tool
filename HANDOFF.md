# HANDOFF — Sentinel

Обновлено: 2026-11-15 (UTC). Ведёт `repo-scout`; правила — скилл `sentinel-stage-flow`.

## Ветка и коммит
- Основная ветка: `main` = этапы 1–3 (вершина этапа 3 — `5c6cd1f`, «Stage 3 (6/6)») + скиллы `.claude/skills/` + этот файл. Ветка `claude/sentinel-stage-3-quarantine-dfzize` — тот же код этапа 3.
- Старые ветки `claude/funny-cray-ckg20j` (этап 1), `claude/lucid-ride-xnd3ng` (этап 2), `claude/modest-knuth-cjvnqo` (этап 1) устарели; новые работы вести от `main`.
- Этап 4 выполнялся параллельной сессией (Fable), прервавшейся по 5-часовому лимиту; коммитов этапа 4 в ветке нет (на момент записи). До старта новой сессии убедиться, что та сессия остановлена или её ветка есть на GitHub — иначе будет двойная работа.

## Статус этапов
| Этап | Содержание | Статус |
|---|---|---|
| 1 | Sentinel.Core: анализ PE, хеши, энтропия, 5 правил, CLI, selftest 7/7 | Готов. WinVerifyTrust не проверен на Windows |
| 2 | ProcessAuditor, PersistenceAuditor, ConfigIntegrityAuditor, CLI `audit-*` | Готов. 234 теста зелёные, 3 пропущены на Linux (после этапа 2) |
| 3 | QuarantineManager, RemediationEngine (манифесты отката), JSON/HTML-отчёты, CLI remediation/quarantine/rollback, сквозной тест | Готов (6/6). Тесты после этапа 3 (Linux, SDK 8.0.134): 331 всего, 327 passed, 0 failed, 4 skipped (все 4 — Windows-only `WindowsFact`) |
| 4 | Служба защиты (Windows Service) + WPF-приложение | В работе, с нуля: кода в ветке нет. Прерван лимитом на шаге «проверка репозитория, SDK и ключей ресурсов XAML» |

## Следующие шаги (сессия на Sonnet, чистый контекст)
1. `git checkout main`; `bash scripts/setup-linux.sh`; `dotnet build`; `dotnet test`.
2. Этап 4, по одному модулю за итерацию (коммиты `Stage 4 (k/m): …`):
   - 4.1 проект службы защиты: хост Worker/Windows Service поверх Sentinel.Core, конфигурация, журнал;
   - 4.2 цикл защиты: периодический запуск аудиторов, события, использование карантина и отката из этапа 3;
   - 4.3 проект WPF: оболочка, статус службы, список находок, действия карантин/откат, просмотр отчётов;
   - 4.4 тесты: логика службы и модели представления — на Linux (xUnit); запуск службы и UI — Windows-only.
   Состав подпунктов уточнить у пользователя, если требования этапа 4 отличаются.
3. Windows-проекты компилируются на Linux с `-p:EnableWindowsTargeting=true`; запуск — только на Windows.
4. После каждого модуля обновлять этот файл; при контексте > 150k токенов — остановиться и передать дальше.

## Не проверено / нужна проверка на Windows
- `WinVerifyTrust` (проверка подписей) — реальная работа на Windows.
- Реестровые и сервисные аудиторы — интеграционные тесты `WindowsFact` пропускаются на Linux.
- Удаление исключений Defender и завершение дерева процессов — на живой системе.
- Служба защиты и WPF (этап 4) — установка, запуск, UI.

## Команды
```
bash scripts/setup-linux.sh
dotnet build Sentinel.sln
dotnet test Sentinel.sln
```
SDK закреплён в `global.json` (8.0.100, rollForward latestFeature).
