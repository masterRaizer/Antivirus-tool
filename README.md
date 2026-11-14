# Sentinel

Системный аудитор и сканер безопасности для Windows (C# / .NET 8).

## Структура

| Проект | Назначение |
|---|---|
| `src/Sentinel.Core` | Движок анализа: SHA-256, энтропия Шеннона, PE-парсер, сигнатурные правила (JSON и YARA-подобные), EICAR, проверка подписей (WinVerifyTrust + каталоги), белый список системных файлов; аудит процессов, автозагрузки/персистентности и целостности конфигурации безопасности |
| `src/Sentinel.Cli` | Консольный интерфейс (`sentinel`) |
| `tests/Sentinel.Core.Tests` | Unit-тесты xUnit на синтетических артефактах |
| `rules/` | Правила сигнатур (`*.json`, `*.yar`, `*.yara`, `*.rule`) |

## Сборка и тесты

```bash
dotnet build
dotnet test
```

## CLI

```bash
sentinel scan <путь> [--rules <каталог>] [--json] [--no-recurse] [--max-size <МБ>]
sentinel hash <файл>
sentinel pe <файл> [--json]
sentinel rules [--rules <каталог>]
sentinel selftest
sentinel audit-processes [--rules <каталог>] [--json] [--no-file-scan]   # только Windows
sentinel audit-startup   [--rules <каталог>] [--json] [--no-file-scan]   # только Windows
sentinel audit-config    [--json]                                        # только Windows
```

Коды возврата: `0` — чисто, `1` — обнаружены угрозы/подозрения, `2` — ошибка.

## Аудит (Этап 2)

Бизнес-логика всех аудиторов платформонезависима и инъектирует системные источники через
интерфейсы (реестр, процессы, планировщик, WMI, хранилище сертификатов), поэтому полностью
покрывается unit-тестами на Linux; реальные механизмы Windows реализованы в отдельных провайдерах
(Win32 API, `Microsoft.Win32.Registry`, CIM через PowerShell, `X509Store`).

- **`ProcessAuditor`** — список процессов (PID/PPID/путь/командная строка/CPU через Win32:
  Toolhelp, `QueryFullProcessImageName`, чтение PEB, `GetProcessTimes`); эвристики: системное имя
  вне штатного каталога, подмена символов (homoglyphs), опасные флаги интерпретаторов
  (`-enc`, скрытое окно, обход политики, загрузка+IEX, base64, `certutil`, URL/IP:порт),
  аномальная загрузка CPU/GPU; проверка файла каждого процесса через `FileAnalyzer`.
- **`PersistenceAuditor`** — `Run`/`RunOnce` (HKCU/HKLM/Wow6432Node), `Winlogon` (`Shell`/`Userinit`),
  IFEO (`Debugger`), службы, задачи планировщика (`%windir%\System32\Tasks`), подписки WMI
  (`__EventFilter`/`CommandLineEventConsumer`), папки автозагрузки (разбор `.lnk`) и файл `hosts`.
- **`ConfigIntegrityAuditor`** — исключения встроенной защиты (Windows Defender), разрешающие
  правила брандмауэра, нештатные корневые сертификаты (store `Root`) и настройки системного прокси.

Интеграционные тесты для Windows работают только в изолированной ветке `HKCU\Software\TestAV`
(на других ОС помечаются как пропущенные).

## Формат правил

YARA-подобный (подмножество): `meta` (`id`, `severity`, `category`, `description`, `sha256`),
`strings` (текст с модификаторами `nocase`/`ascii`/`wide`, hex с `??` и полубайтовыми масками),
`condition` (`and`/`or`/`not`, `any|all|N of them|(...)`, `$a at N`, `$a in (A..B)`, `#a >= N`,
`filesize`, `uint8/16/32[be](off)`). Неподдерживаемые конструкции (import, regex, jumps) дают явную ошибку загрузки.

JSON: см. `rules/miners.json`.

## Безопасность

- Анализатор только читает файлы (`FileShare.ReadWrite | Delete`), никогда их не изменяет.
- Белый список срабатывает только при одновременном выполнении: путь (после разрешения ссылок) в
  защищённом каталоге + действительная подпись + доверенный издатель (Microsoft). На ОС без WinTrust — fail-closed.
- Тесты используют только безопасные артефакты: EICAR (собирается в рантайме) и PE-заглушки без кода.
