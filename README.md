# Sentinel

Системный аудитор и сканер безопасности для Windows (C# / .NET 8).

## Структура

| Проект | Назначение |
|---|---|
| `src/Sentinel.Core` | Движок анализа: SHA-256, энтропия Шеннона, PE-парсер, сигнатурные правила (JSON и YARA-подобные), EICAR, проверка подписей (WinVerifyTrust + каталоги), белый список системных файлов |
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
```

Коды возврата: `0` — чисто, `1` — обнаружены угрозы/подозрения, `2` — ошибка.

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
