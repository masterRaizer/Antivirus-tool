# Сторонние данные в Sentinel

Стартовая база `data/threat_hashes.bin` (11 743 SHA-256, 866 семейств, метка 2026-11-15) собрана командой

```bash
bash scripts/build-threat-db.sh
```

из публичных индикаторов компрометации (IOC). Из исходных файлов извлечены только SHA-256 (MD5, SHA-1, нулевые
и «пустые» хеши отброшены); тексты правил и описания в базу не копируются. Добавлен тестовый хеш EICAR.

## Neo23x0/signature-base

- Источник: https://github.com/Neo23x0/signature-base (коммит `eb8c53cb08ed103d031fe9c98d1d23e94904839d`)
- Использованы: `iocs/hash-iocs.txt` и мета-поля `hash = "…"` правил `yara/*.yar`
- Автор: Florian Roth и участники проекта
- Лицензия: Detection Rule License (DRL) 1.1 — https://github.com/Neo23x0/signature-base/blob/master/LICENSE
  Условие DRL 1.1: при использовании правил и индикаторов сохраняется указание авторства (этот файл).

## eset/malware-ioc

- Источник: https://github.com/eset/malware-ioc (коммит `8921a81d245cce3f9b7a199b123d221ed8f1fe33`)
- Использованы: `*/samples.sha256`, README и файлы IOC в каталогах семейств; имя семейства — `ESET.<каталог>`
- Copyright (c) 2014-2018 ESET spol. s r.o. All rights reserved.
- Лицензия: BSD 2-Clause — https://github.com/eset/malware-ioc/blob/master/LICENSE

  Redistribution and use in source and binary forms, with or without modification, are permitted provided that
  the following conditions are met: (1) Redistributions of source code must retain the above copyright notice,
  this list of conditions and the following disclaimer. (2) Redistributions in binary form must reproduce the above
  copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials
  provided with the distribution. THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
  EXPRESS OR IMPLIED WARRANTIES ARE DISCLAIMED.

## Обновление на компьютере пользователя

`ThreatFeedUpdater` (кнопка «Обновить базы», фоново каждые 6 часов) дополняет базу из тех же репозиториев (через
`api.github.com/.../git/trees` и `raw.githubusercontent.com`, только изменившиеся файлы), из Feodo Tracker (abuse.ch,
IP командных серверов) и — при заданном `AbuseChAuthKey` в `sentinel_config.json` — из API MalwareBazaar, ThreatFox и
URLhaus (abuse.ch, условия использования: https://abuse.ch/). Недоступный источник пропускается, остальные сливаются.
