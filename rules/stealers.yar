// Эвристические сигнатуры инфостилеров: обращение одновременно к хранилищам
// учётных данных нескольких браузеров и к ключу DPAPI Chromium.
rule Stealer_Browser_Credential_Harvest : stealer
{
    meta:
        id = "SNT-STEALER-0001"
        severity = "high"
        category = "stealer"
        description = "Доступ к базам паролей/cookies нескольких браузеров и к ключу шифрования Chromium"
    strings:
        $login_data = "\\Login Data" nocase ascii wide
        $cookies = "\\Network\\Cookies" nocase ascii wide
        $local_state = "Local State" nocase ascii wide
        $enc_key = "\"encrypted_key\"" nocase ascii wide
        $ff_logins = "logins.json" nocase ascii wide
        $ff_key4 = "key4.db" nocase ascii wide
        $chrome = "Google\\Chrome\\User Data" nocase ascii wide
        $edge = "Microsoft\\Edge\\User Data" nocase ascii wide
        $brave = "BraveSoftware\\Brave-Browser" nocase ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 32MB
        and ($login_data or $cookies)
        and ($local_state and $enc_key)
        and 2 of ($chrome, $edge, $brave, $ff_logins, $ff_key4)
}

rule Stealer_Telegram_Exfil : stealer
{
    meta:
        id = "SNT-STEALER-0002"
        severity = "medium"
        category = "stealer"
        description = "Отправка данных через Telegram Bot API в сочетании с поиском сессий Telegram Desktop"
    strings:
        $api = "api.telegram.org/bot" nocase ascii wide
        $send = "sendDocument" ascii wide
        $tdata = "Telegram Desktop\\tdata" nocase ascii wide
    condition:
        uint16(0) == 0x5A4D and $api and $send and $tdata
}
