<#
.SYNOPSIS
    Установка, удаление и проверка тестовой сборки SentinelDrv.sys (режим Test Signing).

.DESCRIPTION
    Запускать от имени администратора из каталога с артефактами сборки (SentinelDrv.sys, SentinelDrvTest.cer).
      -Action Install    импортирует SentinelDrvTest.cer в Root и TrustedPublisher (LocalMachine), копирует драйвер
                         в %SystemRoot%\System32\drivers, создаёт службу ядра SentinelDrv (sc.exe create type= kernel)
                         и запускает её;
      -Action Uninstall  останавливает и удаляет службу, удаляет файл драйвера и тестовый сертификат;
      -Action Status     состояние службы и режима тестовой подписи.
    Конфигурацию загрузки скрипт не меняет: тестовый режим включается вручную (bcdedit /set testsigning on + перезагрузка),
    при включённом Secure Boot его сначала нужно отключить в UEFI.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\install-driver-testmode.ps1 -Action Install
#>
[CmdletBinding()]
param(
    [ValidateSet('Install', 'Uninstall', 'Status')]
    [string] $Action = 'Install',
    [string] $SourceDirectory = $PSScriptRoot
)

$ErrorActionPreference = 'Stop'
$serviceName = 'SentinelDrv'
$target = Join-Path $env:SystemRoot 'System32\drivers\SentinelDrv.sys'

function Assert-Administrator {
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Запустите скрипт от имени администратора.'
    }
}

function Test-TestSigning {
    $bcd = & bcdedit.exe /enum '{current}' 2>$null | Out-String
    return $bcd -match '(?im)^\s*testsigning\s+Yes'
}

function Invoke-Sc([string[]] $Arguments, [switch] $AllowFailure) {
    $output = & sc.exe @Arguments 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0 -and -not $AllowFailure) {
        throw "sc.exe $($Arguments -join ' ') завершился с кодом ${LASTEXITCODE}:`n$output"
    }
    Write-Host $output.Trim()
}

Assert-Administrator

switch ($Action) {
    'Status' {
        Write-Host ("Test Signing: {0}" -f $(if (Test-TestSigning) { 'включён' } else { 'выключен' }))
        Invoke-Sc @('query', $serviceName) -AllowFailure
    }

    'Install' {
        if (-not (Test-TestSigning)) {
            throw "Режим тестовой подписи выключен. Выполните 'bcdedit /set testsigning on' от администратора и перезагрузитесь."
        }

        $sys = Join-Path $SourceDirectory 'SentinelDrv.sys'
        $cer = Join-Path $SourceDirectory 'SentinelDrvTest.cer'
        foreach ($file in @($sys, $cer)) {
            if (-not (Test-Path $file)) { throw "Не найден файл $file." }
        }

        Write-Host 'Импорт тестового сертификата в LocalMachine\Root и LocalMachine\TrustedPublisher...'
        & certutil.exe -f -addstore Root $cer | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'certutil -addstore Root завершился с ошибкой.' }
        & certutil.exe -f -addstore TrustedPublisher $cer | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'certutil -addstore TrustedPublisher завершился с ошибкой.' }

        Invoke-Sc @('stop', $serviceName) -AllowFailure
        Copy-Item $sys $target -Force
        Invoke-Sc @('create', $serviceName, 'type=', 'kernel', 'start=', 'demand', 'error=', 'normal',
            'binPath=', 'System32\drivers\SentinelDrv.sys', 'DisplayName=', 'Sentinel Kernel Telemetry Driver') -AllowFailure
        Invoke-Sc @('start', $serviceName)
        Write-Host 'Готово. Проверка: sentinel.exe kernel-status'
    }

    'Uninstall' {
        Invoke-Sc @('stop', $serviceName) -AllowFailure
        Invoke-Sc @('delete', $serviceName) -AllowFailure
        if (Test-Path $target) { Remove-Item $target -Force }
        $cer = Join-Path $SourceDirectory 'SentinelDrvTest.cer'
        if (Test-Path $cer) {
            $thumbprint = (New-Object Security.Cryptography.X509Certificates.X509Certificate2 $cer).Thumbprint
            & certutil.exe -delstore Root $thumbprint | Out-Null
            & certutil.exe -delstore TrustedPublisher $thumbprint | Out-Null
        }
        Write-Host 'Драйвер и тестовый сертификат удалены. Тестовый режим отключается вручную: bcdedit /set testsigning off'
    }
}
