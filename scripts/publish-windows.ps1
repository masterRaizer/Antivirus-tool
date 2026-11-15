<#
.SYNOPSIS
    Публикует релизные сборки Sentinel для Windows x64 в каталог dist\.

.DESCRIPTION
    Собирает автономные (self-contained) однофайловые исполняемые файлы, которым не нужен
    установленный .NET:
        dist\Sentinel.App.exe      — десктопное приложение (WPF)
        dist\Sentinel.Service.exe  — фоновая служба защиты в реальном времени
        dist\Sentinel.Cli.exe      — консольный сканер
        dist\rules\                — сигнатурные правила (общие для всех трёх программ)
        dist\allowed_exclusions.json — шаблон белого списка пользователя (безопасные исключения по умолчанию)

    Перед публикацией выполняются сборка без предупреждений и модульные тесты.
    Скрипт работает в Windows PowerShell 5.1 и PowerShell 7+ (в том числе в Linux — кросс-сборка).

.PARAMETER Configuration
    Конфигурация сборки (по умолчанию Release).

.PARAMETER Output
    Каталог результата (по умолчанию dist в корне репозитория). Очищается перед публикацией.

.PARAMETER SkipTests
    Не запускать тесты перед публикацией.

.EXAMPLE
    .\scripts\publish-windows.ps1

.EXAMPLE
    .\scripts\publish-windows.ps1 -Output C:\Build\Sentinel -SkipTests
#>
[CmdletBinding()]
param(
    [string]$Configuration = 'Release',
    [string]$Output,
    [switch]$SkipTests
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Runtime = 'win-x64'
$Root = Split-Path -Parent $PSScriptRoot
if (-not $Output) { $Output = Join-Path $Root 'dist' }
$Output = [System.IO.Path]::GetFullPath($Output)

function Invoke-DotNet {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
    Write-Host "> dotnet $($Arguments -join ' ')" -ForegroundColor DarkGray
    & dotnet @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet $($Arguments[0]) завершился с кодом $LASTEXITCODE."
    }
}

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    throw 'Не найден dotnet. Установите .NET SDK 8: https://dotnet.microsoft.com/download/dotnet/8.0'
}

Push-Location $Root
try {
    if (-not $SkipTests) {
        Write-Host '== Сборка и тесты ==' -ForegroundColor Cyan
        Invoke-DotNet build Sentinel.sln -c $Configuration -nologo
        Invoke-DotNet test Sentinel.sln -c $Configuration --no-build -nologo
    }

    if (Test-Path $Output) { Remove-Item $Output -Recurse -Force }
    New-Item -ItemType Directory -Path $Output | Out-Null

    # Каждый проект публикуется в свой промежуточный каталог, затем в dist попадают только .exe и rules.
    $Stage = Join-Path ([System.IO.Path]::GetTempPath()) ("sentinel-publish-" + [Guid]::NewGuid().ToString('N'))
    $Projects = @(
        @{ Project = 'src/Sentinel.App/Sentinel.App.csproj';         Built = 'Sentinel.App.exe';     Final = 'Sentinel.App.exe' },
        @{ Project = 'src/Sentinel.Service/Sentinel.Service.csproj'; Built = 'Sentinel.Service.exe'; Final = 'Sentinel.Service.exe' },
        @{ Project = 'src/Sentinel.Cli/Sentinel.Cli.csproj';         Built = 'sentinel.exe';         Final = 'Sentinel.Cli.exe' }
    )

    try {
        foreach ($p in $Projects) {
            Write-Host "== Публикация $($p.Final) ==" -ForegroundColor Cyan
            $target = Join-Path $Stage ([System.IO.Path]::GetFileNameWithoutExtension($p.Final))
            Invoke-DotNet publish $p.Project -c $Configuration -r $Runtime --self-contained true -nologo `
                -p:PublishSingleFile=true `
                -p:IncludeNativeLibrariesForSelfExtract=true `
                -p:EnableCompressionInSingleFile=true `
                -p:DebugType=none `
                -o $target

            $exe = Join-Path $target $p.Built
            if (-not (Test-Path $exe)) { throw "После публикации не найден файл $exe." }
            Copy-Item $exe (Join-Path $Output $p.Final)

            $rules = Join-Path $target 'rules'
            if (Test-Path $rules) {
                Copy-Item $rules (Join-Path $Output 'rules') -Recurse -Force
            }
        }
    }
    finally {
        if (Test-Path $Stage) { Remove-Item $Stage -Recurse -Force }
    }

    if (-not (Test-Path (Join-Path $Output 'rules'))) { throw 'В dist не попал каталог rules.' }

    $Exclusions = Join-Path $Root 'allowed_exclusions.json'
    if (-not (Test-Path $Exclusions)) { throw "Не найден шаблон $Exclusions." }
    Copy-Item $Exclusions (Join-Path $Output 'allowed_exclusions.json')

    Write-Host ''
    Write-Host "Готово: $Output" -ForegroundColor Green
    Get-ChildItem $Output -File | Sort-Object Name | ForEach-Object {
        '{0,-24} {1,8:N1} МБ' -f $_.Name, ($_.Length / 1MB)
    }
    '{0,-24} {1,8} файлов' -f 'rules\', @(Get-ChildItem (Join-Path $Output 'rules') -Recurse -File).Count
    Write-Host ''
    Write-Host 'Установка службы (от имени администратора):'
    Write-Host "  sc.exe create SentinelService binPath= `"$Output\Sentinel.Service.exe`" start= auto obj= LocalSystem"
    Write-Host '  sc.exe start SentinelService'
}
finally {
    Pop-Location
}
