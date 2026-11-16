<#
.SYNOPSIS
    Сборка и тестовая подпись драйвера SentinelDrv.sys (Windows, GitHub Actions windows-latest или машина разработчика).

.DESCRIPTION
    1. Находит MSBuild с C++-тулсетом через vswhere.
    2. Берёт WDK: установленный Windows Kits\10 (если в нём есть km\ntddk.h нужной версии и не задан -UseNuGetWdk) или
       NuGet-пакеты Microsoft.Windows.WDK.x64 и Microsoft.Windows.SDK.CPP одной версии (извлекаются только
       Include\<ver>\km, Include\<ver>\shared и Lib\<ver>\km\x64; кэш — driver\.wdk).
    3. Собирает driver\SentinelDrv\SentinelDrv.vcxproj (Release|x64, предупреждения компилятора и компоновщика — ошибки).
    4. Проверяет PE: подсистема Native и флаг IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY (/INTEGRITYCHECK).
    5. Создаёт самоподписанный сертификат подписи кода "CN=Sentinel Test Driver", экспортирует SentinelDrvTest.cer
       (только открытая часть; закрытый ключ удаляется из хранилища) и подписывает драйвер signtool (SHA-256).
    6. Кладёт в OutDir: SentinelDrv.sys, SentinelDrv.pdb, SentinelDrv.inf (DriverVer = версия), SentinelDrvTest.cer,
       install-driver-testmode.ps1 и архив SentinelDrv-v<версия>-x64-testsigned.zip.
#>
[CmdletBinding()]
param(
    [string] $Version = '1.3.0',
    [string] $Configuration = 'Release',
    [string] $OutDir = 'dist/driver',
    [string] $WdkPackageVersion = '10.0.26100.6584',
    [string] $WdkIncludeVersion = '10.0.26100.0',
    [switch] $UseNuGetWdk,
    [switch] $SkipSigning
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repo = Split-Path -Parent $PSScriptRoot
$project = Join-Path $repo 'driver\SentinelDrv\SentinelDrv.vcxproj'
$OutDir = if ([IO.Path]::IsPathRooted($OutDir)) { $OutDir } else { Join-Path $repo $OutDir }
if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw "Версия '$Version' должна иметь вид X.Y.Z." }

function Find-MSBuild {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path $vswhere)) { throw 'vswhere.exe не найден: нужна Visual Studio с компонентом C++ (VC.Tools.x86.x64).' }
    $msbuild = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        -find 'MSBuild\**\Bin\MSBuild.exe' | Select-Object -First 1
    if (-not $msbuild) { throw 'MSBuild с C++-тулсетом (VC.Tools.x86.x64) не найден.' }
    return $msbuild
}

function Expand-NuGetSubset([string] $Id, [string] $PackageVersion, [string] $Destination, [string[]] $Prefixes) {
    $marker = Join-Path $Destination '.complete'
    if (Test-Path $marker) { return }
    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    $lower = $Id.ToLowerInvariant()
    $url = "https://api.nuget.org/v3-flatcontainer/$lower/$PackageVersion/$lower.$PackageVersion.nupkg"
    $package = Join-Path ([IO.Path]::GetTempPath()) "$lower.$PackageVersion.nupkg"
    Write-Host "Загрузка $Id $PackageVersion..."
    Invoke-WebRequest -Uri $url -OutFile $package -UseBasicParsing
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead($package)
    try {
        $count = 0
        foreach ($entry in $zip.Entries) {
            $name = [Uri]::UnescapeDataString($entry.FullName)
            if (-not ($Prefixes | Where-Object { $name.StartsWith($_, [StringComparison]::OrdinalIgnoreCase) })) { continue }
            if ($name.EndsWith('/')) { continue }
            $path = Join-Path $Destination ($name -replace '/', '\')
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $path) | Out-Null
            [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $path, $true)
            $count++
        }
        if ($count -eq 0) { throw "В пакете $Id не найдено файлов с префиксами: $($Prefixes -join ', ')." }
        Write-Host "  извлечено файлов: $count"
    }
    finally {
        $zip.Dispose()
        Remove-Item $package -Force -ErrorAction SilentlyContinue
    }
    Set-Content -Path $marker -Value $PackageVersion
}

function Resolve-Wdk {
    $kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10'
    $installed = (Test-Path (Join-Path $kits "Include\$WdkIncludeVersion\km\ntddk.h")) -and
        (Test-Path (Join-Path $kits "Lib\$WdkIncludeVersion\km\x64\ntoskrnl.lib")) -and
        (Test-Path (Join-Path $kits "Include\$WdkIncludeVersion\shared\ntdef.h"))
    if ($installed -and -not $UseNuGetWdk) {
        Write-Host "WDK: установленный $kits ($WdkIncludeVersion)"
        return @{ Wdk = $kits; Shared = $kits; Source = "installed $WdkIncludeVersion" }
    }

    $cache = Join-Path $repo "driver\.wdk\$WdkPackageVersion"
    $wdk = Join-Path $cache 'wdk'
    $sdk = Join-Path $cache 'sdk'
    Expand-NuGetSubset 'Microsoft.Windows.WDK.x64' $WdkPackageVersion $wdk `
        @("c/Include/$WdkIncludeVersion/km/", "c/Include/$WdkIncludeVersion/shared/", "c/Lib/$WdkIncludeVersion/km/x64/")
    Expand-NuGetSubset 'Microsoft.Windows.SDK.CPP' $WdkPackageVersion $sdk @("c/Include/$WdkIncludeVersion/shared/")
    Write-Host "WDK: NuGet $WdkPackageVersion"
    return @{ Wdk = Join-Path $wdk 'c'; Shared = Join-Path $sdk 'c'; Source = "NuGet $WdkPackageVersion" }
}

function Assert-DriverImage([string] $Path) {
    # Заголовки PE целиком помещаются в первые 4 КБ — читается только это окно.
    $bytes = New-Object byte[] 4096
    $stream = [IO.File]::OpenRead($Path)
    try { [void]$stream.Read($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
    if ($bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) { throw "$Path — не PE-файл." }
    $pe = [BitConverter]::ToInt32($bytes, 0x3C)
    if ($pe -lt 0x40 -or $pe -gt 0xE00) { throw "$Path — некорректный e_lfanew." }
    if ([BitConverter]::ToUInt32($bytes, $pe) -ne 0x00004550) { throw "$Path — нет сигнатуры PE." }
    $optional = $pe + 24
    $magic = [BitConverter]::ToUInt16($bytes, $optional)
    $subsystem = [BitConverter]::ToUInt16($bytes, $optional + 68)
    $characteristics = [BitConverter]::ToUInt16($bytes, $optional + 70)
    if ($magic -ne 0x20B) { throw "$Path — не PE32+ (x64)." }
    if ($subsystem -ne 1) { throw "$Path — подсистема $subsystem, ожидается Native (1)." }
    if (($characteristics -band 0x0080) -eq 0) {
        throw "$Path — нет флага FORCE_INTEGRITY (/INTEGRITYCHECK): ObRegisterCallbacks вернёт STATUS_ACCESS_DENIED."
    }
    Write-Host ("PE: x64, Native, DllCharacteristics=0x{0:X4} (FORCE_INTEGRITY установлен)" -f $characteristics)
}

function Find-SignTool {
    $candidates = Get-ChildItem (Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin') -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
        Where-Object { $_.DirectoryName -match '\\x64$' } | Sort-Object FullName -Descending
    if (-not $candidates) { throw 'signtool.exe не найден (нужен Windows SDK).' }
    return $candidates[0].FullName
}

$msbuild = Find-MSBuild
$wdk = Resolve-Wdk
Write-Host "MSBuild: $msbuild"

& $msbuild $project /nologo /m /v:minimal /p:Configuration=$Configuration /p:Platform=x64 `
    "/p:WdkRoot=$($wdk.Wdk)" "/p:SdkSharedRoot=$($wdk.Shared)" "/p:WdkVersion=$WdkIncludeVersion"
if ($LASTEXITCODE -ne 0) { throw "Сборка драйвера завершилась с кодом $LASTEXITCODE." }

$bin = Join-Path $repo "driver\SentinelDrv\bin\x64\$Configuration"
$sys = Join-Path $bin 'SentinelDrv.sys'
if (-not (Test-Path $sys)) { throw "Не найден $sys." }
Assert-DriverImage $sys

if (Test-Path $OutDir) { Remove-Item $OutDir -Recurse -Force }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
Copy-Item $sys, (Join-Path $bin 'SentinelDrv.pdb') $OutDir
$sys = Join-Path $OutDir 'SentinelDrv.sys'

$inf = Get-Content (Join-Path $repo 'driver\SentinelDrv\SentinelDrv.inf') -Raw
$driverVer = '{0},{1}.0' -f (Get-Date).ToUniversalTime().ToString('MM/dd/yyyy', [Globalization.CultureInfo]::InvariantCulture), $Version
$inf = $inf -replace '(?m)^DriverVer\s*=.*$', "DriverVer   = $driverVer"
Set-Content -Path (Join-Path $OutDir 'SentinelDrv.inf') -Value $inf -Encoding Unicode   # INF — UTF-16 LE
Copy-Item (Join-Path $repo 'scripts\install-driver-testmode.ps1') $OutDir

if (-not $SkipSigning) {
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=Sentinel Test Driver' `
        -CertStoreLocation 'Cert:\CurrentUser\My' -KeyUsage DigitalSignature -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(2)
    try {
        Export-Certificate -Cert $cert -FilePath (Join-Path $OutDir 'SentinelDrvTest.cer') -Type CERT | Out-Null
        $signtool = Find-SignTool
        Write-Host "signtool: $signtool"
        & $signtool sign /fd SHA256 /sha1 $cert.Thumbprint /s My /d 'Sentinel Kernel Telemetry Driver (test)' $sys
        if ($LASTEXITCODE -ne 0) { throw "signtool sign завершился с кодом $LASTEXITCODE." }
        $signature = Get-AuthenticodeSignature $sys
        if ($null -eq $signature.SignerCertificate -or $signature.SignerCertificate.Thumbprint -ne $cert.Thumbprint) {
            throw "Подпись SentinelDrv.sys не найдена после signtool (статус $($signature.Status))."
        }
        Write-Host "Подписано тестовым сертификатом $($cert.Thumbprint) (статус на сборочной машине: $($signature.Status) — корень не доверен, это ожидаемо)."
    }
    finally {
        Remove-Item "Cert:\CurrentUser\My\$($cert.Thumbprint)" -Force -ErrorAction SilentlyContinue
    }
}

$archive = Join-Path (Split-Path -Parent $OutDir) "SentinelDrv-v$Version-x64-testsigned.zip"
if (Test-Path $archive) { Remove-Item $archive -Force }
Compress-Archive -Path (Join-Path $OutDir '*') -DestinationPath $archive
Write-Host "Драйвер собран ($($wdk.Source)): $OutDir"
Get-ChildItem $OutDir | ForEach-Object { Write-Host ("  {0,-34} {1,10:N0} байт" -f $_.Name, $_.Length) }
Write-Host "Архив: $archive"
