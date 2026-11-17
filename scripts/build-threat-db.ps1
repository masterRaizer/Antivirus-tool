<#
.SYNOPSIS
    Сборка базы вирусных хешей Sentinel из открытых источников (запускается в GitHub Actions перед publish-windows.ps1).

.DESCRIPTION
    Скачивает и объединяет:
      - abuse.ch MalwareBazaar — полная выгрузка (CSV в zip, ~1 млн образцов с названием семейства; при отказе — список SHA-256);
      - VirusShare — последние N списков MD5 (по 65 536 хешей в каждом);
      - eset/malware-ioc и Neo23x0/signature-base — IOC вендоров (SHA-256, SHA-1, MD5).
    Результат — data\threat_hashes.bin (SHA-256), data\threat_hashes_sha1.bin, data\threat_hashes_md5.bin; дальше их забирает
    publish-windows.ps1 в dist\data и установщик. Недоступный источник пропускается с предупреждением; если не удалось собрать
    ничего, остаётся база из репозитория — релиз не падает из-за чужого сервера.

    Ключ abuse.ch (бесплатный, auth.abuse.ch) передаётся через переменную окружения ABUSECH_AUTH_KEY (секрет репозитория).
#>
param(
    [string]$OutDir = 'data',
    [int]$VirusShareLists = 50
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$work = Join-Path ([System.IO.Path]::GetTempPath()) ('sentinel-threatdb-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force $work | Out-Null
$buildArgs = [System.Collections.Generic.List[string]]::new()
$headers = @{ 'User-Agent' = 'Sentinel-ThreatDB-Builder' }
if ($env:ABUSECH_AUTH_KEY) { $headers['Auth-Key'] = $env:ABUSECH_AUTH_KEY }

function Get-File([string]$Url, [string]$Path, [int]$Timeout = 900) {
    Invoke-WebRequest -Uri $Url -OutFile $Path -Headers $headers -TimeoutSec $Timeout -UseBasicParsing
    if (-not (Test-Path $Path) -or (Get-Item $Path).Length -lt 64) { throw "пустой ответ от $Url" }
}

function Test-Zip([string]$Path) {
    $stream = [System.IO.File]::OpenRead($Path)
    try { return $stream.ReadByte() -eq 0x50 -and $stream.ReadByte() -eq 0x4B } finally { $stream.Dispose() }
}

# 1. Репозитории IOC вендоров (GitHub).
foreach ($repo in @(@{ Name = 'eset/malware-ioc'; Dir = 'eset'; Arg = '--eset' }, @{ Name = 'Neo23x0/signature-base'; Dir = 'sigbase'; Arg = '--signature-base' })) {
    try {
        git clone --depth 1 --quiet "https://github.com/$($repo.Name)" (Join-Path $work $repo.Dir)
        if ($LASTEXITCODE -ne 0) { throw "git clone завершился с кодом $LASTEXITCODE" }
        $buildArgs.Add($repo.Arg); $buildArgs.Add((Join-Path $work $repo.Dir))
        Write-Host "OK  $($repo.Name)"
    } catch { Write-Warning "Пропущен $($repo.Name): $_" }
}

# 2. MalwareBazaar: полная выгрузка CSV (с семействами), при отказе — полный список SHA-256.
$mb = $null
# Старые адреса bazaar.abuse.ch/export/… отвечают 410 Gone; выгрузки теперь только с Auth-Key в пути
# (https://mb-api.abuse.ch/v2/files/exports/<ключ>/…) — секрет репозитория ABUSECH_AUTH_KEY.
$mbCandidates = @()
if ($env:ABUSECH_AUTH_KEY) {
    $mbBase = "https://mb-api.abuse.ch/v2/files/exports/$($env:ABUSECH_AUTH_KEY)"
    $mbCandidates += @{ Url = "$mbBase/full.csv.zip"; File = 'malwarebazaar_full.zip'; Label = 'exports/full.csv.zip' }
    $mbCandidates += @{ Url = "$mbBase/full.zip"; File = 'malwarebazaar_full2.zip'; Label = 'exports/full.zip' }
    $mbCandidates += @{ Url = "$mbBase/sha256_full.zip"; File = 'malwarebazaar_sha256_full.zip'; Label = 'exports/sha256_full.zip' }
} else {
    Write-Warning 'MalwareBazaar: секрет ABUSECH_AUTH_KEY не задан — полная выгрузка пропущена.'
}
foreach ($candidate in $mbCandidates) {
    try {
        $path = Join-Path $work $candidate.File
        Get-File $candidate.Url $path
        if (-not (Test-Zip $path)) { throw 'ответ не zip (вероятно, нужен ключ ABUSECH_AUTH_KEY)' }
        $mb = $path
        # В журнал — только метка: в адресе есть ключ (GitHub его маскирует, но лучше не печатать вовсе).
        Write-Host ("OK  MalwareBazaar {0} ({1:N0} МБ)" -f $candidate.Label, ((Get-Item $path).Length / 1MB))
        break
    } catch { Write-Warning ("MalwareBazaar {0}: {1}" -f $candidate.Label, ($_.Exception.Message -replace [regex]::Escape([string]$env:ABUSECH_AUTH_KEY), '***')) }
}
if ($mb) { $buildArgs.Add('--malwarebazaar'); $buildArgs.Add($mb) }

# 3. VirusShare: номер последнего списка — со страницы списков, затем последние N файлов.
try {
    $page = (Invoke-WebRequest -Uri 'https://virusshare.com/hashes' -Headers $headers -TimeoutSec 120 -UseBasicParsing).Content
    $numbers = [regex]::Matches($page, 'VirusShare_(\d{5})\.md5') | ForEach-Object { [int]$_.Groups[1].Value } | Sort-Object -Unique
    if (-not $numbers) { throw 'на странице не найдено ни одного списка' }
    $last = [int](($numbers | Measure-Object -Maximum).Maximum) # Measure-Object отдаёт double, а формат {0:D5} — только для целых
    $vsDir = Join-Path $work 'virusshare'
    New-Item -ItemType Directory -Force $vsDir | Out-Null
    $ok = 0
    for ($n = $last; $n -gt [Math]::Max(-1, $last - $VirusShareLists); $n--) {
        $name = 'VirusShare_{0:D5}.md5' -f $n
        try { Get-File "https://virusshare.com/hashfiles/$name" (Join-Path $vsDir $name) 300; $ok++ }
        catch { Write-Warning "VirusShare $($name): $_" }
    }
    if ($ok -gt 0) { $buildArgs.Add('--virusshare'); $buildArgs.Add($vsDir) }
    Write-Host "OK  VirusShare: списков $ok (последний №$last)"
} catch { Write-Warning "Пропущен VirusShare: $_" }

if ($buildArgs.Count -eq 0) {
    Write-Warning 'Ни один источник не доступен: остаётся база из репозитория.'
    exit 0
}

# 4. Сборка трёх файлов базы во временный каталог; в data\ они попадают только при успехе.
$built = Join-Path $work 'out'
New-Item -ItemType Directory -Force $built | Out-Null
$all = @('run', '--project', 'src/Sentinel.Cli/Sentinel.Cli.csproj', '-c', 'Release', '--', 'threatdb', 'build', '--out', (Join-Path $built 'threat_hashes.bin')) + $buildArgs
& dotnet @all
if ($LASTEXITCODE -ne 0) {
    Write-Warning "Сборка базы завершилась с кодом ${LASTEXITCODE}: остаётся база из репозитория."
    exit 0
}

New-Item -ItemType Directory -Force $OutDir | Out-Null
Get-ChildItem $built -Filter 'threat_hashes*.bin' | ForEach-Object {
    Copy-Item $_.FullName (Join-Path $OutDir $_.Name) -Force
    Write-Host ("{0,-28} {1,10:N1} МБ" -f $_.Name, ($_.Length / 1MB))
}
Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
