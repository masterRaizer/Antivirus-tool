<#
.SYNOPSIS
    Сборка базы вирусных хешей Sentinel из открытых источников (запускается в GitHub Actions перед publish-windows.ps1).

.DESCRIPTION
    Скачивает и объединяет:
      - eset/malware-ioc и Neo23x0/signature-base — IOC вендоров (SHA-256, SHA-1, MD5);
      - отчёты IOC Cisco-Talos/IOCs, pan-unit42/iocs (в т.ч. ~630 тыс. образцов майнеров), sophoslabs/IoCs — без строк с пометками
        легитимного файла (уязвимые драйверы, подмена DLL);
      - VirusShare — последние N списков MD5 (по 65 536 хешей в каждом);
      - abuse.ch MalwareBazaar — только с ключом: с ноября 2026 выгрузки без ключа отвечают 410 Gone, новые адреса
        mb-api.abuse.ch/v2/files/exports/<ключ>/<файл>.
    Результат — data\threat_hashes.bin (SHA-256), data\threat_hashes_sha1.bin, data\threat_hashes_md5.bin; дальше их забирает
    publish-windows.ps1 в dist\data и установщик. Недоступный источник пропускается с предупреждением; если не удалось собрать
    ничего, остаётся база из репозитория — релиз не падает из-за чужого сервера.

    Ключ abuse.ch (бесплатный, auth.abuse.ch) передаётся через переменную окружения ABUSECH_AUTH_KEY (секрет репозитория);
    в журнал он не выводится.
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
$abuseKey = "$env:ABUSECH_AUTH_KEY".Trim()

function Get-File([string]$Url, [string]$Path, [int]$Timeout = 900) {
    try {
        Invoke-WebRequest -Uri $Url -OutFile $Path -Headers $headers -TimeoutSec $Timeout -UseBasicParsing
    } catch {
        # Ключ abuse.ch стоит в пути адреса: в сообщение об ошибке он попасть не должен.
        $message = "$($_.Exception.Message)"
        if ($abuseKey) { $message = $message.Replace($abuseKey, '***') }
        throw $message
    }
    if (-not (Test-Path $Path) -or (Get-Item $Path).Length -lt 64) { throw 'пустой ответ' }
}

function Test-Zip([string]$Path) {
    $stream = [System.IO.File]::OpenRead($Path)
    try { return $stream.ReadByte() -eq 0x50 -and $stream.ReadByte() -eq 0x4B } finally { $stream.Dispose() }
}

# 1. Репозитории IOC вендоров и отчётов (GitHub).
$repos = @(
    @{ Name = 'eset/malware-ioc'; Dir = 'eset'; Args = @('--eset') },
    @{ Name = 'Neo23x0/signature-base'; Dir = 'sigbase'; Args = @('--signature-base') },
    @{ Name = 'Cisco-Talos/IOCs'; Dir = 'talos'; Args = @('--ioc-reports'); Prefix = 'Talos' },
    @{ Name = 'pan-unit42/iocs'; Dir = 'unit42'; Args = @('--ioc-reports'); Prefix = 'Unit42' },
    @{ Name = 'sophoslabs/IoCs'; Dir = 'sophos'; Args = @('--ioc-reports'); Prefix = 'Sophos' })
foreach ($repo in $repos) {
    try {
        $dir = Join-Path $work $repo.Dir
        git clone --depth 1 --quiet "https://github.com/$($repo.Name)" $dir
        if ($LASTEXITCODE -ne 0) { throw "git clone завершился с кодом $LASTEXITCODE" }
        $buildArgs.Add($repo.Args[0])
        $buildArgs.Add($(if ($repo.Prefix) { "$($repo.Prefix)=$dir" } else { $dir }))
        Write-Host "OK  $($repo.Name)"
    } catch { Write-Warning "Пропущен $($repo.Name): $_" }
}

# 2. MalwareBazaar: с ноября 2026 только по ключу (бесплатный, auth.abuse.ch) в пути адреса. Имена полных выгрузок
#    перебираются по очереди (неверное имя — быстрый 404); последней — выгрузка за 48 часов (recent.csv).
if ($abuseKey) {
    $mb = $null
    foreach ($file in @('full.csv.zip', 'csv_full.zip', 'sha256_full.txt.zip', 'full_sha256.txt.zip', 'recent.csv')) {
        try {
            $path = Join-Path $work ('malwarebazaar_' + $file)
            Get-File "https://mb-api.abuse.ch/v2/files/exports/$abuseKey/$file" $path
            if ($file.EndsWith('.zip') -and -not (Test-Zip $path)) { throw 'ответ не zip' }
            if ($file.EndsWith('.csv') -and (Get-Content $path -TotalCount 1) -notmatch '^(#|"?first_seen)') { throw 'ответ не CSV' }
            $mb = $path
            Write-Host ("OK  MalwareBazaar {0} ({1:N1} МБ)" -f $file, ((Get-Item $path).Length / 1MB))
            break
        } catch { Write-Warning "MalwareBazaar $($file): $_" }
    }
    if ($mb) { $buildArgs.Add('--malwarebazaar'); $buildArgs.Add($mb) }
} else {
    Write-Warning 'MalwareBazaar пропущен: не задан секрет ABUSECH_AUTH_KEY (бесплатный ключ на auth.abuse.ch).'
}

# 3. VirusShare: номер последнего списка — со страницы списков, затем последние N файлов.
try {
    $page = (Invoke-WebRequest -Uri 'https://virusshare.com/hashes' -Headers $headers -TimeoutSec 120 -UseBasicParsing).Content
    $numbers = [regex]::Matches($page, 'VirusShare_(\d{5})\.md5') | ForEach-Object { [int]$_.Groups[1].Value } | Sort-Object -Unique
    if (-not $numbers) { throw 'на странице не найдено ни одного списка' }
    $last = [int](($numbers | Measure-Object -Maximum).Maximum)  # Measure-Object возвращает double: {0:D5} с ним не работает
    $vsDir = Join-Path $work 'virusshare'
    New-Item -ItemType Directory -Force $vsDir | Out-Null
    $ok = 0
    for ([int]$n = $last; $n -gt [Math]::Max(-1, $last - $VirusShareLists); $n--) {
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
