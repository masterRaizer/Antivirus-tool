<#
.SYNOPSIS
  Безопасный стенд для детектора скрытых майнеров Sentinel: имитация процесса, который прячет нагрузку от Диспетчера задач.

.DESCRIPTION
  Ничего не майнит и не ходит в сеть. Копирует powershell.exe в %TEMP%\SentinelEvasionTest\svc-evasion-test.exe
  (у копии нет каталожной подписи Microsoft — как у настоящего майнера в профиле пользователя) и запускает в нём
  нагрузку на -Threads потоков. Раз в секунду копия проверяет, открыт ли Диспетчер задач (или Process Explorer,
  Process Hacker, System Informer, Монитор ресурсов): если открыт — нагрузка останавливается, если закрыт — возвращается.
  Через -Minutes минут копия завершается сама.

  Порядок проверки:
    1. powershell -ExecutionPolicy Bypass -File .\scripts\test-monitor-evasion.ps1
    2. Подождать 40 с, открыть Диспетчер задач на 20 с, закрыть.
       Через 5–10 с после закрытия служба Sentinel покажет находку «Прячется от Диспетчера задач» (ждёт решения).
    3. Повторить шаг 2: второй цикл — служба сама завершит процесс и отправит svc-evasion-test.exe в карантин.
    Без службы: в другом окне sentinel.exe evasion-watch 300 — только наблюдение, печатает находки и балл.
    Остановить стенд досрочно: .\scripts\test-monitor-evasion.ps1 -Stop

.PARAMETER NoCopy
  Запускать нагрузку в обычном powershell.exe (подписан Microsoft): служба тогда только пишет находку в журнал.
#>
param(
    [int]$Threads = 2,
    [int]$Minutes = 10,
    [switch]$NoCopy,
    [switch]$Stop,
    [switch]$Child
)

$ErrorActionPreference = 'Stop'
$testName = 'svc-evasion-test'
$monitors = @('Taskmgr', 'procexp', 'procexp64', 'procexp64a', 'ProcessHacker', 'SystemInformer', 'resmon', 'perfmon')

if ($Stop) {
    $running = Get-Process -Name $testName -ErrorAction SilentlyContinue
    $running | Stop-Process -Force
    Write-Host ("Остановлено процессов стенда: {0}." -f @($running).Count)
    return
}

if (-not $Child) {
    $Threads = [Math]::Max(1, [Math]::Min($Threads, [Environment]::ProcessorCount))
    $host_ = Join-Path $PSHOME 'powershell.exe'
    if (-not $NoCopy) {
        $dir = Join-Path $env:TEMP 'SentinelEvasionTest'
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        $host_ = Join-Path $dir "$testName.exe"
        Copy-Item -Path (Join-Path $PSHOME 'powershell.exe') -Destination $host_ -Force
    }

    $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-Child', '-Threads', $Threads, '-Minutes', $Minutes)
    $process = Start-Process -FilePath $host_ -ArgumentList $arguments -WindowStyle Hidden -PassThru
    Write-Host ("Стенд запущен: {0} (PID {1}), потоков нагрузки {2}, автоостановка через {3} мин." -f $host_, $process.Id, $Threads, $Minutes)
    Write-Host 'Подождите 40 с, затем откройте Диспетчер задач на 20 с и закройте его. Повторите — второй цикл служба нейтрализует сама.'
    Write-Host 'Остановить досрочно: .\scripts\test-monitor-evasion.ps1 -Stop'
    return
}

# Дочерний процесс: нагрузка на $Threads потоков, пауза, пока открыт мониторинг.
$state = [hashtable]::Synchronized(@{ Hidden = $false; Stop = $false })
$pool = [runspacefactory]::CreateRunspacePool(1, $Threads)
$pool.Open()
$burn = {
    param($s)
    while (-not $s.Stop) {
        if ($s.Hidden) {
            Start-Sleep -Milliseconds 250
            continue
        }

        $x = 0
        for ($i = 0; $i -lt 300000; $i++) { $x = $x + $i }
    }
}

$workers = for ($t = 0; $t -lt $Threads; $t++) {
    $ps = [powershell]::Create()
    $ps.RunspacePool = $pool
    [void]$ps.AddScript($burn).AddArgument($state)
    [pscustomobject]@{ Shell = $ps; Handle = $ps.BeginInvoke() }
}

$deadline = (Get-Date).AddMinutes($Minutes)
try {
    while ((Get-Date) -lt $deadline) {
        $state.Hidden = [bool](Get-Process -Name $monitors -ErrorAction SilentlyContinue)
        Start-Sleep -Seconds 1
    }
}
finally {
    $state.Stop = $true
    foreach ($w in $workers) {
        [void]$w.Shell.EndInvoke($w.Handle)
        $w.Shell.Dispose()
    }

    $pool.Close()
}
