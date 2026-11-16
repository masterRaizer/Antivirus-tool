<#
.SYNOPSIS
    Синтетический стенд для проверки MemoryIntegrityScanner (модуль 8/2) на живой Windows.

.DESCRIPTION
    Выделяет в СОБСТВЕННОМ процессе PowerShell приватный регион MEM_PRIVATE с защитой PAGE_EXECUTE_READWRITE
    и копирует туда безопасные тестовые данные:
      * строку EICAR (стандартный безвредный тестовый образец антивирусов) — ожидается находка MEM-YARA-MATCH;
      * с ключом -WithPeHeader — ещё и синтетический заголовок MZ/PE (64 байта DOS-заголовка + "PE\0\0" + Machine x64,
        без единой инструкции кода) по адресу начала региона — ожидается MEM-REFLECTIVE-PE.
    Память никогда не исполняется. Служба проверяет процесс один раз — сразу после старта, когда региона ещё нет,
    поэтому детерминированная проверка — командой CLI из второго окна (от имени администратора), пока скрипт ждёт:
        Sentinel.Cli.exe audit-memory <PID>        (PID печатается ниже)

    Ожидаемый результат: аномалии MEM-YARA-MATCH (EICAR-Test-File) и с -WithPeHeader — MEM-REFLECTIVE-PE (PE (x64))
    по адресу региона, код выхода 1.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\test-memory-scanner.ps1 -WithPeHeader
#>
[CmdletBinding()]
param(
    [switch] $WithPeHeader,
    [int] $WaitSeconds = 60
)

$ErrorActionPreference = 'Stop'

Add-Type -Namespace SentinelTest -Name Native -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true)]
public static extern System.IntPtr VirtualAlloc(System.IntPtr lpAddress, System.UIntPtr dwSize, uint flAllocationType, uint flProtect);

[DllImport("kernel32.dll", SetLastError = true)]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool VirtualFree(System.IntPtr lpAddress, System.UIntPtr dwSize, uint dwFreeType);
'@

$MEM_COMMIT_RESERVE = 0x3000
$PAGE_EXECUTE_READWRITE = 0x40
$MEM_RELEASE = 0x8000
$size = 64KB

$region = [SentinelTest.Native]::VirtualAlloc([IntPtr]::Zero, [UIntPtr]::new($size), $MEM_COMMIT_RESERVE, $PAGE_EXECUTE_READWRITE)
if ($region -eq [IntPtr]::Zero) {
    throw "VirtualAlloc завершился ошибкой $([Runtime.InteropServices.Marshal]::GetLastWin32Error())."
}

try {
    if ($WithPeHeader) {
        $header = New-Object byte[] 0x88
        $header[0] = 0x4D; $header[1] = 0x5A                                  # MZ
        [BitConverter]::GetBytes([int]0x80).CopyTo($header, 0x3C)             # e_lfanew
        [Text.Encoding]::ASCII.GetBytes("PE").CopyTo($header, 0x80)           # PE\0\0
        [BitConverter]::GetBytes([uint16]0x8664).CopyTo($header, 0x84)        # Machine = x64
        [Runtime.InteropServices.Marshal]::Copy($header, 0, $region, $header.Length)
    }

    # EICAR собирается из частей, чтобы сам скрипт на диске не детектировался.
    $eicar = [Text.Encoding]::ASCII.GetBytes('X5O!P%@AP[4\PZX54(P^)7CC)7}$' + 'EICAR' + '-STANDARD-ANTIVIRUS-TEST-' + 'FILE!$H+H*')
    [Runtime.InteropServices.Marshal]::Copy($eicar, 0, [IntPtr]::Add($region, 0x1000), $eicar.Length)

    Write-Host ("PID {0}: регион MEM_PRIVATE + PAGE_EXECUTE_READWRITE по адресу 0x{1:X} ({2} КБ) подготовлен." -f $PID, $region.ToInt64(), $size / 1KB)
    Write-Host "Выполните во втором окне:  Sentinel.Cli.exe audit-memory $PID"
    Write-Host "Ожидание $WaitSeconds с, затем регион будет освобождён..."
    Start-Sleep -Seconds $WaitSeconds
}
finally {
    [void][SentinelTest.Native]::VirtualFree($region, [UIntPtr]::Zero, $MEM_RELEASE)
}
