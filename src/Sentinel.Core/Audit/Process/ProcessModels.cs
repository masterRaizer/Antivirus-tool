using Sentinel.Core.Audit.Config;
using Sentinel.Core.Scanning;

namespace Sentinel.Core.Audit.Process;

/// <summary>
/// Снимок одного активного процесса. Собирается платформенно-зависимым поставщиком
/// (<see cref="IProcessProvider"/>), но сам по себе платформонезависим, поэтому вся
/// аналитика (<see cref="ProcessAuditor"/>) тестируется на синтетических снимках в Linux.
/// </summary>
public sealed record ProcessSnapshot
{
    public required int Pid { get; init; }
    public int ParentPid { get; init; }

    /// <summary>Имя образа (например, <c>svchost.exe</c>), как его сообщает ОС.</summary>
    public required string Name { get; init; }

    /// <summary>Полный путь к исполняемому файлу или <c>null</c>, если недоступен.</summary>
    public string? ExecutablePath { get; init; }

    /// <summary>Полная командная строка запуска или <c>null</c>, если недоступна.</summary>
    public string? CommandLine { get; init; }

    /// <summary>Доля CPU (0..100, суммарно по всем ядрам нормировано к одному). Отрицательное — неизвестно.</summary>
    public double CpuPercent { get; init; } = -1;

    /// <summary>Доля загрузки GPU (0..100). Отрицательное — неизвестно/не измерено.</summary>
    public double GpuPercent { get; init; } = -1;

    /// <summary>
    /// Время создания процесса (UTC) или <c>null</c>, если недоступно. Позволяет отличить настоящего
    /// потомка от процесса, чей <see cref="ParentPid"/> совпал с повторно выданным идентификатором.
    /// </summary>
    public DateTime? StartTimeUtc { get; init; }

    public bool CpuKnown => CpuPercent >= 0;
    public bool GpuKnown => GpuPercent >= 0;
}

/// <summary>Поставщик списка активных процессов. Реализация для Windows использует Win32 API.</summary>
public interface IProcessProvider
{
    IReadOnlyList<ProcessSnapshot> GetProcesses();
}

/// <summary>Результат проверки одного процесса: снимок, находки и (если доступен) вердикт анализа файла.</summary>
public sealed record ProcessAuditEntry(
    ProcessSnapshot Process,
    IReadOnlyList<AuditFinding> Findings,
    FileScanResult? FileScan)
{
    /// <summary>Исключения встроенной защиты, под которые попал процесс (пусто — обычная проверка).</summary>
    public IReadOnlyList<DefenderExclusion> MatchedExclusions { get; init; } = [];

    /// <summary>Итог аудита памяти процесса (<c>null</c> — память не проверялась).</summary>
    public Auditors.Memory.MemoryScanResult? MemoryScan { get; init; }

    public bool HasFindings => Findings.Count > 0;
}

/// <summary>Итог аудита процессов.</summary>
public sealed record ProcessAuditReport(IReadOnlyList<ProcessAuditEntry> Entries)
{
    public int ProcessCount => Entries.Count;
    public int FlaggedCount => Entries.Count(e => e.HasFindings);
    public IEnumerable<ProcessAuditEntry> Flagged => Entries.Where(e => e.HasFindings);
}
