using Sentinel.Core.Audit.Process;

namespace Sentinel.Core.Remediation;

public enum RemediationActionKind
{
    TerminateProcess,
    RollbackPersistence,
    RemoveDefenderExclusion,
    Undo,
}

public enum RemediationStatus
{
    /// <summary>Действие выполнено.</summary>
    Done,

    /// <summary>Предпросмотр (dry-run): действие было бы выполнено, изменений нет.</summary>
    WouldDo,

    /// <summary>Действие не требуется или не поддерживается для этого объекта.</summary>
    Skipped,

    /// <summary>Запрещено белым списком или защитой критических процессов.</summary>
    Blocked,
    Failed,
}

/// <summary>Результат одного действия нейтрализации.</summary>
public sealed record RemediationAction(
    RemediationActionKind Kind,
    string Target,
    RemediationStatus Status,
    string Message)
{
    /// <summary>Идентификатор записи манифеста отката с резервной копией (если что-то изменено).</summary>
    public string? RollbackId { get; init; }

    public bool Success => Status == RemediationStatus.Done;
}

/// <summary>Результат попытки завершить один процесс из дерева.</summary>
public sealed record ProcessTerminationResult(ProcessSnapshot Process, RemediationStatus Status, string Message);

/// <summary>Результат завершения дерева процессов.</summary>
public sealed record ProcessTreeResult(int RootPid, RemediationStatus Status, string Message, IReadOnlyList<ProcessTerminationResult> Processes)
{
    public int TerminatedCount => Processes.Count(p => p.Status == RemediationStatus.Done);

    public RemediationAction ToAction() =>
        new(RemediationActionKind.TerminateProcess, $"PID {RootPid}", Status, Message);
}

public sealed class RemediationOptions
{
    /// <summary>Путь к манифесту отката (<c>rollback_manifest.json</c>).</summary>
    public required string RollbackManifestPath { get; init; }

    /// <summary>Предпросмотр: все действия только планируются, система и манифест не изменяются.</summary>
    public bool DryRun { get; init; }

    /// <summary>Эталонное значение <c>Winlogon\Shell</c>.</summary>
    public string DefaultShell { get; init; } = "explorer.exe";

    /// <summary>Эталонное значение <c>Winlogon\Userinit</c>.</summary>
    public string DefaultUserinit { get; init; } = @"C:\Windows\system32\userinit.exe,";

    /// <summary>Политика системных процессов: защищает критические процессы с неизвестным путём.</summary>
    public SystemProcessPolicy SystemPolicy { get; init; } = SystemProcessPolicy.CreateDefault();

    /// <summary>PID текущего процесса — Sentinel никогда не завершает сам себя.</summary>
    public int CurrentProcessId { get; init; } = Environment.ProcessId;

    public static RemediationOptions CreateDefault(string dataDirectory, bool dryRun = false)
    {
        ArgumentException.ThrowIfNullOrEmpty(dataDirectory);
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        return new RemediationOptions
        {
            RollbackManifestPath = Path.Combine(dataDirectory, RollbackManifestStore.DefaultFileName),
            DryRun = dryRun,
            DefaultUserinit = string.IsNullOrEmpty(windows)
                ? @"C:\Windows\system32\userinit.exe,"
                : Path.Combine(windows, "system32", "userinit.exe") + ",",
        };
    }
}
