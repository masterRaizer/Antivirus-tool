using Sentinel.Core.Audit.Config;
using Sentinel.Core.Audit.Process;
using Sentinel.Core.Remediation;

namespace Sentinel.Core.Tests;

/// <summary>«Живая» таблица процессов для тестов: завершение удаляет процесс из снимка.</summary>
internal sealed class FakeProcessHost : IProcessProvider, IProcessTerminator
{
    private readonly List<ProcessSnapshot> _processes = [];

    public List<int> Killed { get; } = [];

    public HashSet<int> Unkillable { get; } = [];

    public FakeProcessHost Add(int pid, int parent, string name, string? path = null, DateTime? start = null)
    {
        _processes.Add(new ProcessSnapshot { Pid = pid, ParentPid = parent, Name = name, ExecutablePath = path, StartTimeUtc = start });
        return this;
    }

    public bool IsRunning(int pid) => _processes.Any(p => p.Pid == pid);

    public IReadOnlyList<ProcessSnapshot> GetProcesses() => _processes.ToArray();

    public ProviderResult Terminate(int pid)
    {
        if (Unkillable.Contains(pid))
        {
            return ProviderResult.Fail("Отказано в доступе.");
        }

        Killed.Add(pid);
        _processes.RemoveAll(p => p.Pid == pid);
        return ProviderResult.Ok;
    }
}

internal sealed class FakeTaskEditor : IScheduledTaskEditor
{
    public Dictionary<string, string> Tasks { get; } = new(StringComparer.OrdinalIgnoreCase);

    public string? ExportXml(string taskPath) => Tasks.GetValueOrDefault(taskPath);

    public ProviderResult Delete(string taskPath) =>
        Tasks.Remove(taskPath) ? ProviderResult.Ok : ProviderResult.Fail("Задача не найдена.");

    public ProviderResult Create(string taskPath, string xml)
    {
        Tasks[taskPath] = xml;
        return ProviderResult.Ok;
    }
}

/// <summary>Имитация MSFT_MpPreference: хранит списки исключений и журнал вызовов Add/Remove.</summary>
internal sealed class FakeDefender : IDefenderPreferenceProvider
{
    public List<(DefenderExclusionKind Kind, string Value)> Exclusions { get; } = [];

    public List<string> Calls { get; } = [];

    public bool FailRemove { get; set; }

    public ProviderResult RemoveExclusion(DefenderExclusionKind kind, string value)
    {
        Calls.Add($"Remove:{kind}:{value}");
        if (FailRemove)
        {
            return ProviderResult.Fail("0x800106ba");
        }

        Exclusions.RemoveAll(e => e.Kind == kind && string.Equals(e.Value, value, StringComparison.OrdinalIgnoreCase));
        return ProviderResult.Ok;
    }

    public ProviderResult AddExclusion(DefenderExclusionKind kind, string value)
    {
        Calls.Add($"Add:{kind}:{value}");
        Exclusions.Add((kind, value));
        return ProviderResult.Ok;
    }
}
