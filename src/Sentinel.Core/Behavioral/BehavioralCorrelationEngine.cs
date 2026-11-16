namespace Sentinel.Core.Behavioral;

/// <summary>Корреляционная цепочка поведения.</summary>
public enum CorrelationChain
{
    /// <summary>BH-01: сброс исполняемого файла/скрипта в профиль + последующий ярлык или автозапуск.</summary>
    DropperStaging,

    /// <summary>BH-02: ярлык/скрипт с обфусцированной или бесфайловой конструкцией.</summary>
    WeaponizedArtifact,

    /// <summary>BH-03: новая запись автозапуска на неподписанный бинарник в профиле/временной папке.</summary>
    PersistenceUnsignedProfile,
}

public sealed record CorrelationFinding(CorrelationChain Chain, int Score, string Summary, IReadOnlyList<string> Artifacts);

/// <summary>
/// Потокобезопасный корреляционный движок: кольцевой буфер (не более 2048 событий, окно 60 с) связывает файловые,
/// скриптовые и реестровые события в цепочки BH-01..03. Весь анализ — в User-Mode, без чтения чужой памяти.
/// </summary>
public sealed class BehavioralCorrelationEngine
{
    public const int DefaultCapacity = 2048;

    private static readonly string[] ProfileMarkers =
        [@"\temp\", @"\tmp\", @"\appdata\local\", @"\appdata\roaming\", @"\appdata\", @"\users\public\"];

    private static readonly string[] StagedExtensions =
        [".exe", ".dll", ".ps1", ".vbs", ".hta", ".bat", ".cmd", ".scr", ".js", ".jse", ".wsf"];

    private static readonly string[] WeaponizedArtifactExtensions = [".lnk", ".hta", ".vbs", ".ps1", ".cmd", ".js"];

    private static readonly string[] FilelessMarkers =
    [
        "-enc", "-encodedcommand", "frombase64string", "invoke-expression", "iex(", "iex ", "downloadstring",
        "mshta http", "mshta  http", "rundll32 javascript:", "javascript:\"", "regsvr32 /s /n /u /i:http", "/i:http",
    ];

    private readonly int _capacity;
    private readonly TimeSpan _window;
    private readonly TimeSpan _dropperLink;
    private readonly TimeProvider _time;
    private readonly object _sync = new();
    private readonly LinkedList<Event> _events = new();

    public BehavioralCorrelationEngine(TimeProvider? timeProvider = null, int capacity = DefaultCapacity, TimeSpan? window = null, TimeSpan? dropperLinkWindow = null)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(capacity, 16);
        _capacity = capacity;
        _window = window ?? TimeSpan.FromSeconds(60);
        _dropperLink = dropperLinkWindow ?? TimeSpan.FromSeconds(30);
        _time = timeProvider ?? TimeProvider.System;
    }

    public int Count
    {
        get
        {
            lock (_sync)
            {
                return _events.Count;
            }
        }
    }

    /// <summary>Сброшен новый файл (создан/записан). Возвращает находку, если это замыкает цепочку.</summary>
    public CorrelationFinding? ReportFileWritten(string path, bool isSigned)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        return Ingest(new Event(EventKind.FileWritten, Normalize(path), null, isSigned, _time.GetUtcNow().Ticks));
    }

    /// <summary>Создан ярлык или скрипт; <paramref name="commandLine"/> — его целевая команда (для детекта обфускации).</summary>
    public CorrelationFinding? ReportShortcutOrScript(string path, string? commandLine)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        return Ingest(new Event(EventKind.ShortcutOrScript, Normalize(path), commandLine, false, _time.GetUtcNow().Ticks));
    }

    /// <summary>Зарегистрирована точка автозапуска (Run/RunOnce/Services/Tasks/IFEO), указывающая на <paramref name="target"/>.</summary>
    public CorrelationFinding? ReportAutorunEntry(string area, string target, bool targetSigned)
    {
        ArgumentException.ThrowIfNullOrEmpty(area);
        ArgumentException.ThrowIfNullOrEmpty(target);
        return Ingest(new Event(EventKind.AutorunEntry, Normalize(target), area, targetSigned, _time.GetUtcNow().Ticks));
    }

    private CorrelationFinding? Ingest(Event e)
    {
        lock (_sync)
        {
            Prune(e.Ticks);
            _events.AddLast(e);
            while (_events.Count > _capacity)
            {
                _events.RemoveFirst();
            }

            return Correlate(e);
        }
    }

    private CorrelationFinding? Correlate(Event e)
    {
        switch (e.Kind)
        {
            case EventKind.ShortcutOrScript:
                if (IsWeaponized(e.Detail, e.Path))
                {
                    return new CorrelationFinding(CorrelationChain.WeaponizedArtifact, 55,
                        "Обфусцированный или бесфайловый артефакт (BH-02).", [e.Path]);
                }

                // Ярлык вскоре после сброса бинарника в профиль → BH-01.
                var dropper = FindRecentStagedDropper(e.Ticks);
                if (dropper is not null)
                {
                    return new CorrelationFinding(CorrelationChain.DropperStaging, 50,
                        "Сброс исполняемого файла в профиль с последующим созданием ярлыка (BH-01).", [dropper, e.Path]);
                }

                break;

            case EventKind.AutorunEntry:
                if (!e.Signed && IsInProfile(e.Path) && HasStagedExtension(e.Path))
                {
                    return new CorrelationFinding(CorrelationChain.PersistenceUnsignedProfile, 65,
                        $"Автозапуск ({e.Detail}) на неподписанный файл в профиле: {e.Path} (BH-03).", [e.Path]);
                }

                var staged = FindRecentStagedDropper(e.Ticks);
                if (staged is not null)
                {
                    return new CorrelationFinding(CorrelationChain.DropperStaging, 50,
                        "Сброс исполняемого файла в профиль с последующей записью в автозапуск (BH-01).", [staged, e.Path]);
                }

                break;
        }

        return null;
    }

    private string? FindRecentStagedDropper(long nowTicks)
    {
        for (var node = _events.Last; node is not null; node = node.Previous)
        {
            var e = node.Value;
            if (nowTicks - e.Ticks > _dropperLink.Ticks)
            {
                break;
            }

            if (e.Kind == EventKind.FileWritten && IsInProfile(e.Path) && HasStagedExtension(e.Path))
            {
                return e.Path;
            }
        }

        return null;
    }

    private void Prune(long nowTicks)
    {
        var cutoff = nowTicks - _window.Ticks;
        while (_events.First is { } node && node.Value.Ticks < cutoff)
        {
            _events.RemoveFirst();
        }
    }

    private static bool IsWeaponized(string? commandLine, string path)
    {
        var hasArtifactExt = WeaponizedArtifactExtensions.Contains(Path.GetExtension(path), StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(commandLine))
        {
            return false;
        }

        var lower = commandLine.ToLowerInvariant();
        var fileless = FilelessMarkers.Any(m => lower.Contains(m, StringComparison.Ordinal));
        return fileless && (hasArtifactExt || lower.Contains("powershell", StringComparison.Ordinal)
            || lower.Contains("mshta", StringComparison.Ordinal) || lower.Contains("rundll32", StringComparison.Ordinal)
            || lower.Contains("regsvr32", StringComparison.Ordinal) || lower.Contains("wscript", StringComparison.Ordinal)
            || lower.Contains("cscript", StringComparison.Ordinal) || lower.Contains("cmd", StringComparison.Ordinal));
    }

    private static bool IsInProfile(string path) => ProfileMarkers.Any(m => path.Contains(m, StringComparison.Ordinal));

    private static bool HasStagedExtension(string path) => StagedExtensions.Contains(Path.GetExtension(path), StringComparer.OrdinalIgnoreCase);

    private static string Normalize(string path) => path.Replace('/', '\\').ToLowerInvariant();

    private enum EventKind
    {
        FileWritten,
        ShortcutOrScript,
        AutorunEntry,
    }

    private readonly record struct Event(EventKind Kind, string Path, string? Detail, bool Signed, long Ticks);
}
