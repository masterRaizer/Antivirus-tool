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

    /// <summary>BH-04: неподписанный файл, только что сброшенный в профиль, сразу запущен как процесс.</summary>
    DropAndExecute,

    /// <summary>BH-05: полезная нагрузка в памяти (PE/сигнатура) у процесса с обфусцированным запуском или только что сброшенного.</summary>
    InMemoryPayload,
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

    /// <summary>Признаки бесфайлового запуска сами по себе (закодированная/декодируемая нагрузка, скрипт по URL).</summary>
    private static readonly string[] StrongFilelessMarkers =
    [
        "frombase64string", "downloadstring", "mshta http", "mshta  http", "rundll32 javascript:", "javascript:\"",
        "regsvr32 /s /n /u /i:http", "/i:http",
    ];

    /// <summary>
    /// <c>-e</c>/<c>-ec</c>/<c>-enc</c>…<c>-EncodedCommand</c> как отдельный ключ с base64-аргументом. Подстрока «-enc» без этого
    /// ловила и обычный <c>-Encoding UTF8</c> служебных команд.
    /// </summary>
    private static readonly System.Text.RegularExpressions.Regex EncodedCommand = new(
        @"(?<![\w-])[-/]e(?:c|n|nc|nco|ncod|ncode|ncoded|ncodedc|ncodedco|ncodedcom|ncodedcomm|ncodedcomma|ncodedcomman|ncodedcommand)?\s+['""]?[a-z0-9+/]{8,}={0,2}",
        System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    /// <summary>Invoke-Expression/IEX — отдельным словом.</summary>
    private static readonly System.Text.RegularExpressions.Regex Iex = new(
        @"(?<![a-z0-9_-])iex(?![a-z0-9_-])|invoke-expression", System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    /// <summary>Загрузка из сети: IEX опасен как «download cradle», а одиночный IEX — обычный приём служебных сценариев.</summary>
    private static readonly System.Text.RegularExpressions.Regex Download = new(
        @"downloadstring|downloadfile|downloaddata|invoke-webrequest|invoke-restmethod|net\.webclient|start-bitstransfer|(?<![a-z0-9_-])(?:iwr|irm|curl|wget)(?![a-z0-9_-])",
        System.Text.RegularExpressions.RegexOptions.CultureInvariant);

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

    /// <summary>
    /// Стартовал процесс (событие <c>ProcessStartMonitor</c>): командная строка проверяется на обфускацию и бесфайловый
    /// запуск (BH-02), запуск неподписанной цели свежего автозапуска из профиля — BH-03, запуск только что сброшенного
    /// неподписанного файла из профиля — BH-04.
    /// </summary>
    public CorrelationFinding? ReportProcessStart(string imagePath, string? commandLine, bool isSigned)
    {
        ArgumentException.ThrowIfNullOrEmpty(imagePath);
        return Ingest(new Event(EventKind.ProcessStart, Normalize(imagePath), commandLine, isSigned, _time.GetUtcNow().Ticks));
    }

    /// <summary>
    /// Аномалия памяти процесса (<c>MEM-REFLECTIVE-PE</c>/<c>MEM-YARA-MATCH</c>). Замыкает BH-05, если тот же образ недавно
    /// стартовал с обфусцированной командной строкой или был только что сброшен в профиль и запущен.
    /// </summary>
    public CorrelationFinding? ReportMemoryAnomaly(string imagePath, string anomaly)
    {
        ArgumentException.ThrowIfNullOrEmpty(imagePath);
        ArgumentException.ThrowIfNullOrEmpty(anomaly);
        return Ingest(new Event(EventKind.MemoryAnomaly, Normalize(imagePath), anomaly, false, _time.GetUtcNow().Ticks));
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

            case EventKind.ProcessStart:
                return CorrelateProcessStart(e);

            case EventKind.MemoryAnomaly:
                return CorrelateMemoryAnomaly(e);
        }

        return null;
    }

    private CorrelationFinding? CorrelateProcessStart(Event e)
    {
        // Имя образа добавляется к строке: WMI и PEB иногда отдают аргументы без пути к интерпретатору.
        var imageName = Path.GetFileName(e.Path.Replace('\\', '/'));
        if (IsWeaponized($"{imageName} {e.Detail}", e.Path))
        {
            return new CorrelationFinding(CorrelationChain.WeaponizedArtifact, 55,
                $"Запуск процесса с обфусцированной или бесфайловой командной строкой (BH-02): {imageName}.", [e.Path]);
        }

        if (e.Signed || !IsInProfile(e.Path) || !HasStagedExtension(e.Path))
        {
            return null;
        }

        var dropped = false;
        for (var node = _events.Last?.Previous; node is not null; node = node.Previous)
        {
            var prior = node.Value;
            if (!string.Equals(prior.Path, e.Path, StringComparison.Ordinal))
            {
                continue;
            }

            if (prior.Kind == EventKind.AutorunEntry && !prior.Signed)
            {
                return new CorrelationFinding(CorrelationChain.PersistenceUnsignedProfile, 65,
                    $"Сработал свежий автозапуск ({prior.Detail}) неподписанного файла из профиля: {e.Path} (BH-03).", [e.Path]);
            }

            if (prior.Kind == EventKind.FileWritten && e.Ticks - prior.Ticks <= _dropperLink.Ticks)
            {
                dropped = true;
            }
        }

        return dropped
            ? new CorrelationFinding(CorrelationChain.DropAndExecute, 60,
                $"Неподписанный файл сброшен в профиль и сразу запущен (BH-04): {e.Path}.", [e.Path])
            : null;
    }

    private CorrelationFinding? CorrelateMemoryAnomaly(Event e)
    {
        for (var node = _events.Last?.Previous; node is not null; node = node.Previous)
        {
            var start = node.Value;
            if (start.Kind != EventKind.ProcessStart || !string.Equals(start.Path, e.Path, StringComparison.Ordinal))
            {
                continue;
            }

            var imageName = Path.GetFileName(start.Path.Replace('\\', '/'));
            var weaponized = IsWeaponized($"{imageName} {start.Detail}", start.Path);
            var dropped = !start.Signed && IsInProfile(start.Path) && HasStagedExtension(start.Path) && WasDroppedBefore(start);
            if (weaponized || dropped)
            {
                return new CorrelationFinding(CorrelationChain.InMemoryPayload, 85,
                    $"Полезная нагрузка в памяти ({e.Detail}) у процесса с {(weaponized ? "обфусцированным запуском" : "только что сброшенным образом")}: {e.Path} (BH-05).",
                    [e.Path]);
            }

            break; // учитывается только последний старт этого образа
        }

        return null;
    }

    private bool WasDroppedBefore(Event start)
    {
        for (var node = _events.First; node is not null; node = node.Next)
        {
            var v = node.Value;
            if (v.Kind == EventKind.FileWritten && string.Equals(v.Path, start.Path, StringComparison.Ordinal)
                && v.Ticks <= start.Ticks && start.Ticks - v.Ticks <= _dropperLink.Ticks)
            {
                return true;
            }
        }

        return false;
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
        var fileless = StrongFilelessMarkers.Any(m => lower.Contains(m, StringComparison.Ordinal))
            || EncodedCommand.IsMatch(lower)
            || (Iex.IsMatch(lower) && Download.IsMatch(lower));
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
        ProcessStart,
        MemoryAnomaly,
    }

    private readonly record struct Event(EventKind Kind, string Path, string? Detail, bool Signed, long Ticks);
}
