namespace Sentinel.Core.Monitoring.Evasion;

/// <summary>Пороги детектора уклонения от мониторинга. Значения по умолчанию подобраны против ложных срабатываний.</summary>
public sealed class MonitorEvasionOptions
{
    /// <summary>
    /// Средства мониторинга, от которых прячутся скрытые майнеры: Диспетчер задач, Монитор ресурсов, Системный монитор,
    /// Process Explorer, Process Hacker / System Informer, Process Monitor и аналоги.
    /// </summary>
    public static readonly IReadOnlySet<string> DefaultMonitorTools = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "Taskmgr.exe", "resmon.exe", "perfmon.exe", "procexp.exe", "procexp64.exe", "procexp64a.exe",
        "ProcessHacker.exe", "SystemInformer.exe", "Procmon.exe", "Procmon64.exe", "Procmon64a.exe",
        "anvir.exe", "AnVir.exe", "prio.exe", "ProcessLasso.exe", "HWiNFO64.exe", "HWiNFO32.exe", "OpenHardwareMonitor.exe",
        "LibreHardwareMonitor.exe", "HWMonitor.exe", "HWMonitor_x64.exe", "MSIAfterburner.exe", "GPU-Z.exe", "AIDA64.exe",
    };

    /// <summary>
    /// Служебные процессы ядра без образа: не кандидаты (их нагрузка — работа самой ОС, действовать по ним нельзя).
    /// </summary>
    public static readonly IReadOnlySet<string> KernelPseudoProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "System", "System Idle Process", "Idle", "Registry", "Memory Compression", "Secure System", "Interrupts",
    };

    public IReadOnlySet<string> MonitorTools { get; init; } = DefaultMonitorTools;

    /// <summary>Окно, по которому считается обычная нагрузка процесса перед открытием мониторинга.</summary>
    public TimeSpan BaselineWindow { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>Минимум замеров в окне базовой нагрузки (при замере раз в секунду — 10 с наблюдения).</summary>
    public int MinBaselineSamples { get; init; } = 10;

    /// <summary>Минимальная средняя нагрузка, при которой процесс вообще рассматривается (0,25 — четверть ядра).</summary>
    public double MinBaselineCores { get; init; } = 0.25;

    /// <summary>Минимальная средняя нагрузка на видеокарту (0,15 — 15 %), при которой процесс рассматривается как GPU-кандидат.</summary>
    public double MinBaselineGpu { get; init; } = 0.15;

    /// <summary>«Тихо» для видеокарты — не выше этого абсолютного уровня (3 %), если он больше доли от базовой нагрузки.</summary>
    public double QuietFloorGpu { get; init; } = 0.03;

    /// <summary>Доля замеров окна, в которых нагрузка не ниже половины средней: отсекает всплески (сборка, распаковка).</summary>
    public double MinActiveShare { get; init; } = 0.8;

    /// <summary>Сколько последних замеров перед открытием мониторинга процесс обязан быть активным.</summary>
    public int PreOpenActiveSamples { get; init; } = 3;

    /// <summary>За сколько после появления мониторинга процесс должен затихнуть, чтобы это считалось реакцией.</summary>
    public TimeSpan ReactionWindow { get; init; } = TimeSpan.FromSeconds(12);

    /// <summary>Сколько замеров подряд процесс должен быть «тихим», чтобы считать, что он спрятался.</summary>
    public int QuietSamplesRequired { get; init; } = 3;

    /// <summary>«Тихо» — не выше этой доли базовой нагрузки…</summary>
    public double QuietFraction { get; init; } = 0.2;

    /// <summary>…или не выше этого абсолютного уровня в ядрах (что больше).</summary>
    public double QuietFloorCores { get; init; } = 0.05;

    /// <summary>Сколько активных замеров подряд при открытом мониторинге снимают подозрение (процесс не прятался).</summary>
    public int BreakSamples { get; init; } = 2;

    /// <summary>Сколько ждать возврата нагрузки после закрытия мониторинга.</summary>
    public TimeSpan ResumeWindow { get; init; } = TimeSpan.FromSeconds(90);

    /// <summary>Сколько замеров подряд нагрузка должна держаться, чтобы считать её вернувшейся.</summary>
    public int ResumeSamplesRequired { get; init; } = 3;

    /// <summary>Возврат — не ниже этой доли базовой нагрузки.</summary>
    public double ResumeFraction { get; init; } = 0.5;

    /// <summary>Сколько хранится история нагрузки процесса.</summary>
    public TimeSpan HistoryWindow { get; init; } = TimeSpan.FromSeconds(120);

    /// <summary>Как долго помнятся циклы «спрятался — вернулся» по имени образа (повторение усиливает вердикт).</summary>
    public TimeSpan CycleMemory { get; init; } = TimeSpan.FromHours(24);

    /// <summary>Разрыв между замерами, после которого история сбрасывается (сон, гибернация, зависание службы).</summary>
    public TimeSpan MaxSampleGap { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>Скрытая нагрузка: не меньше стольких ядер…</summary>
    public double HiddenCpuMinCores { get; init; } = 1.0;

    /// <summary>…и не меньше этой доли всех логических процессоров.</summary>
    public double HiddenCpuMinShare { get; init; } = 0.15;

    /// <summary>Сколько скрытая нагрузка должна держаться без перерыва.</summary>
    public TimeSpan HiddenCpuSustain { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>
    /// Замеры, между которыми появилось или завершилось больше процессов, не учитываются: время короткоживущих процессов
    /// не попадает в сумму видимых и выглядело бы как скрытая нагрузка (например, при сборке проекта).
    /// </summary>
    public int HiddenCpuMaxChurn { get; init; } = 2;

    /// <summary>Минимальный интервал между повторными сообщениями о скрытой нагрузке.</summary>
    public TimeSpan HiddenCpuCooldown { get; init; } = TimeSpan.FromMinutes(30);
}

/// <summary>Счётчики детектора для журнала, CLI и интерфейса.</summary>
public sealed record MonitorEvasionStats(long Samples, int MonitorOpenings, int Findings, int HiddenCpuAlerts, string? OpenMonitor, int WatchedCandidates);

/// <summary>
/// Детектор скрытых майнеров, которые прячутся от средств мониторинга. Логика: у каждого процесса хранится история
/// нагрузки на процессор (по накопленному времени ядра и пользователя). Когда появляется Диспетчер задач или аналог,
/// кандидатами становятся процессы с устойчивой нагрузкой за последние 30 с. Если кандидат затих за 12 с после
/// появления мониторинга и молчит, пока тот открыт, — он «спрятался»; если после закрытия мониторинга нагрузка
/// вернулась — это полный цикл, самый сильный признак. Повторные циклы того же образа за сутки усиливают вердикт.
/// Отдельно сравнивается общая занятость процессоров с суммой видимых процессов: устойчивый разрыв — признак процесса,
/// скрытого руткитом. Детектор чисто вычислительный (без вызовов ОС): данные даёт <see cref="IProcessActivitySampler"/>.
/// Не потокобезопасен: замеры подаются последовательно из одного цикла.
/// </summary>
public sealed class MonitorEvasionDetector
{
    private readonly MonitorEvasionOptions _o;
    private readonly int _ownPid;
    private readonly Dictionary<(int Pid, long Create), Track> _tracks = [];
    private readonly Dictionary<string, List<TimeSpan>> _cycles = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, List<TimeSpan>> _exits = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<Candidate> _waiting = [];
    private ActivitySnapshot? _last;
    private Episode? _episode;
    private TimeSpan? _hiddenSince;
    private double _hiddenSum;
    private int _hiddenCount;
    private TimeSpan? _lastHiddenReport;
    private long _samples;
    private int _openings;
    private int _findings;
    private int _hiddenAlerts;

    public MonitorEvasionDetector(MonitorEvasionOptions? options = null, int? ownProcessId = null)
    {
        _o = options ?? new MonitorEvasionOptions();
        _ownPid = ownProcessId ?? Environment.ProcessId;
    }

    public MonitorEvasionOptions Options => _o;

    public MonitorEvasionStats Stats => new(
        _samples, _openings, _findings, _hiddenAlerts, _episode?.Monitor,
        (_episode?.Candidates.Count(c => !c.Done) ?? 0) + _waiting.Count(c => !c.Done));

    /// <summary>Обрабатывает очередной замер и возвращает находки, подтвердившиеся на нём.</summary>
    public EvasionObservation Observe(ActivitySnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        _samples++;
        var last = _last;
        _last = snapshot;
        var interval = last is null ? TimeSpan.Zero : snapshot.Clock - last.Clock;
        if (last is null || interval <= TimeSpan.Zero || interval > _o.MaxSampleGap)
        {
            // Первый замер или разрыв (сон, гибернация): скорости по старым точкам неверны — начинаем заново.
            Reset(snapshot);
            return EvasionObservation.Quiet(_episode is not null, _episode?.Monitor);
        }

        var present = new HashSet<(int, long)>();
        var appeared = 0;
        var visibleCores = 0.0;
        foreach (var p in snapshot.Processes)
        {
            if (p.Pid == 0)
            {
                continue; // «Бездействие системы» — не процесс, его время — простой процессоров
            }

            var key = (p.Pid, p.CreateTimeTicks);
            present.Add(key);
            if (!_tracks.TryGetValue(key, out var track))
            {
                _tracks[key] = new Track(p.Pid, p.CreateTimeTicks, p.ParentPid, p.Name, p.CpuTimeTicks);
                appeared++;
                continue;
            }

            var cores = Math.Max(0, p.CpuTimeTicks - track.LastCpu) / (double)interval.Ticks;
            track.LastCpu = p.CpuTimeTicks;
            track.Points.Add(new Point(snapshot.Clock, cores, p.GpuPercent >= 0 ? Math.Min(1, p.GpuPercent / 100) : -1));
            var horizon = snapshot.Clock - _o.HistoryWindow;
            var stale = track.Points.FindIndex(x => x.Clock >= horizon);
            if (stale > 0)
            {
                track.Points.RemoveRange(0, stale);
            }

            visibleCores += cores;
        }

        var exited = _tracks.Keys.Where(k => !present.Contains(k)).ToList();
        var findings = new List<MonitorEvasionFinding>();

        var monitor = snapshot.Processes.FirstOrDefault(p => _o.MonitorTools.Contains(p.Name));
        if (monitor is not null)
        {
            if (_episode is null)
            {
                OpenEpisode(snapshot, last, monitor);
            }

            UpdateOpenEpisode(snapshot, present, findings);
        }
        else if (_episode is not null)
        {
            CloseEpisode(snapshot);
        }

        UpdateWaiting(snapshot, present, findings);

        foreach (var key in exited)
        {
            _tracks.Remove(key);
        }

        var hidden = ObserveHiddenCpu(snapshot, last, interval, visibleCores, appeared + exited.Count);
        _findings += findings.Count;
        return new EvasionObservation(findings, hidden, _episode is not null, _episode?.Monitor);
    }

    private void Reset(ActivitySnapshot snapshot)
    {
        _tracks.Clear();
        _waiting.Clear();
        _episode = null;
        _hiddenSince = null;
        foreach (var p in snapshot.Processes.Where(p => p.Pid != 0))
        {
            _tracks[(p.Pid, p.CreateTimeTicks)] = new Track(p.Pid, p.CreateTimeTicks, p.ParentPid, p.Name, p.CpuTimeTicks);
        }

        // Мониторинг, открытый уже в момент первого замера, не даёт эпизода: базовой нагрузки «до» нет.
        var monitor = snapshot.Processes.FirstOrDefault(p => _o.MonitorTools.Contains(p.Name));
        if (monitor is not null)
        {
            _episode = new Episode(monitor.Name, monitor.Pid, snapshot.Clock, snapshot.TimestampUtc);
        }
    }

    private void OpenEpisode(ActivitySnapshot snapshot, ActivitySnapshot last, ProcessActivitySample monitor)
    {
        _openings++;
        // Мониторинг появился где-то между прошлым и текущим замером: отсчёт реакции — от прошлого замера.
        var episode = new Episode(monitor.Name, monitor.Pid, last.Clock, snapshot.TimestampUtc);
        var monitorPids = snapshot.Processes.Where(p => _o.MonitorTools.Contains(p.Name)).Select(p => p.Pid).ToHashSet();

        // Уже спрятавшиеся при прошлом открытии и ещё не вернувшиеся: продолжают ждать закрытия нового эпизода.
        foreach (var waiting in _waiting.Where(c => !c.Done))
        {
            waiting.ResumeRun = 0;
            waiting.QuietRun = 0;
            episode.Candidates.Add(waiting);
        }

        _waiting.Clear();
        var already = episode.Candidates.Select(c => (c.Key, c.Resource)).ToHashSet();

        foreach (var (key, track) in _tracks)
        {
            if (key.Pid <= 4 || key.Pid == _ownPid || monitorPids.Contains(key.Pid)
                || monitorPids.Contains(track.ParentPid) || _o.MonitorTools.Contains(track.Name)
                || MonitorEvasionOptions.KernelPseudoProcesses.Contains(track.Name))
            {
                continue;
            }

            foreach (var resource in Resources)
            {
                if (!already.Contains((key, resource)) && Baseline(snapshot, track, resource) is { } candidate)
                {
                    episode.Candidates.Add(candidate);
                }
            }
        }

        _episode = episode;
    }

    private static readonly ActivityResource[] Resources = [ActivityResource.Cpu, ActivityResource.Gpu];

    /// <summary>Нагрузка точки по ресурсу; −1 — неизвестно (нагрузка видеокарты не замерялась).</summary>
    private static double Load(Point x, ActivityResource resource) => resource == ActivityResource.Cpu ? x.Cores : x.Gpu;

    private double MinBaseline(ActivityResource resource) => resource == ActivityResource.Cpu ? _o.MinBaselineCores : _o.MinBaselineGpu;

    private double QuietThreshold(Candidate c) =>
        Math.Max(c.Resource == ActivityResource.Cpu ? _o.QuietFloorCores : _o.QuietFloorGpu, c.Baseline * _o.QuietFraction);

    /// <summary>Кандидат по ресурсу, если нагрузка на него до открытия мониторинга была устойчивой; иначе <c>null</c>.</summary>
    private Candidate? Baseline(ActivitySnapshot snapshot, Track track, ActivityResource resource)
    {
        // Базовая нагрузка — строго до текущего замера: в его интервал уже попадает реакция на мониторинг.
        var baseline = track.Points
            .Where(x => x.Clock < snapshot.Clock && x.Clock >= snapshot.Clock - _o.BaselineWindow && Load(x, resource) >= 0)
            .Select(x => Load(x, resource))
            .ToList();
        var horizon = snapshot.Clock - _o.CycleMemory;
        if (Count(_cycles, track.Name, horizon) + Count(_exits, track.Name, horizon) > 0)
        {
            // Образ уже прятался: при быстром повторном открытии Диспетчера достаточно непрерывной нагрузки после
            // возврата (не меньше PreOpenActiveSamples замеров) — полного окна в 10 с у него ещё нет.
            var tail = baseline.Count - 1;
            while (tail >= 0 && baseline[tail] >= MinBaseline(resource))
            {
                tail--;
            }

            baseline = baseline.GetRange(tail + 1, baseline.Count - tail - 1);
            if (baseline.Count < _o.PreOpenActiveSamples)
            {
                return null;
            }
        }
        else if (baseline.Count < _o.MinBaselineSamples)
        {
            return null;
        }

        var mean = baseline.Average();
        if (mean < MinBaseline(resource))
        {
            return null;
        }

        var activeShare = baseline.Count(x => x >= mean * 0.5) / (double)baseline.Count;
        var preOpen = baseline.TakeLast(_o.PreOpenActiveSamples).ToList();
        if (activeShare < _o.MinActiveShare || preOpen.Count < _o.PreOpenActiveSamples
            || preOpen.Exists(x => x < mean * _o.ResumeFraction))
        {
            return null;
        }

        var deviation = Math.Sqrt(baseline.Average(x => (x - mean) * (x - mean)));
        return new Candidate((track.Pid, track.Create), track.Name, track.ParentPid, resource, mean, mean > 0 ? deviation / mean : 0);
    }

    /// <summary>По процессу уже есть находка: кандидат по другому ресурсу того же процесса больше не нужен.</summary>
    private void CloseSiblings(Candidate reported)
    {
        foreach (var c in (_episode?.Candidates ?? []).Concat(_waiting))
        {
            if (!ReferenceEquals(c, reported) && c.Key == reported.Key)
            {
                c.Done = true;
            }
        }
    }

    private void UpdateOpenEpisode(ActivitySnapshot snapshot, HashSet<(int, long)> present, List<MonitorEvasionFinding> findings)
    {
        var episode = _episode!;
        foreach (var c in episode.Candidates.Where(c => !c.Done))
        {
            var elapsed = snapshot.Clock - episode.OpenedClock;
            if (!present.Contains(c.Key))
            {
                if (!c.Dropped && elapsed <= _o.ReactionWindow)
                {
                    var count = Remember(_exits, c.Name, snapshot.Clock);
                    findings.Add(Finding(c, EvasionKind.ExitOnMonitor, episode, elapsed, null, snapshot) with { ExitCount = count });
                    CloseSiblings(c);
                }

                c.Done = true;
                continue;
            }

            var point = _tracks[c.Key].Points.LastOrDefault();
            var cores = point is null ? 0 : Load(point, c.Resource);
            if (cores < 0)
            {
                continue; // нагрузка видеокарты в этом замере неизвестна — ждём следующий
            }

            var quiet = cores <= QuietThreshold(c);
            if (c.Dropped)
            {
                // Спрятавшийся процесс снова нагрузил процессор при открытом мониторинге — он не прятался.
                c.BreakRun = quiet ? 0 : c.BreakRun + 1;
                if (c.BreakRun >= _o.BreakSamples)
                {
                    c.Done = true;
                }
                else if (quiet)
                {
                    c.QuietSum += cores;
                    c.QuietSamples++;
                }

                continue;
            }

            if (quiet)
            {
                c.QuietRun++;
                c.FirstQuiet ??= snapshot.Clock;
                c.QuietSum += cores;
                c.QuietSamples++;
            }
            else
            {
                c.QuietRun = 0;
                c.FirstQuiet = null;
                c.QuietSum = 0;
                c.QuietSamples = 0;
            }

            if (c.QuietRun >= _o.QuietSamplesRequired && c.FirstQuiet is { } first && first - episode.OpenedClock <= _o.ReactionWindow)
            {
                c.Dropped = true;
                c.Reaction = first - episode.OpenedClock;
                c.Monitor = episode.Monitor;
                c.OpenedUtc = episode.OpenedUtc;
            }
            else if (elapsed > _o.ReactionWindow + TimeSpan.FromTicks(_o.MaxSampleGap.Ticks * _o.QuietSamplesRequired))
            {
                c.Done = true; // не отреагировал на мониторинг
            }
        }
    }

    private void CloseEpisode(ActivitySnapshot snapshot)
    {
        foreach (var c in _episode!.Candidates.Where(c => !c.Done))
        {
            if (c.Dropped)
            {
                c.ClosedClock = snapshot.Clock;
                c.ClosedUtc = snapshot.TimestampUtc;
                c.ResumeRun = 0;
                _waiting.Add(c);
            }
        }

        _episode = null;
    }

    private void UpdateWaiting(ActivitySnapshot snapshot, HashSet<(int, long)> present, List<MonitorEvasionFinding> findings)
    {
        if (_episode is not null)
        {
            return; // мониторинг открыт — ожидание возврата нагрузки начнётся после его закрытия
        }

        foreach (var c in _waiting.Where(c => !c.Done))
        {
            if (!present.Contains(c.Key))
            {
                c.Done = true; // завершился, пока прятался: возврат не подтвердить
                continue;
            }

            var point = _tracks[c.Key].Points.LastOrDefault();
            var cores = point is null ? 0 : Load(point, c.Resource);
            if (cores < 0)
            {
                continue;
            }

            if (cores >= c.Baseline * _o.ResumeFraction)
            {
                c.ResumeRun++;
                c.FirstResume ??= snapshot.Clock;
            }
            else
            {
                c.ResumeRun = 0;
                c.FirstResume = null;
            }

            var sinceClose = snapshot.Clock - c.ClosedClock!.Value;
            if (c.ResumeRun >= _o.ResumeSamplesRequired)
            {
                var cycles = Remember(_cycles, c.Name, snapshot.Clock);
                var finding = Finding(c, EvasionKind.HideAndResume, null, c.Reaction, c.FirstResume!.Value - c.ClosedClock.Value, snapshot);
                findings.Add(finding with { CycleCount = cycles });
                c.Done = true;
                CloseSiblings(c);
            }
            else if (sinceClose > _o.ResumeWindow)
            {
                findings.Add(Finding(c, EvasionKind.HiddenWhileMonitorOpen, null, c.Reaction, null, snapshot));
                c.Done = true;
                CloseSiblings(c);
            }
        }

        _waiting.RemoveAll(c => c.Done);
    }

    private MonitorEvasionFinding Finding(
        Candidate c, EvasionKind kind, Episode? episode, TimeSpan reaction, TimeSpan? resume, ActivitySnapshot snapshot)
    {
        var horizon = snapshot.Clock - _o.CycleMemory;
        return new MonitorEvasionFinding
        {
            Kind = kind,
            Pid = c.Key.Pid,
            ParentPid = c.ParentPid,
            Name = c.Name,
            Resource = c.Resource,
            CreateTimeTicks = c.Key.Create,
            Monitor = episode?.Monitor ?? c.Monitor ?? "мониторинга",
            BaselineCores = c.Baseline,
            BaselineVariation = c.Variation,
            QuietCores = c.QuietSamples > 0 ? c.QuietSum / c.QuietSamples : 0,
            Reaction = reaction,
            ResumeDelay = resume,
            CycleCount = Count(_cycles, c.Name, horizon),
            ExitCount = Count(_exits, c.Name, horizon),
            MonitorOpenedUtc = episode?.OpenedUtc ?? c.OpenedUtc,
            MonitorClosedUtc = c.ClosedUtc,
        };
    }

    private int Remember(Dictionary<string, List<TimeSpan>> map, string name, TimeSpan clock)
    {
        if (!map.TryGetValue(name, out var list))
        {
            map[name] = list = [];
        }

        list.RemoveAll(x => x < clock - _o.CycleMemory);
        list.Add(clock);
        return list.Count;
    }

    private static int Count(Dictionary<string, List<TimeSpan>> map, string name, TimeSpan horizon) =>
        map.TryGetValue(name, out var list) ? list.Count(x => x >= horizon) : 0;

    private HiddenCpuFinding? ObserveHiddenCpu(ActivitySnapshot snapshot, ActivitySnapshot last, TimeSpan interval, double visibleCores, int churn)
    {
        if (snapshot.System is not { } now || last.System is not { } before)
        {
            return null;
        }

        var accounted = (now.BusyTicks - before.BusyTicks) - (now.DpcTicks - before.DpcTicks) - (now.InterruptTicks - before.InterruptTicks);
        var hidden = (accounted / (double)interval.Ticks) - visibleCores;
        var threshold = Math.Max(_o.HiddenCpuMinCores, _o.HiddenCpuMinShare * snapshot.ProcessorCount);
        if (churn > _o.HiddenCpuMaxChurn || hidden < threshold)
        {
            _hiddenSince = null;
            _hiddenSum = 0;
            _hiddenCount = 0;
            return null;
        }

        _hiddenSince ??= last.Clock;
        _hiddenSum += hidden;
        _hiddenCount++;
        var duration = snapshot.Clock - _hiddenSince.Value;
        if (duration < _o.HiddenCpuSustain || (_lastHiddenReport is { } previous && snapshot.Clock - previous < _o.HiddenCpuCooldown))
        {
            return null;
        }

        var finding = new HiddenCpuFinding(snapshot.TimestampUtc, _hiddenSum / _hiddenCount, snapshot.ProcessorCount, duration);
        _lastHiddenReport = snapshot.Clock;
        _hiddenSince = null;
        _hiddenSum = 0;
        _hiddenCount = 0;
        _hiddenAlerts++;
        return finding;
    }

    /// <summary>Замер процесса: нагрузка на процессор в ядрах и на видеокарту в долях (−1 — неизвестно).</summary>
    private sealed record Point(TimeSpan Clock, double Cores, double Gpu);

    private sealed class Track(int pid, long create, int parentPid, string name, long cpu)
    {
        public int Pid { get; } = pid;

        public long Create { get; } = create;

        public int ParentPid { get; } = parentPid;

        public string Name { get; } = name;

        public long LastCpu { get; set; } = cpu;

        public List<Point> Points { get; } = [];
    }

    private sealed class Episode(string monitor, int monitorPid, TimeSpan openedClock, DateTimeOffset openedUtc)
    {
        public string Monitor { get; } = monitor;

        public int MonitorPid { get; } = monitorPid;

        public TimeSpan OpenedClock { get; } = openedClock;

        public DateTimeOffset OpenedUtc { get; } = openedUtc;

        public List<Candidate> Candidates { get; } = [];
    }

    private sealed class Candidate((int Pid, long Create) key, string name, int parentPid, ActivityResource resource, double baseline, double variation)
    {
        public (int Pid, long Create) Key { get; } = key;

        public string Name { get; } = name;

        public int ParentPid { get; } = parentPid;

        public ActivityResource Resource { get; } = resource;

        public double Baseline { get; } = baseline;

        public double Variation { get; } = variation;

        public bool Done { get; set; }

        public bool Dropped { get; set; }

        public int QuietRun { get; set; }

        public TimeSpan? FirstQuiet { get; set; }

        public double QuietSum { get; set; }

        public int QuietSamples { get; set; }

        public int BreakRun { get; set; }

        public TimeSpan Reaction { get; set; }

        public string? Monitor { get; set; }

        public DateTimeOffset OpenedUtc { get; set; }

        public TimeSpan? ClosedClock { get; set; }

        public DateTimeOffset? ClosedUtc { get; set; }

        public int ResumeRun { get; set; }

        public TimeSpan? FirstResume { get; set; }
    }
}
