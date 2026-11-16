using Sentinel.Core.Audit.Config;
using Sentinel.Core.Audit.Process;
using Sentinel.Core.Realtime;
using Sentinel.Core.Scanning;

namespace Sentinel.Core.Runtime;

/// <summary>Защита в реальном времени: наблюдение за файлами и периодический аудит.</summary>
public sealed partial class SentinelRuntime
{
    private readonly HashSet<(int Pid, long Start, string? Path)> _seenProcesses = [];
    private FileActivityMonitor? _monitor;
    private IReadOnlyList<DefenderExclusion> _knownExclusions = [];
    private volatile bool _auditRequested = true;

    /// <summary>
    /// Цикл файлового монитора: изменённые файлы (после дебаунса и отсева шума) анализируются,
    /// а находки передаются диспетчеру. Работает до отмены; при выключенной защите наблюдение снято.
    /// </summary>
    public async Task RunFileMonitorAsync(CancellationToken cancellationToken)
    {
        using var monitor = new FileActivityMonitor(_o.Monitor, _o.TimeProvider);
        monitor.Faulted += m => Log?.Invoke(m);
        lock (_sync)
        {
            _monitor = monitor;
        }

        ApplyMonitorState();
        PublishStatus();
        try
        {
            await foreach (var path in monitor.Changes.ReadAllAsync(cancellationToken).ConfigureAwait(false))
            {
                if (!_realtimeEnabled)
                {
                    continue;
                }

                try
                {
                    await InspectFileAsync(path, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Text.Json.JsonException)
                {
                    Log?.Invoke($"Проверка '{path}' не выполнена: {ex.Message}");
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
        finally
        {
            lock (_sync)
            {
                _monitor = null;
            }
        }
    }

    /// <summary>Проверяет один файл и передаёт находку диспетчеру. <c>null</c> — файл чист, разрешён или уже исчез.</summary>
    public async Task<ThreatEvent?> InspectFileAsync(string path, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        if (!File.Exists(path))
        {
            return null;
        }

        // Поведенческий анти-шифровальщик и приманки: изменение файла в профиле наблюдается до обычного анализа.
        ObserveFileActivity(Behavioral.FileEventKind.Modified, path);
        if (IsCanaryFile(path))
        {
            return null; // приманки не проверяются штатным сканером
        }

        var result = _o.Analyzer.Analyze(path);
        if (result.Verdict == Verdict.Error && File.Exists(path))
        {
            // Файл ещё удерживается записывающим процессом — одна повторная попытка после паузы.
            await Task.Delay(TimeSpan.FromMilliseconds(400), _o.TimeProvider, cancellationToken).ConfigureAwait(false);
            result = _o.Analyzer.Analyze(path);
        }

        Interlocked.Increment(ref _filesChecked);
        if (IsPersistenceSurface(path))
        {
            _auditRequested = true; // изменён hosts или задача планировщика — внеочередной аудит автозагрузки
        }

        return await _dispatcher.DispatchFileAsync(result, "realtime", cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Периодический аудит: новые процессы — каждый интервал; точки автозагрузки и исключения
    /// конфигурации — раз в <see cref="SentinelRuntimeOptions.ConfigAuditInterval"/> или сразу после изменения hosts/задач.
    /// </summary>
    public async Task RunPeriodicAuditAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(_o.ProcessAuditInterval, _o.TimeProvider);
        long? lastConfig = null;
        try
        {
            do
            {
                if (!_realtimeEnabled)
                {
                    continue;
                }

                try
                {
                    if (_auditRequested || lastConfig is null || _o.TimeProvider.GetElapsedTime(lastConfig.Value) >= _o.ConfigAuditInterval)
                    {
                        _auditRequested = false;
                        lastConfig = _o.TimeProvider.GetTimestamp();
                        await AuditPersistenceAndConfigAsync(cancellationToken).ConfigureAwait(false);
                    }

                    await AuditNewProcessesAsync(cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException
                    or System.ComponentModel.Win32Exception or System.Text.Json.JsonException)
                {
                    Log?.Invoke($"Фоновый аудит: {ex.Message}");
                }
            }
            while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
        }
    }

    /// <summary>Аудит процессов, появившихся с прошлого вызова. Возвращает число проверенных.</summary>
    public async Task<int> AuditNewProcessesAsync(CancellationToken cancellationToken = default)
    {
        if (_o.Processes is null)
        {
            return 0;
        }

        var snapshot = _o.Processes.GetProcesses();
        List<ProcessSnapshot> fresh;
        IReadOnlyList<DefenderExclusion> exclusions;
        lock (_sync)
        {
            var alive = snapshot.Select(Key).ToHashSet();
            _seenProcesses.IntersectWith(alive); // завершённые процессы забываются: PID может быть выдан повторно
            fresh = snapshot.Where(p => _seenProcesses.Add(Key(p))).ToList();
            exclusions = _knownExclusions;
        }

        if (fresh.Count == 0)
        {
            return 0;
        }

        var report = new ProcessAuditor(new ProcessAuditorOptions { MemoryScanner = _o.MemoryScanner }, _o.Analyzer).Audit(fresh, exclusions);
        Interlocked.Add(ref _processesChecked, fresh.Count);
        foreach (var entry in report.Entries)
        {
            ReportMemoryAnomalies(entry);
        }

        foreach (var entry in report.Flagged)
        {
            await _dispatcher.DispatchProcessAsync(entry, "realtime", cancellationToken).ConfigureAwait(false);
        }

        return fresh.Count;

        static (int, long, string?) Key(ProcessSnapshot p) => (p.Pid, p.StartTimeUtc?.Ticks ?? 0, p.ExecutablePath);
    }

    /// <summary>Аудит критических точек автозагрузки и исключений конфигурации; находки уходят диспетчеру.</summary>
    public async Task AuditPersistenceAndConfigAsync(CancellationToken cancellationToken = default)
    {
        if (_o.PersistenceAudit is not null)
        {
            foreach (var entry in _o.PersistenceAudit().Flagged)
            {
                await _dispatcher.DispatchPersistenceAsync(entry, "realtime", cancellationToken).ConfigureAwait(false);
            }
        }

        if (_o.ConfigAudit is not null)
        {
            var config = _o.ConfigAudit();
            lock (_sync)
            {
                _knownExclusions = config.DefenderExclusions;
            }

            foreach (var (exclusion, finding) in PairExclusions(config))
            {
                await _dispatcher.DispatchExclusionAsync(exclusion, finding, "realtime", cancellationToken).ConfigureAwait(false);
            }
        }

        InvalidateStartup();
    }

    private void ApplyMonitorState()
    {
        FileActivityMonitor? monitor;
        lock (_sync)
        {
            monitor = _monitor;
        }

        if (monitor is null)
        {
            return;
        }

        if (_realtimeEnabled)
        {
            monitor.Start();
        }
        else
        {
            monitor.Stop();
        }
    }

    private IReadOnlyList<string> WatchedDirectories()
    {
        lock (_sync)
        {
            return _monitor?.WatchedDirectories ?? [];
        }
    }

    private static bool IsPersistenceSurface(string path)
    {
        var normalized = FileNoiseFilter.Normalize(path);
        return normalized.EndsWith(@"\drivers\etc\hosts", StringComparison.Ordinal)
            || normalized.Contains(@"\system32\tasks\", StringComparison.Ordinal)
            || normalized.Contains(@"\start menu\programs\startup\", StringComparison.Ordinal);
    }
}
