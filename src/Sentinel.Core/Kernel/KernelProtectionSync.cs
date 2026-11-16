using System.Runtime.CompilerServices;
using Sentinel.Core.Audit.Process;
using Sentinel.Core.Monitoring;
using Sentinel.Core.Protection;
using Sentinel.Core.Scanning;

namespace Sentinel.Core.Kernel;

/// <summary>
/// Подбирает PID, которые драйвер защищает от снятия дескрипторов, и передаёт их в ядро при изменении:
/// собственный процесс, процессы Sentinel из каталога установки и ядро ОС (<c>csrss</c>, <c>smss</c>, <c>wininit</c>,
/// <c>services</c>, <c>lsass</c>, <c>winlogon</c>) — только из системного каталога (маскировка защиты не получает).
/// <c>svchost.exe</c> и <c>explorer.exe</c> не включаются: их штатно перезапускают пользователь и SCM.
/// Переданный список публикуется и в <see cref="CriticalProcessGuard"/> — User-Mode и ядро защищают одно и то же.
/// </summary>
public sealed class KernelProtectionSync
{
    private static readonly HashSet<string> KernelProtectedSystemImages = new(StringComparer.OrdinalIgnoreCase)
    {
        "csrss.exe", "smss.exe", "wininit.exe", "services.exe", "lsass.exe", "winlogon.exe",
    };

    private readonly IKernelBridge _bridge;
    private readonly IProcessProvider? _processes;
    private readonly int _ownPid;
    private readonly string[] _extraOwnDirectories;
    private readonly bool _publishToGuard;
    private int[] _last = [];

    public KernelProtectionSync(
        IKernelBridge bridge,
        IProcessProvider? processes,
        int? ownProcessId = null,
        IEnumerable<string>? extraOwnDirectories = null,
        bool publishToGuard = true)
    {
        ArgumentNullException.ThrowIfNull(bridge);
        _bridge = bridge;
        _processes = processes;
        _ownPid = ownProcessId ?? Environment.ProcessId;
        _extraOwnDirectories = (extraOwnDirectories ?? []).ToArray();
        _publishToGuard = publishToGuard;
    }

    /// <summary>Последний список, принятый драйвером.</summary>
    public IReadOnlyList<int> Current => _last;

    /// <summary>Выбор защищаемых PID из снимка процессов (открыт для тестов).</summary>
    public static IReadOnlyList<int> SelectProtectedPids(IEnumerable<ProcessSnapshot> processes, int ownProcessId, params string[] extraOwnDirectories)
    {
        ArgumentNullException.ThrowIfNull(processes);
        var own = new List<int> { ownProcessId };
        var system = new List<int>();
        foreach (var p in processes)
        {
            if (p.Pid <= 4 || p.Pid == ownProcessId || string.IsNullOrEmpty(p.ExecutablePath))
            {
                continue;
            }

            if (SelfProtection.IsOwnImageName(p.Name) && SelfProtection.IsInOwnDirectory(p.ExecutablePath, extraOwnDirectories))
            {
                own.Add(p.Pid);
            }
            else if (KernelProtectedSystemImages.Contains(p.Name)
                && CriticalProcessGuard.IsProtectedProcess(p.Pid, p.Name, p.ExecutablePath))
            {
                system.Add(p.Pid);
            }
        }

        // Процессы Sentinel — первыми: при переполнении (> 64) отбрасываются системные, а не собственные.
        return own.Concat(system.Order()).Distinct().Take(KernelProtocol.MaxProtectedPids).ToArray();
    }

    /// <summary>
    /// Передаёт драйверу актуальный список, если он изменился. <c>null</c> — драйвер недоступен или изменений нет.
    /// </summary>
    public KernelOperationResult? Synchronize()
    {
        if (!_bridge.IsConnected)
        {
            return null;
        }

        var snapshot = _processes?.GetProcesses() ?? [];
        var pids = SelectProtectedPids(snapshot, _ownPid, _extraOwnDirectories).ToArray();
        if (pids.AsSpan().SequenceEqual(_last))
        {
            return null;
        }

        var result = _bridge.SetProtectedProcesses(pids);
        if (result.Success)
        {
            _last = pids;
            if (_publishToGuard)
            {
                CriticalProcessGuard.SetKernelProtectedProcessIds(pids);
            }
        }

        return result;
    }
}

/// <summary>
/// Источник событий старта процессов из драйвера (<c>PsSetCreateProcessNotifyRoutineEx</c> → кольцевой буфер →
/// <c>IOCTL_SENTINEL_READ_EVENTS</c>). Если связь с драйвером потеряна, переключается на резервный источник
/// (WMI/опрос) — монитор продолжает работать без перезапуска службы.
/// </summary>
public sealed class KernelProcessCreationEventSource : IProcessCreationEventSource
{
    private readonly IKernelBridge _bridge;
    private readonly Func<IProcessCreationEventSource>? _fallback;
    private readonly TimeSpan _interval;
    private readonly TimeProvider _time;
    private IProcessCreationEventSource? _active;

    public KernelProcessCreationEventSource(
        IKernelBridge bridge, Func<IProcessCreationEventSource>? fallback = null, TimeSpan? pollInterval = null, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(bridge);
        _bridge = bridge;
        _fallback = fallback;
        _interval = pollInterval ?? TimeSpan.FromMilliseconds(250);
        _time = timeProvider ?? TimeProvider.System;
    }

    public string Mode => _active?.Mode is { } fallbackMode ? $"kernel→{fallbackMode}" : "kernel";

    /// <summary>Переход на резервный источник (для журнала службы).</summary>
    public event Action<string>? Log;

    public async IAsyncEnumerable<ProcessCreationEvent> ReadEventsAsync([EnumeratorCancellation] CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested && _bridge.IsConnected)
        {
            var batch = _bridge.ReadEvents();
            foreach (var e in batch)
            {
                if (e.Kind == KernelProcessEventKind.Create)
                {
                    yield return e.ToCreationEvent();
                }
            }

            // Полный пакет — в буфере ещё есть события: забираем без паузы.
            if (batch.Count < KernelProtocol.DefaultReadBatch && !await DelayAsync(cancellationToken).ConfigureAwait(false))
            {
                yield break;
            }
        }

        if (cancellationToken.IsCancellationRequested || _fallback is null)
        {
            yield break;
        }

        _active = _fallback();
        Log?.Invoke($"{_bridge.GetStatus().Message}: мониторинг старта процессов переключён на источник '{_active.Mode}'.");
        await foreach (var e in _active.ReadEventsAsync(cancellationToken).ConfigureAwait(false))
        {
            yield return e;
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_active is not null)
        {
            await _active.DisposeAsync().ConfigureAwait(false);
        }
    }

    private async ValueTask<bool> DelayAsync(CancellationToken cancellationToken)
    {
        try
        {
            await Task.Delay(_interval, _time, cancellationToken).ConfigureAwait(false);
            return true;
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }
}
