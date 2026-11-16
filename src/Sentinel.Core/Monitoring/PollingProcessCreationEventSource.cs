using System.Runtime.CompilerServices;

namespace Sentinel.Core.Monitoring;

/// <summary>
/// Резервный источник (Безопасный режим, WinRE, отключённая служба WMI): раз в интервал снимает дешёвый список
/// процессов (PID, родитель, имя — без открытия дескрипторов) и сообщает о процессах, которых не было на прошлом
/// тике. Подробности (путь, командная строка, время старта) запрашиваются только для новых PID.
/// Первый тик — базовая линия: уже работающие процессы покрывает периодический аудит, событий о них нет.
/// </summary>
public sealed class PollingProcessCreationEventSource : IProcessCreationEventSource
{
    private readonly Func<IReadOnlyCollection<ProcessIdentity>> _list;
    private readonly Func<ProcessIdentity, ProcessCreationEvent> _enrich;
    private readonly TimeSpan _interval;
    private readonly TimeProvider _time;
    private HashSet<ProcessIdentity>? _known;

    public PollingProcessCreationEventSource(
        Func<IReadOnlyCollection<ProcessIdentity>> list,
        Func<ProcessIdentity, ProcessCreationEvent> enrich,
        TimeSpan? interval = null,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(list);
        ArgumentNullException.ThrowIfNull(enrich);
        _list = list;
        _enrich = enrich;
        _interval = interval ?? TimeSpan.FromSeconds(1);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(_interval, TimeSpan.Zero);
        _time = timeProvider ?? TimeProvider.System;
    }

    public string Mode => "polling";

    /// <summary>Сбой получения списка процессов (событие не останавливает опрос).</summary>
    public event Action<string>? Faulted;

    public async IAsyncEnumerable<ProcessCreationEvent> ReadEventsAsync([EnumeratorCancellation] CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(_interval, _time);
        do
        {
            foreach (var created in Poll())
            {
                yield return created;
            }
        }
        while (await WaitAsync(timer, cancellationToken).ConfigureAwait(false));
    }

    /// <summary>Один тик опроса: новые процессы относительно предыдущего тика (открыт для тестов).</summary>
    public IReadOnlyList<ProcessCreationEvent> Poll()
    {
        IReadOnlyCollection<ProcessIdentity> current;
        try
        {
            current = _list();
        }
        catch (Exception ex) when (ex is InvalidOperationException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
        {
            Faulted?.Invoke($"Опрос процессов: {ex.Message}");
            return [];
        }

        var alive = current.ToHashSet();
        if (_known is null)
        {
            _known = alive;
            return [];
        }

        var fresh = new List<ProcessCreationEvent>();
        foreach (var id in current)
        {
            if (_known.Contains(id))
            {
                continue;
            }

            try
            {
                fresh.Add(_enrich(id));
            }
            catch (Exception ex) when (ex is InvalidOperationException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
            {
                // Процесс завершился между тиком и запросом подробностей — сообщаем то, что известно.
                fresh.Add(new ProcessCreationEvent(id.Pid, id.ParentPid, id.Name, string.Empty, string.Empty, _time.GetUtcNow()));
            }
        }

        // Завершённые процессы забываются: PID может быть выдан повторно.
        _known = alive;
        return fresh;
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    private static async ValueTask<bool> WaitAsync(PeriodicTimer timer, CancellationToken cancellationToken)
    {
        try
        {
            return await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }
}
