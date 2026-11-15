using System.Threading.Channels;

namespace Sentinel.Core.Scanning.Pool;

/// <summary>Результат проверки одного пути в пуле.</summary>
/// <param name="Result">Результат анализа; <c>null</c> для пропущенных по кэшу и для ошибок.</param>
/// <param name="Error">Описание сбоя (<c>ScanError</c>): файл не удалось проверить, рабочий процесс заменён.</param>
/// <param name="FromCache">Файл не менялся и ранее признан чистым — повторная проверка не выполнялась.</param>
public sealed record PoolResult(string Path, FileScanResult? Result, string? Error, bool FromCache)
{
    public static PoolResult Cached(string path) => new(path, null, null, true);

    public static PoolResult Failed(string path, string error) => new(path, null, error, false);
}

public enum ScanPoolMode
{
    /// <summary>Параллельные потоки внутри текущего процесса (нет <c>Sentinel.Cli.exe</c> рядом, например портативный <c>Sentinel.App.exe</c>).</summary>
    InProcess,

    /// <summary>Изолированные дочерние процессы <c>Sentinel.Cli.exe --scan-worker</c>: сбой разбора файла не затрагивает остальные.</summary>
    MultiProcess,
}

/// <summary>Пул параллельной проверки файлов.</summary>
public interface IScanPool : IAsyncDisposable
{
    ScanPoolMode Mode { get; }

    int WorkerCount { get; }

    /// <summary>Сколько рабочих прямо сейчас проверяют файл.</summary>
    int ActiveWorkers { get; }

    /// <summary>Сколько рабочих процессов было заменено после сбоя.</summary>
    long WorkerRestarts { get; }

    /// <summary>
    /// Проверяет файлы параллельно; результаты передаются в <paramref name="onResult"/> по одному, последовательно (вызов не потокобезопасный не требуется).
    /// <paramref name="pauseGate"/>: пока сброшен, новые файлы не берутся в работу. Отмена токена останавливает пул.
    /// </summary>
    Task RunAsync(IEnumerable<string> files, Func<PoolResult, ValueTask> onResult, ManualResetEventSlim? pauseGate, CancellationToken cancellationToken);
}

/// <summary>Общая часть пулов: подача файлов, кэш чистых файлов, пауза, сбор результатов.</summary>
public abstract class ScanPoolBase : IScanPool
{
    private int _active;
    private long _restarts;

    protected ScanPoolBase(int workerCount, ScanVerdictCache? cache)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(workerCount, 1);
        WorkerCount = workerCount;
        Cache = cache;
    }

    public abstract ScanPoolMode Mode { get; }

    public int WorkerCount { get; }

    public int ActiveWorkers => Volatile.Read(ref _active);

    public long WorkerRestarts => Interlocked.Read(ref _restarts);

    protected ScanVerdictCache? Cache { get; }

    public static int DefaultWorkerCount() => Math.Clamp(Environment.ProcessorCount, 4, 8);

    public async Task RunAsync(IEnumerable<string> files, Func<PoolResult, ValueTask> onResult, ManualResetEventSlim? pauseGate, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(files);
        ArgumentNullException.ThrowIfNull(onResult);
        var input = Channel.CreateBounded<string>(new BoundedChannelOptions(Math.Max(64, WorkerCount * 32)) { SingleWriter = true, SingleReader = false });
        var output = Channel.CreateBounded<PoolResult>(new BoundedChannelOptions(1024) { SingleReader = true });
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var token = linked.Token;

        var producer = Task.Factory.StartNew(() => Produce(files, input.Writer, output.Writer, pauseGate, token),
            CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        var workers = Enumerable.Range(0, WorkerCount)
            .Select(index => Task.Run(() => RunWorkerAsync(index, input.Reader, output.Writer, pauseGate, token), CancellationToken.None))
            .ToArray();
        var completion = Task.Run(async () =>
        {
            try
            {
                await producer.ConfigureAwait(false);
                await Task.WhenAll(workers).ConfigureAwait(false);
                output.Writer.TryComplete();
            }
            catch (Exception ex)
            {
                output.Writer.TryComplete(ex);
            }
        }, CancellationToken.None);

        try
        {
            await foreach (var result in output.Reader.ReadAllAsync(CancellationToken.None).ConfigureAwait(false))
            {
                if (result.Result is { Verdict: Verdict.Clean or Verdict.Trusted } && Cache is not null)
                {
                    Cache.MarkClean(result.Path);
                }

                await onResult(result).ConfigureAwait(false);
            }
        }
        finally
        {
            await linked.CancelAsync().ConfigureAwait(false);
            try
            {
                await completion.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // остановка пользователем
            }

            Cache?.Save();
        }

        cancellationToken.ThrowIfCancellationRequested();
    }

    protected abstract Task RunWorkerAsync(int index, ChannelReader<string> input, ChannelWriter<PoolResult> output, ManualResetEventSlim? pauseGate, CancellationToken cancellationToken);

    public virtual ValueTask DisposeAsync()
    {
        GC.SuppressFinalize(this);
        return ValueTask.CompletedTask;
    }

    protected void WorkerStarted() => Interlocked.Increment(ref _active);

    protected void WorkerFinished() => Interlocked.Decrement(ref _active);

    protected void WorkerRestarted() => Interlocked.Increment(ref _restarts);

    /// <summary>Ожидание снятия паузы без блокировки при обычной работе.</summary>
    protected static async ValueTask WaitWhilePausedAsync(ManualResetEventSlim? gate, CancellationToken cancellationToken)
    {
        if (gate is null || gate.IsSet)
        {
            return;
        }

        await Task.Run(() => gate.Wait(cancellationToken), cancellationToken).ConfigureAwait(false);
    }

    private void Produce(IEnumerable<string> files, ChannelWriter<string> input, ChannelWriter<PoolResult> output, ManualResetEventSlim? pauseGate, CancellationToken token)
    {
        try
        {
            foreach (var file in files)
            {
                token.ThrowIfCancellationRequested();
                if (pauseGate is { IsSet: false })
                {
                    pauseGate.Wait(token);
                }

                if (Cache is not null && Cache.IsKnownClean(file))
                {
                    output.WriteAsync(PoolResult.Cached(file), token).AsTask().GetAwaiter().GetResult();
                    continue;
                }

                input.WriteAsync(file, token).AsTask().GetAwaiter().GetResult();
            }
        }
        finally
        {
            input.TryComplete();
        }
    }
}

/// <summary>Параллельные потоки внутри процесса поверх <c>Channel&lt;string&gt;</c>: запасной режим, когда рядом нет <c>Sentinel.Cli.exe</c>.</summary>
public sealed class InProcessScanPool(Func<string, FileScanResult> analyze, int workerCount, ScanVerdictCache? cache = null) : ScanPoolBase(workerCount, cache)
{
    public override ScanPoolMode Mode => ScanPoolMode.InProcess;

    protected override async Task RunWorkerAsync(int index, ChannelReader<string> input, ChannelWriter<PoolResult> output, ManualResetEventSlim? pauseGate,
        CancellationToken cancellationToken)
    {
        // Анализ синхронный и нагружает процессор/диск: каждому рабочему — собственный поток, а не общий пул задач.
        await Task.Factory.StartNew(async () =>
        {
            await foreach (var path in input.ReadAllAsync(cancellationToken).ConfigureAwait(false))
            {
                await WaitWhilePausedAsync(pauseGate, cancellationToken).ConfigureAwait(false);
                WorkerStarted();
                PoolResult result;
                try
                {
                    result = new PoolResult(path, analyze(path), null, false);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException or InvalidDataException)
                {
                    result = PoolResult.Failed(path, $"ScanError: {ex.Message}");
                }
                finally
                {
                    WorkerFinished();
                }

                await output.WriteAsync(result, cancellationToken).ConfigureAwait(false);
            }
        }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default).Unwrap().ConfigureAwait(false);
    }
}
