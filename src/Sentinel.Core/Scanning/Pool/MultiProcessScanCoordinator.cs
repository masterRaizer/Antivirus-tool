using System.Diagnostics;
using System.IO.Pipes;
using System.Threading.Channels;

namespace Sentinel.Core.Scanning.Pool;

/// <summary>Запущенный рабочий процесс (или его тестовая замена).</summary>
public interface IWorkerProcess : IDisposable
{
    bool HasExited { get; }

    void Kill();
}

/// <summary>Запускает рабочий процесс, который должен подключиться к каналу <c>pipeName</c>.</summary>
public interface IWorkerLauncher
{
    IWorkerProcess Start(string pipeName, int parentPid);
}

/// <summary>Запуск <c>Sentinel.Cli.exe --scan-worker --pipe … --parent-pid …</c>.</summary>
public sealed class ProcessWorkerLauncher(string executablePath, string rulesDirectory, string dataDirectory, string? allowedExclusionsFile = null,
    IReadOnlyList<string>? leadingArguments = null) : IWorkerLauncher
{
    public IWorkerProcess Start(string pipeName, int parentPid)
    {
        var info = new ProcessStartInfo
        {
            FileName = executablePath,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = false,
            RedirectStandardError = false,
        };
        foreach (var argument in leadingArguments ?? [])
        {
            info.ArgumentList.Add(argument);
        }

        foreach (var argument in new[] { "--scan-worker", "--pipe", pipeName, "--parent-pid", parentPid.ToString(System.Globalization.CultureInfo.InvariantCulture),
            "--rules", rulesDirectory, "--data-dir", dataDirectory })
        {
            info.ArgumentList.Add(argument);
        }

        if (allowedExclusionsFile is not null)
        {
            info.ArgumentList.Add("--allowed-exclusions");
            info.ArgumentList.Add(allowedExclusionsFile);
        }

        var process = Process.Start(info) ?? throw new InvalidOperationException("Не удалось запустить рабочий процесс сканирования.");
        try
        {
            // Как «уступать ресурсы» у Касперского: проверка забирает свободный CPU, но не отнимает его у программ пользователя.
            process.PriorityClass = ProcessPriorityClass.BelowNormal;
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or PlatformNotSupportedException)
        {
            // приоритет — пожелание: без него проверка работает как раньше
        }

        return new ProcessHandle(process);
    }

    private sealed class ProcessHandle(Process process) : IWorkerProcess
    {
        public bool HasExited
        {
            get
            {
                try
                {
                    return process.HasExited;
                }
                catch (InvalidOperationException)
                {
                    return true;
                }
            }
        }

        public void Kill()
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
            {
                // уже завершён
            }
        }

        public void Dispose() => process.Dispose();
    }
}

/// <summary>
/// Пул изолированных рабочих процессов. Файл, на котором процесс упал или завис, фиксируется как <c>ScanError</c>,
/// а на его место сразу запускается новый рабочий — остальная проверка не прерывается.
/// Если рабочие процессы не удаётся запустить, файлы проверяются запасным внутрипроцессным анализатором.
/// </summary>
public sealed class MultiProcessScanCoordinator : ScanPoolBase
{
    private static readonly TimeSpan DefaultConnectTimeout = TimeSpan.FromSeconds(20);
    private static readonly TimeSpan DefaultFileTimeout = TimeSpan.FromMinutes(2);

    private readonly IWorkerLauncher _launcher;
    private readonly Func<string, FileScanResult>? _fallback;
    private readonly TimeSpan _connectTimeout;
    private readonly TimeSpan _fileTimeout;

    public MultiProcessScanCoordinator(IWorkerLauncher launcher, int workerCount, ScanVerdictCache? cache = null,
        Func<string, FileScanResult>? inProcessFallback = null, TimeSpan? connectTimeout = null, TimeSpan? fileTimeout = null)
        : base(workerCount, cache)
    {
        _launcher = launcher ?? throw new ArgumentNullException(nameof(launcher));
        _fallback = inProcessFallback;
        _connectTimeout = connectTimeout ?? DefaultConnectTimeout;
        _fileTimeout = fileTimeout ?? DefaultFileTimeout;
    }

    public override ScanPoolMode Mode => ScanPoolMode.MultiProcess;

    /// <summary>Сколько файлов проверено запасным внутрипроцессным анализатором из-за невозможности запустить рабочий процесс.</summary>
    public long FallbackScans => Interlocked.Read(ref _fallbackScans);

    private long _fallbackScans;

    protected override async Task RunWorkerAsync(int index, ChannelReader<string> input, ChannelWriter<PoolResult> output, ManualResetEventSlim? pauseGate,
        CancellationToken cancellationToken)
    {
        Connection? connection = null;
        var connectFailures = 0;
        try
        {
            await foreach (var path in input.ReadAllAsync(cancellationToken).ConfigureAwait(false))
            {
                await WaitWhilePausedAsync(pauseGate, cancellationToken).ConfigureAwait(false);
                WorkerStarted();
                PoolResult result;
                try
                {
                    if (connection is null && connectFailures < 3)
                    {
                        connection = await TryConnectAsync(cancellationToken).ConfigureAwait(false);
                        connectFailures = connection is null ? connectFailures + 1 : 0;
                    }

                    if (connection is null)
                    {
                        result = ScanInProcess(path);
                    }
                    else
                    {
                        try
                        {
                            result = await connection.ScanAsync(path, _fileTimeout, cancellationToken).ConfigureAwait(false);
                        }
                        catch (Exception ex) when (ex is IOException or TimeoutException or InvalidDataException or ObjectDisposedException
                            || (ex is OperationCanceledException && !cancellationToken.IsCancellationRequested))
                        {
                            // Рабочий упал или завис на этом файле: файл — в журнал, процесс — заменить немедленно.
                            WorkerRestarted();
                            connection.Dispose();
                            connection = null;
                            result = PoolResult.Failed(path, $"ScanError: рабочий процесс завершился при проверке файла ({ex.GetType().Name}); процесс заменён.");
                            connection = await TryConnectAsync(cancellationToken).ConfigureAwait(false);
                        }
                    }
                }
                finally
                {
                    WorkerFinished();
                }

                await output.WriteAsync(result, cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            if (connection is not null)
            {
                await connection.QuitAsync().ConfigureAwait(false);
                connection.Dispose();
            }
        }
    }

    private PoolResult ScanInProcess(string path)
    {
        if (_fallback is null)
        {
            return PoolResult.Failed(path, "ScanError: рабочие процессы не запускаются, запасной анализатор не задан.");
        }

        Interlocked.Increment(ref _fallbackScans);
        try
        {
            return new PoolResult(path, _fallback(path), null, false);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException or InvalidDataException)
        {
            return PoolResult.Failed(path, $"ScanError: {ex.Message}");
        }
    }

    private async Task<Connection?> TryConnectAsync(CancellationToken cancellationToken)
    {
        var pipeName = $"Sentinel.ScanWorker.{Environment.ProcessId}.{Guid.NewGuid():N}";
        var server = new NamedPipeServerStream(pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        IWorkerProcess? process = null;
        try
        {
            process = _launcher.Start(pipeName, Environment.ProcessId);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(_connectTimeout);
            await server.WaitForConnectionAsync(timeout.Token).ConfigureAwait(false);
            var hello = await WorkerProtocol.ReadAsync(server, timeout.Token).ConfigureAwait(false);
            if (hello is not { Type: "hello" })
            {
                throw new InvalidDataException("Рабочий процесс не поздоровался.");
            }

            return new Connection(server, process);
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or InvalidOperationException or System.ComponentModel.Win32Exception
            or OperationCanceledException && !cancellationToken.IsCancellationRequested)
        {
            process?.Kill();
            process?.Dispose();
            await server.DisposeAsync().ConfigureAwait(false);
            return null;
        }
    }

    private sealed class Connection(NamedPipeServerStream pipe, IWorkerProcess process) : IDisposable
    {
        private long _nextId;

        public async Task<PoolResult> ScanAsync(string path, TimeSpan timeout, CancellationToken cancellationToken)
        {
            var id = Interlocked.Increment(ref _nextId);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(timeout);
            try
            {
                await WorkerProtocol.WriteAsync(pipe, new WorkerMessage { Type = "scan", Id = id, Path = path }, cts.Token).ConfigureAwait(false);
                var reply = await WorkerProtocol.ReadAsync(pipe, cts.Token).ConfigureAwait(false)
                    ?? throw new IOException("Рабочий процесс закрыл канал.");
                if (reply.Type != "result" || reply.Id != id)
                {
                    throw new InvalidDataException("Неожиданный ответ рабочего процесса.");
                }

                return reply.Error is not null || reply.Result is null
                    ? PoolResult.Failed(path, $"ScanError: {reply.Error ?? "пустой результат"}")
                    : new PoolResult(path, reply.Result, null, false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                throw new TimeoutException($"Рабочий процесс не ответил за {timeout.TotalSeconds:F0} с.");
            }
        }

        public async Task QuitAsync()
        {
            try
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                await WorkerProtocol.WriteAsync(pipe, new WorkerMessage { Type = "quit" }, cts.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException or ObjectDisposedException)
            {
                // рабочий уже недоступен — будет остановлен принудительно
            }
        }

        public void Dispose()
        {
            if (!process.HasExited)
            {
                process.Kill();
            }

            process.Dispose();
            pipe.Dispose();
        }
    }
}

/// <summary>Выбор режима пула и построение рабочих параметров.</summary>
public static class ScanPoolFactory
{
    public const string CliFileName = "Sentinel.Cli.exe";

    /// <summary>Путь к <c>Sentinel.Cli.exe</c> рядом с текущим бинарником; <c>null</c> — файла нет (портативный <c>Sentinel.App.exe</c>).</summary>
    public static string? FindCli(string? baseDirectory = null)
    {
        var path = Path.Combine(baseDirectory ?? AppContext.BaseDirectory, CliFileName);
        return File.Exists(path) ? path : null;
    }

    /// <summary>
    /// Если рядом найден <c>Sentinel.Cli.exe</c> — пул дочерних процессов; иначе внутрипроцессный пул той же ширины
    /// <c>N = Math.Clamp(Environment.ProcessorCount, 4, 8)</c>, чтобы одиночный <c>Sentinel.App.exe</c> проверял без сбоев.
    /// </summary>
    public static IScanPool Create(Func<string, FileScanResult> analyze, string rulesDirectory, string dataDirectory, ScanVerdictCache? cache,
        string? allowedExclusionsFile = null, string? baseDirectory = null, IWorkerLauncher? launcherOverride = null)
    {
        var workers = ScanPoolBase.DefaultWorkerCount();
        var cli = FindCli(baseDirectory);
        if (launcherOverride is not null)
        {
            return new MultiProcessScanCoordinator(launcherOverride, workers, cache, analyze);
        }

        return cli is null
            ? new InProcessScanPool(analyze, workers, cache)
            : new MultiProcessScanCoordinator(new ProcessWorkerLauncher(cli, rulesDirectory, dataDirectory, allowedExclusionsFile), workers, cache, analyze);
    }
}
