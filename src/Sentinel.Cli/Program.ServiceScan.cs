using System.Text.Json;
using Sentinel.Core.Ipc;

namespace Sentinel.Cli;

internal static partial class Program
{
    /// <summary>
    /// <c>service-scan quick|full|custom &lt;путь&gt; [--wait] [--json]</c> — запуск проверки в службе (как кнопка в окне). С <c>--wait</c>
    /// ждёт завершения, раз в 5 с печатает прогресс и в конце — итог (длительность, объекты, скорость, находки, номер отчёта).
    /// </summary>
    private static int ServiceScan(CliOptions opts)
    {
        ScanRequest? request = opts.Target?.ToLowerInvariant() switch
        {
            "quick" => new ScanRequest(ScanMode.Quick),
            "full" => new ScanRequest(ScanMode.Full),
            "custom" when !string.IsNullOrWhiteSpace(opts.Argument) => new ScanRequest(ScanMode.Custom, Path.GetFullPath(opts.Argument)),
            _ => null,
        };
        if (request is null)
        {
            Console.Error.WriteLine("Использование: sentinel service-scan quick|full|custom <путь> [--wait] [--json]");
            return ExitError;
        }

        var client = SentinelIpcClient.TryConnectAsync(opts.Pipe ?? IpcProtocol.DefaultPipeName, TimeSpan.FromSeconds(3)).GetAwaiter().GetResult();
        if (client is null)
        {
            Console.Error.WriteLine("Служба Sentinel не запущена или недоступна.");
            return ExitError;
        }

        try
        {
            var started = client.StartScanAsync(request).GetAwaiter().GetResult();
            if (!started.Success)
            {
                Console.Error.WriteLine($"Проверка не запущена: {started.Message}");
                return ExitError;
            }

            if (!opts.Json)
            {
                Console.WriteLine($"Проверка запущена в службе: {request.Mode}{(request.Path is null ? string.Empty : " — " + request.Path)}.");
            }

            if (!opts.Wait)
            {
                return ExitOk;
            }

            ScanProgress progress;
            var lastPrint = DateTime.MinValue;
            while (true)
            {
                Thread.Sleep(TimeSpan.FromSeconds(1));
                progress = client.GetStatusAsync().GetAwaiter().GetResult().Scan;
                if (!progress.IsActive)
                {
                    break;
                }

                if (!opts.Json && DateTime.UtcNow - lastPrint >= TimeSpan.FromSeconds(5))
                {
                    lastPrint = DateTime.UtcNow;
                    Console.WriteLine($"  [{progress.Percent,3:0}%] {progress.Stage}: {progress.Scanned:N0} из {progress.Total:N0}, "
                        + $"{progress.ItemsPerSecond:N1} об/с, {progress.BytesPerSecond / (1024 * 1024):N1} МБ/с — {progress.CurrentItem}");
                }
            }

            if (opts.Json)
            {
                Console.WriteLine(JsonSerializer.Serialize(progress, JsonOptions));
            }
            else
            {
                Console.WriteLine($"{progress.State}: объектов {progress.Scanned:N0} за {progress.ElapsedSeconds:N0} с "
                    + $"({progress.ItemsPerSecond:N1} об/с), прочитано {progress.BytesScanned / (1024 * 1024):N0} МБ, находок {progress.Threats}, "
                    + $"ошибок {progress.Errors}, отчёт {progress.ReportId ?? "—"}.");
            }

            return progress.State != ScanState.Completed ? ExitError : progress.Threats > 0 ? ExitDetected : ExitOk;
        }
        finally
        {
            client.DisposeAsync().AsTask().GetAwaiter().GetResult();
        }
    }
}
