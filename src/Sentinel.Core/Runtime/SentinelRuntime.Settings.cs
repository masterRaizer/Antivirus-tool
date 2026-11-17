using Sentinel.Core.Ipc;
using Sentinel.Core.Settings;
using Sentinel.Core.ThreatIntel;

namespace Sentinel.Core.Runtime;

/// <summary>Настройки, список разрешённого, базы угроз и удаление из карантина — раздел «Настройки и базы».</summary>
public sealed partial class SentinelRuntime
{
    /// <summary>Интервал фонового автообновления баз.</summary>
    public static readonly TimeSpan DatabaseUpdateInterval = TimeSpan.FromHours(6);

    private readonly object _updateSync = new();
    private Task<DatabaseStatus>? _updateTask;
    private ThreatFeedUpdater? _feeds;

    private SentinelConfigStore ConfigStore => _o.Services?.Config ?? SentinelConfigStore.ForDataDirectory(_o.DataDirectory);

    private ThreatFeedUpdater? Feeds
    {
        get
        {
            if (_feeds is null && _o.Services is { } services)
            {
                _feeds = new ThreatFeedUpdater(_o.DataDirectory, services.Config, services.ThreatIntel, SentinelServices.Http, _o.TimeProvider);
            }

            return _feeds;
        }
    }

    public async Task<OperationResult> DeleteQuarantineAsync(string id, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);
        var result = await _o.Quarantine.DeleteAsync(id, cancellationToken).ConfigureAwait(false);
        PublishStatus();
        return new OperationResult(result.Success, result.Message);
    }

    public Task<SettingsSnapshot> GetSettingsAsync(CancellationToken cancellationToken = default)
    {
        var config = LoadConfigSafe();
        AllowedExclusions allowed;
        try
        {
            allowed = _allowed.Load();
        }
        catch (System.Text.Json.JsonException)
        {
            allowed = AllowedExclusions.Empty;
        }

        return Task.FromResult(new SettingsSnapshot
        {
            HasKasperskyOpenTipApiKey = !string.IsNullOrWhiteSpace(config.KasperskyOpenTipApiKey),
            HasVirusTotalApiKey = !string.IsNullOrWhiteSpace(config.VirusTotalApiKey),
            HasAbuseChAuthKey = !string.IsNullOrWhiteSpace(config.AbuseChAuthKey),
            AutoUpdateDatabases = config.AutoUpdateDatabases,
            EnableRansomwareShield = config.EnableRansomwareShield,
            EnableCanaryFiles = config.EnableCanaryFiles,
            EnableUsbShield = config.EnableUsbShield,
            BehavioralShadowMode = config.BehavioralShadowMode,
            AllowedPaths = allowed.Paths,
            AllowedProcesses = allowed.Processes,
            AllowedHashes = allowed.Hashes,
            Database = CurrentDatabaseStatus(),
            DataDirectory = _o.DataDirectory,
        });
    }

    /// <summary>
    /// Сохраняет настройки и список разрешённого. Анализатор и аудиторы перечитывают оба файла по времени изменения,
    /// поэтому новые правила действуют со следующей проверки без перезапуска службы; кэш чистых файлов сбрасывается автоматически.
    /// </summary>
    public Task<OperationResult> SaveSettingsAsync(SettingsUpdate update, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(update);
        var invalid = update.AllowedHashes.FirstOrDefault(h => !ThreatFeedParsers.TryNormalizeSha256(h, out _));
        if (invalid is not null)
        {
            return Task.FromResult(OperationResult.Fail($"Некорректный SHA-256: '{invalid}'. Ожидается 64 шестнадцатеричных символа."));
        }

        try
        {
            var config = LoadConfigSafe();
            ConfigStore.Save(config with
            {
                KasperskyOpenTipApiKey = Apply(config.KasperskyOpenTipApiKey, update.KasperskyOpenTipApiKey),
                VirusTotalApiKey = Apply(config.VirusTotalApiKey, update.VirusTotalApiKey),
                AbuseChAuthKey = Apply(config.AbuseChAuthKey, update.AbuseChAuthKey),
                AutoUpdateDatabases = update.AutoUpdateDatabases,
                EnableRansomwareShield = update.EnableRansomwareShield,
                EnableCanaryFiles = update.EnableCanaryFiles,
                EnableUsbShield = update.EnableUsbShield,
                BehavioralShadowMode = update.BehavioralShadowMode,
            });

            _allowed.Replace(new AllowedExclusions
            {
                Paths = Distinct(update.AllowedPaths),
                Processes = Distinct(update.AllowedProcesses),
                Hashes = Distinct(update.AllowedHashes.Select(h => h.Trim().ToLowerInvariant())),
            });
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Task.FromResult(OperationResult.Fail($"Не удалось сохранить настройки: {ex.Message}"));
        }

        PublishStatus();
        return Task.FromResult(OperationResult.Ok("Настройки сохранены и применены."));

        static string? Apply(string? current, string? incoming) =>
            incoming is null ? current : string.IsNullOrWhiteSpace(incoming) ? null : incoming.Trim();

        static string[] Distinct(IEnumerable<string> values) =>
            values.Where(v => !string.IsNullOrWhiteSpace(v)).Select(v => v.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    /// <summary>Запускает обновление баз в фоне (не чаще одного одновременно) и сразу возвращает текущий статус.</summary>
    public Task<DatabaseStatus> UpdateDatabasesAsync(CancellationToken cancellationToken = default)
    {
        if (Feeds is null)
        {
            return Task.FromResult(new DatabaseStatus { LastStatus = "Базы угроз недоступны в этом режиме." });
        }

        lock (_updateSync)
        {
            if (_updateTask is null || _updateTask.IsCompleted)
            {
                _updateTask = Task.Run(RunUpdateAsync, CancellationToken.None);
            }
        }

        return Task.FromResult(CurrentDatabaseStatus() with { LastStatus = "Обновление баз выполняется…" });
    }

    /// <summary>Фоновое автообновление баз каждые 6 часов (если включено в настройках). Первое — через 2 минуты после запуска.</summary>
    public async Task RunDatabaseUpdatesAsync(CancellationToken cancellationToken)
    {
        try
        {
            await Task.Delay(TimeSpan.FromMinutes(2), _o.TimeProvider, cancellationToken).ConfigureAwait(false);
            using var timer = new PeriodicTimer(DatabaseUpdateInterval, _o.TimeProvider);
            do
            {
                if (LoadConfigSafe().AutoUpdateDatabases && Feeds is not null)
                {
                    await UpdateDatabasesAsync(cancellationToken).ConfigureAwait(false);
                }
            }
            while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
        }
    }

    private async Task<DatabaseStatus> RunUpdateAsync()
    {
        try
        {
            var status = await Feeds!.UpdateAsync(_lifetime.Token).ConfigureAwait(false);
            var failed = status.Sources.Where(src => src.Status != "ok").ToList();
            Log?.Invoke($"Базы угроз: {status.LastStatus}"
                + (failed.Count == 0 ? string.Empty
                    : ". Не обновлены: " + string.Join("; ", failed.Select(src => $"{src.Name} — {src.Status}: {src.Message}"))));
            return status;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or HttpRequestException or OperationCanceledException)
        {
            Log?.Invoke($"Обновление баз не выполнено: {ex.Message}");
            return CurrentDatabaseStatus() with { LastStatus = $"Обновление не выполнено: {ex.Message}" };
        }
        finally
        {
            PublishStatus();
        }
    }

    private DatabaseStatus CurrentDatabaseStatus()
    {
        var status = Feeds?.ReadStatus() ?? new DatabaseStatus { LastStatus = "Базы угроз не подключены" };
        lock (_updateSync)
        {
            return _updateTask is { IsCompleted: false } ? status with { LastStatus = "Обновление баз выполняется…" } : status;
        }
    }

    private SentinelConfig LoadConfigSafe()
    {
        try
        {
            return ConfigStore.Load();
        }
        catch (Exception ex) when (ex is System.Text.Json.JsonException or IOException or UnauthorizedAccessException)
        {
            return new SentinelConfig();
        }
    }
}
