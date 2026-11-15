using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using Sentinel.Core.Ipc;
using Sentinel.Core.Reporting;

namespace Sentinel.Core.Runtime;

/// <summary>История отчётов: каждый завершённый прогон сохраняется как <c>Reports\&lt;id&gt;.json</c>.</summary>
public sealed partial class ReportStore
{
    private readonly string _directory;

    public ReportStore(string directory)
    {
        ArgumentException.ThrowIfNullOrEmpty(directory);
        _directory = Path.GetFullPath(directory);
    }

    public string Directory => _directory;

    /// <summary>Сохраняет отчёт и возвращает его идентификатор.</summary>
    public string Save(SentinelReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        var id = report.StartedAtUtc.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture) + "-" + Guid.NewGuid().ToString("N")[..6];
        ReportGenerator.WriteJson(report, PathOf(id));
        return id;
    }

    /// <summary>Сводки отчётов, новые — первыми. Повреждённые файлы пропускаются.</summary>
    public IReadOnlyList<ReportSummary> List(int limit = 200)
    {
        if (!System.IO.Directory.Exists(_directory))
        {
            return [];
        }

        var summaries = new List<ReportSummary>();
        foreach (var file in System.IO.Directory.EnumerateFiles(_directory, "*.json").OrderByDescending(Path.GetFileName, StringComparer.Ordinal).Take(limit))
        {
            var id = Path.GetFileNameWithoutExtension(file);
            if (!IdPattern().IsMatch(id))
            {
                continue;
            }

            try
            {
                var r = ReportGenerator.FromJson(File.ReadAllText(file));
                summaries.Add(new ReportSummary(id, r.StartedAtUtc, r.Command, r.Mode, r.Duration.TotalSeconds, r.TotalChecked, r.Found, r.Quarantined));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
            {
            }
        }

        return summaries;
    }

    public SentinelReport Load(string id) => ReportGenerator.FromJson(File.ReadAllText(Locate(id)));

    /// <summary>Отчёт в виде самодостаточного HTML или JSON.</summary>
    public ReportExport Export(string id, ReportFormat format)
    {
        var json = File.ReadAllText(Locate(id));
        return format == ReportFormat.Json
            ? new ReportExport($"sentinel-report-{id}.json", json)
            : new ReportExport($"sentinel-report-{id}.html", ReportGenerator.ToHtml(ReportGenerator.FromJson(json)));
    }

    private string Locate(string id)
    {
        // Идентификатор приходит по IPC от процесса пользователя: только строгий формат, никаких путей.
        if (string.IsNullOrEmpty(id) || !IdPattern().IsMatch(id))
        {
            throw new ArgumentException("Недопустимый идентификатор отчёта.", nameof(id));
        }

        var path = PathOf(id);
        return File.Exists(path) ? path : throw new KeyNotFoundException($"Отчёт '{id}' не найден.");
    }

    private string PathOf(string id) => Path.Combine(_directory, id + ".json");

    [GeneratedRegex("^[A-Za-z0-9-]{1,64}$", RegexOptions.CultureInvariant)]
    private static partial Regex IdPattern();
}
