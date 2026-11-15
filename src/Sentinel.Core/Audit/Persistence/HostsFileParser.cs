using System.Net;

namespace Sentinel.Core.Audit.Persistence;

/// <summary>Одна содержательная запись файла hosts: IP-адрес и сопоставленное имя хоста.</summary>
public sealed record HostsEntry(string Address, string Host, bool IsLoopback)
{
    public int LineNumber { get; init; }
}

/// <summary>
/// Разбор файла <c>hosts</c>. Платформонезависим и тестируется на Linux.
/// Комментарии и пустые строки пропускаются; каждая запись «адрес имя[ имя2 ...]»
/// разворачивается в отдельные <see cref="HostsEntry"/>.
/// </summary>
public static class HostsFileParser
{
    /// <summary>Адрес относится к петле (127.0.0.0/8, ::1 или 0.0.0.0 как «заглушка»).</summary>
    public static bool IsLoopbackOrNull(string address)
    {
        if (string.Equals(address, "0.0.0.0", StringComparison.Ordinal))
        {
            return true;
        }

        if (!IPAddress.TryParse(address, out var ip))
        {
            return false;
        }

        if (IPAddress.IsLoopback(ip))
        {
            return true;
        }

        return ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any);
    }

    public static IReadOnlyList<HostsEntry> Parse(string content)
    {
        ArgumentNullException.ThrowIfNull(content);
        var entries = new List<HostsEntry>();
        var lines = content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i].Trim();
            if (line.Length == 0 || line[0] == '#')
            {
                continue;
            }

            var hash = line.IndexOf('#', StringComparison.Ordinal);
            if (hash >= 0)
            {
                line = line[..hash].Trim();
            }

            var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2)
            {
                continue;
            }

            var address = parts[0];
            var loopback = IsLoopbackOrNull(address);
            for (var j = 1; j < parts.Length; j++)
            {
                entries.Add(new HostsEntry(address, parts[j], loopback) { LineNumber = i + 1 });
            }
        }

        return entries;
    }
}

/// <summary>
/// Блокировка телеметрии Microsoft в hosts — осознанная настройка приватности, а не признак заражения:
/// такие записи получают уровень <c>Info</c> и никогда не удаляются автоматически.
/// </summary>
public static class HostsTelemetryList
{
    private static readonly string[] Suffixes =
    [
        ".events.data.microsoft.com", ".telemetry.microsoft.com", ".aria.microsoft.com", ".vortex.data.microsoft.com",
    ];

    private static readonly string[] Exact =
    [
        "vortex.data.microsoft.com", "oca.telemetry.microsoft.com", "sqm.telemetry.microsoft.com",
        "settings-win.data.microsoft.com", "compatexchange.cloudapp.net", "telemetry.microsoft.com",
        "events.data.microsoft.com", "aria.microsoft.com",
    ];

    public static bool IsTelemetryHost(string host)
    {
        ArgumentNullException.ThrowIfNull(host);
        var h = host.Trim().TrimEnd('.').ToLowerInvariant();
        return Exact.Contains(h, StringComparer.Ordinal)
            || Suffixes.Any(s => h.EndsWith(s, StringComparison.Ordinal))
            || h.StartsWith("nw-umwatson.", StringComparison.Ordinal);
    }
}
