using System.Globalization;
using System.Runtime.Versioning;
using System.Xml;
using System.Xml.Linq;
using Sentinel.Core.Audit.Config;

namespace Sentinel.Core.ThreatFamilies;

/// <summary>
/// Событие 5007 журнала <c>Microsoft-Windows-Windows Defender/Operational</c> («конфигурация изменена»), сведённое
/// к добавленному/удалённому исключению. У вредоносов семейства CAAService/techias оно появляется через секунды после
/// создания файла загрузчика.
/// </summary>
public sealed record DefenderExclusionChange(DateTime TimeUtc, DefenderExclusionKind Kind, string Value, bool Added);

/// <summary>Источник изменений исключений Защитника (журнал событий в Windows, заглушка в тестах).</summary>
public interface IDefenderEventSource
{
    IReadOnlyList<DefenderExclusionChange> GetExclusionChanges(TimeSpan lookback);
}

/// <summary>Разбор текстов «Old Value»/«New Value» события 5007.</summary>
public static class DefenderEventParser
{
    private static readonly (string Marker, DefenderExclusionKind Kind)[] Markers =
    [
        (@"\Exclusions\Paths\", DefenderExclusionKind.Path),
        (@"\Exclusions\Processes\", DefenderExclusionKind.Process),
        (@"\Exclusions\Extensions\", DefenderExclusionKind.Extension),
        (@"\Exclusions\IpAddresses\", DefenderExclusionKind.IpAddress),
    ];

    /// <summary>
    /// <c>HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\ProgramData\CAAService = 0x0</c> →
    /// (Path, <c>C:\ProgramData\CAAService</c>). Для «New Value» — добавление, для пустого нового и заполненного старого — удаление.
    /// </summary>
    public static DefenderExclusionChange? Parse(DateTime timeUtc, string? oldValue, string? newValue)
    {
        if (TryParseValue(newValue) is { } added)
        {
            return new DefenderExclusionChange(timeUtc, added.Kind, added.Value, Added: true);
        }

        return TryParseValue(oldValue) is { } removed
            ? new DefenderExclusionChange(timeUtc, removed.Kind, removed.Value, Added: false)
            : null;
    }

    private static (DefenderExclusionKind Kind, string Value)? TryParseValue(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        foreach (var (marker, kind) in Markers)
        {
            var idx = text.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            if (idx < 0)
            {
                continue;
            }

            var value = text[(idx + marker.Length)..];
            var eq = value.LastIndexOf(" = ", StringComparison.Ordinal);
            if (eq >= 0)
            {
                value = value[..eq];
            }

            value = value.Trim();
            return value.Length == 0 ? null : (kind, value);
        }

        return null;
    }

    /// <summary>Разбор вывода <c>wevtutil qe … /f:xml</c> (последовательность элементов &lt;Event&gt; без корня).</summary>
    public static IReadOnlyList<DefenderExclusionChange> ParseWevtutilXml(string? xml)
    {
        var list = new List<DefenderExclusionChange>();
        if (string.IsNullOrWhiteSpace(xml))
        {
            return list;
        }

        XElement root;
        try
        {
            root = XElement.Parse("<Events>" + xml + "</Events>", LoadOptions.None);
        }
        catch (XmlException)
        {
            return list;
        }

        foreach (var ev in root.Elements().Where(e => e.Name.LocalName == "Event"))
        {
            var system = ev.Elements().FirstOrDefault(e => e.Name.LocalName == "System");
            var eventId = system?.Elements().FirstOrDefault(e => e.Name.LocalName == "EventID")?.Value;
            if (eventId?.Trim() != "5007")
            {
                continue;
            }

            var timeText = system!.Elements().FirstOrDefault(e => e.Name.LocalName == "TimeCreated")?.Attribute("SystemTime")?.Value;
            if (!DateTime.TryParse(timeText, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var time))
            {
                continue;
            }

            var data = ev.Descendants().Where(e => e.Name.LocalName == "Data")
                .ToDictionary(e => e.Attribute("Name")?.Value ?? string.Empty, e => e.Value, StringComparer.OrdinalIgnoreCase);
            if (Parse(time, data.GetValueOrDefault("Old Value"), data.GetValueOrDefault("New Value")) is { } change)
            {
                list.Add(change);
            }
        }

        return list;
    }
}

/// <summary>Чтение событий 5007 через штатный <c>wevtutil.exe</c> из System32 (без поиска по PATH).</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsDefenderEventSource : IDefenderEventSource
{
    private const string Channel = "Microsoft-Windows-Windows Defender/Operational";

    public IReadOnlyList<DefenderExclusionChange> GetExclusionChanges(TimeSpan lookback)
    {
        var ms = (long)Math.Max(1, lookback.TotalMilliseconds);
        var query = $"*[System[(EventID=5007) and TimeCreated[timediff(@SystemTime) <= {ms.ToString(CultureInfo.InvariantCulture)}]]]";
        var wevtutil = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "wevtutil.exe");
        var (code, output, _) = Remediation.SystemTool.Run(wevtutil, ["qe", Channel, "/q:" + query, "/f:xml", "/rd:true", "/c:2000"],
            TimeSpan.FromSeconds(60), outputEncoding: System.Text.Encoding.UTF8);
        return code == 0 ? DefenderEventParser.ParseWevtutilXml(output) : [];
    }
}
