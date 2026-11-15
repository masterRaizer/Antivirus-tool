using System.Runtime.Versioning;
using System.Text.Json;

namespace Sentinel.Core.Audit.Config;

/// <summary>
/// Источник исключений встроенной защиты помимо реестра: действующие настройки Defender
/// (<c>MSFT_MpPreference</c>), которые включают и локальные исключения, и навязанные политикой.
/// </summary>
public interface IDefenderExclusionSource
{
    IReadOnlyList<DefenderExclusion> GetExclusions();
}

/// <summary>Разбор JSON со свойствами <c>MSFT_MpPreference</c> (<c>ExclusionPath</c>, <c>ExclusionProcess</c> и т. д.).</summary>
public static class DefenderExclusionJson
{
    public const string SourceKey = @"root\Microsoft\Windows\Defender:MSFT_MpPreference";

    private static readonly (string Property, DefenderExclusionKind Kind)[] Properties =
    [
        ("ExclusionPath", DefenderExclusionKind.Path),
        ("ExclusionProcess", DefenderExclusionKind.Process),
        ("ExclusionExtension", DefenderExclusionKind.Extension),
        ("ExclusionIpAddress", DefenderExclusionKind.IpAddress),
    ];

    /// <summary>
    /// Значение свойства — строка, массив строк или null. Записи вида «N/A: Must be an administrator…»
    /// Defender подставляет вместо исключений при нехватке прав; это не исключения, и они отбрасываются.
    /// </summary>
    public static IReadOnlyList<DefenderExclusion> Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return [];
        }

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(json);
        }
        catch (JsonException)
        {
            return [];
        }

        using (document)
        {
            var root = document.RootElement;
            if (root.ValueKind == JsonValueKind.Array && root.GetArrayLength() > 0)
            {
                root = root[0];
            }

            if (root.ValueKind != JsonValueKind.Object)
            {
                return [];
            }

            var result = new List<DefenderExclusion>();
            foreach (var (property, kind) in Properties)
            {
                if (!root.TryGetProperty(property, out var value))
                {
                    continue;
                }

                foreach (var item in Items(value))
                {
                    if (!string.IsNullOrWhiteSpace(item) && !item.StartsWith("N/A", StringComparison.OrdinalIgnoreCase))
                    {
                        result.Add(new DefenderExclusion(kind, item.Trim(), $"{SourceKey}.{property}"));
                    }
                }
            }

            return result;
        }
    }

    private static string?[] Items(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.String => [value.GetString()],
        JsonValueKind.Array => value.EnumerateArray().Where(e => e.ValueKind == JsonValueKind.String).Select(e => e.GetString()).ToArray(),
        _ => [],
    };
}

/// <summary>
/// Чтение исключений Defender из WMI: класс <c>MSFT_MpPreference</c> в <c>root\Microsoft\Windows\Defender</c>
/// запрашивается средствами CIM. Сбой запуска или нехватка прав дают пустой список: реестровый аудит остаётся.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsDefenderExclusionSource : IDefenderExclusionSource
{
    private const string Script =
        "$ErrorActionPreference='Stop';" +
        "Get-CimInstance -Namespace root\\Microsoft\\Windows\\Defender -ClassName MSFT_MpPreference |" +
        " Select-Object ExclusionPath,ExclusionProcess,ExclusionExtension,ExclusionIpAddress | ConvertTo-Json -Compress";

    private readonly TimeSpan _timeout;

    public WindowsDefenderExclusionSource(TimeSpan? timeout = null) => _timeout = timeout ?? TimeSpan.FromSeconds(60);

    public IReadOnlyList<DefenderExclusion> GetExclusions()
    {
        var powershell = Remediation.SystemTool.System32Path("WindowsPowerShell", "v1.0", "powershell.exe");
        var (code, output, _) = Remediation.SystemTool.Run(
            powershell, ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", Script], _timeout,
            outputEncoding: System.Text.Encoding.UTF8);
        return code == 0 ? DefenderExclusionJson.Parse(output) : [];
    }
}
