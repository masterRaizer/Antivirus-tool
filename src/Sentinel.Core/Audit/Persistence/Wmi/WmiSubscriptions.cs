using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text.Json;

namespace Sentinel.Core.Audit.Persistence.Wmi;

/// <summary>Потребитель событий WMI (CommandLineEventConsumer / ActiveScriptEventConsumer).</summary>
public sealed record WmiConsumer(
    string Name,
    string ConsumerType,
    string? ExecutablePath,
    string? CommandLineTemplate,
    string? ScriptText);

/// <summary>Фильтр событий WMI (__EventFilter): имя, запрос и пространство имён.</summary>
public sealed record WmiFilter(string Name, string? Query, string? QueryLanguage);

/// <summary>Снимок подписок WMI: фильтры и потребители.</summary>
public sealed record WmiSubscriptionSnapshot(
    IReadOnlyList<WmiFilter> Filters,
    IReadOnlyList<WmiConsumer> Consumers);

/// <summary>Поставщик постоянных подписок WMI.</summary>
public interface IWmiSubscriptionProvider
{
    WmiSubscriptionSnapshot GetSubscriptions();
}

/// <summary>
/// Разбор JSON, полученного от <c>Get-CimInstance ... | ConvertTo-Json</c>.
/// Вынесен отдельно, чтобы логика анализа подписок тестировалась на Linux без WMI.
/// Принимает как одиночный объект, так и массив (поведение ConvertTo-Json по умолчанию).
/// </summary>
public static class WmiSubscriptionJsonParser
{
    public static IReadOnlyList<WmiConsumer> ParseConsumers(string? consumersJson)
    {
        var list = new List<WmiConsumer>();
        foreach (var el in EnumerateObjects(consumersJson))
        {
            var type = GetString(el, "__CLASS") ?? GetString(el, "ConsumerType") ?? "EventConsumer";
            list.Add(new WmiConsumer(
                GetString(el, "Name") ?? "<без имени>",
                type,
                GetString(el, "ExecutablePath"),
                GetString(el, "CommandLineTemplate"),
                GetString(el, "ScriptText")));
        }

        return list;
    }

    public static IReadOnlyList<WmiFilter> ParseFilters(string? filtersJson)
    {
        var list = new List<WmiFilter>();
        foreach (var el in EnumerateObjects(filtersJson))
        {
            list.Add(new WmiFilter(
                GetString(el, "Name") ?? "<без имени>",
                GetString(el, "Query"),
                GetString(el, "QueryLanguage")));
        }

        return list;
    }

    private static IEnumerable<JsonElement> EnumerateObjects(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            yield break;
        }

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(json);
        }
        catch (JsonException)
        {
            yield break;
        }

        using (doc)
        {
            if (doc.RootElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in doc.RootElement.EnumerateArray())
                {
                    if (item.ValueKind == JsonValueKind.Object)
                    {
                        yield return item.Clone();
                    }
                }
            }
            else if (doc.RootElement.ValueKind == JsonValueKind.Object)
            {
                yield return doc.RootElement.Clone();
            }
        }
    }

    private static string? GetString(JsonElement el, string name)
    {
        if (!el.TryGetProperty(name, out var prop) || prop.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        return prop.ValueKind == JsonValueKind.String ? prop.GetString() : prop.ToString();
    }
}

/// <summary>
/// Windows-провайдер подписок WMI: запрашивает root/subscription через PowerShell CIM
/// и разбирает JSON. Реальный системный механизм (без сторонних пакетов).
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsWmiSubscriptionProvider : IWmiSubscriptionProvider
{
    private readonly TimeSpan _timeout;

    public WindowsWmiSubscriptionProvider(TimeSpan? timeout = null) => _timeout = timeout ?? TimeSpan.FromSeconds(30);

    public WmiSubscriptionSnapshot GetSubscriptions()
    {
        var consumers = WmiSubscriptionJsonParser.ParseConsumers(
            Query("Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue | Select-Object Name,__CLASS,ExecutablePath,CommandLineTemplate,ScriptText | ConvertTo-Json -Depth 3 -Compress"));
        var filters = WmiSubscriptionJsonParser.ParseFilters(
            Query("Get-CimInstance -Namespace root/subscription -ClassName __EventFilter -ErrorAction SilentlyContinue | Select-Object Name,Query,QueryLanguage | ConvertTo-Json -Depth 3 -Compress"));
        return new WmiSubscriptionSnapshot(filters, consumers);
    }

    private string? Query(string script)
    {
        try
        {
            using var proc = new System.Diagnostics.Process
            {
                StartInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                },
            };
            proc.StartInfo.ArgumentList.Add("-NoProfile");
            proc.StartInfo.ArgumentList.Add("-NonInteractive");
            proc.StartInfo.ArgumentList.Add("-Command");
            proc.StartInfo.ArgumentList.Add(script);

            if (!proc.Start())
            {
                return null;
            }

            var output = proc.StandardOutput.ReadToEnd();
            if (!proc.WaitForExit((int)_timeout.TotalMilliseconds))
            {
                try
                {
                    proc.Kill(entireProcessTree: true);
                }
                catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
                {
                    // процесс уже завершился
                }

                return null;
            }

            return output;
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            return null;
        }
    }
}
