using System.Text;
using System.Text.Json;

namespace Sentinel.Core.Signatures;

/// <summary>
/// Правила в формате JSON. Файл содержит либо один объект правила, либо {"rules": [...]}.
/// <code>
/// {
///   "id": "SNT-MINER-0001", "name": "Miner_Stratum", "severity": "high", "category": "miner",
///   "description": "...", "tags": ["miner"],
///   "strings": [ { "id": "$a", "text": "stratum+tcp://", "nocase": true, "wide": true },
///                { "id": "$b", "hex": "4D 5A ?? 00" } ],
///   "condition": "any of them",
///   "sha256": [ "..." ]
/// }
/// </code>
/// Если "condition" не задан, используется "any of them" (при наличии строк).
/// </summary>
public static class JsonRuleParser
{
    private static readonly JsonDocumentOptions Options = new()
    {
        AllowTrailingCommas = true,
        CommentHandling = JsonCommentHandling.Skip,
        MaxDepth = 16,
    };

    public static IReadOnlyList<SignatureRule> Parse(string json, string sourceFile)
    {
        ArgumentNullException.ThrowIfNull(json);
        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(json, Options);
        }
        catch (JsonException ex)
        {
            throw new RuleFormatException($"Некорректный JSON: {ex.Message}", (int)(ex.LineNumber ?? 0) + 1);
        }

        using (doc)
        {
            var root = doc.RootElement;
            var rules = new List<SignatureRule>();
            if (root.ValueKind == JsonValueKind.Object && root.TryGetProperty("rules", out var arr))
            {
                if (arr.ValueKind != JsonValueKind.Array)
                {
                    throw new RuleFormatException("Свойство 'rules' должно быть массивом.");
                }

                var index = 0;
                foreach (var item in arr.EnumerateArray())
                {
                    rules.Add(ParseRule(item, sourceFile, index++));
                }
            }
            else if (root.ValueKind == JsonValueKind.Array)
            {
                var index = 0;
                foreach (var item in root.EnumerateArray())
                {
                    rules.Add(ParseRule(item, sourceFile, index++));
                }
            }
            else
            {
                rules.Add(ParseRule(root, sourceFile, 0));
            }

            return rules;
        }
    }

    private static SignatureRule ParseRule(JsonElement e, string sourceFile, int index)
    {
        if (e.ValueKind != JsonValueKind.Object)
        {
            throw new RuleFormatException($"Правило #{index}: ожидался объект.");
        }

        var name = RequiredString(e, "name", index);
        var id = OptionalString(e, "id") ?? name;
        var severity = OptionalString(e, "severity") is { } sv ? RuleFactory.ParseSeverity(sv, 0) : Severity.Medium;
        var category = OptionalString(e, "category") ?? "generic";
        var description = OptionalString(e, "description") ?? string.Empty;

        var tags = new List<string>();
        if (e.TryGetProperty("tags", out var tagsEl))
        {
            foreach (var t in ArrayOf(tagsEl, "tags", name))
            {
                tags.Add(t.GetString() ?? throw new RuleFormatException($"Правило {name}: тег должен быть строкой."));
            }
        }

        var sha = new HashSet<string>(StringComparer.Ordinal);
        if (e.TryGetProperty("sha256", out var shaEl))
        {
            foreach (var h in ArrayOf(shaEl, "sha256", name))
            {
                sha.Add(RuleFactory.NormalizeSha256(h.GetString() ?? string.Empty, 0));
            }
        }

        var patterns = new List<BytePattern>();
        var ids = new HashSet<string>(StringComparer.Ordinal);
        if (e.TryGetProperty("strings", out var stringsEl))
        {
            var n = 0;
            foreach (var s in ArrayOf(stringsEl, "strings", name))
            {
                if (s.ValueKind != JsonValueKind.Object)
                {
                    throw new RuleFormatException($"Правило {name}: элемент strings должен быть объектом.");
                }

                var pid = OptionalString(s, "id") ?? $"$s{n}";
                n++;
                if (!pid.StartsWith('$') || pid.Length < 2 || pid.EndsWith('*'))
                {
                    throw new RuleFormatException($"Правило {name}: некорректный идентификатор строки '{pid}'.");
                }

                if (!ids.Add(pid))
                {
                    throw new RuleFormatException($"Правило {name}: повторное определение строки {pid}.");
                }

                var hex = OptionalString(s, "hex");
                var text = OptionalString(s, "text");
                if ((hex is null) == (text is null))
                {
                    throw new RuleFormatException($"Правило {name}: строка {pid} должна иметь ровно одно из полей 'text' или 'hex'.");
                }

                if (hex is not null)
                {
                    patterns.Add(PatternBuilder.FromHex(pid, hex));
                }
                else
                {
                    patterns.AddRange(PatternBuilder.FromText(pid, Encoding.UTF8.GetBytes(text!), text!,
                        OptionalBool(s, "nocase"), OptionalBool(s, "ascii"), OptionalBool(s, "wide")));
                }
            }
        }

        Condition? condition = null;
        if (OptionalString(e, "condition") is { } condText)
        {
            condition = ConditionParser.Parse(condText);
        }
        else if (patterns.Count > 0)
        {
            condition = new OfCondition(1, null);
        }

        return RuleFactory.Build(id, name, description, severity, category, tags, patterns, sha, condition, sourceFile, 0);
    }

    private static JsonElement.ArrayEnumerator ArrayOf(JsonElement el, string prop, string rule) =>
        el.ValueKind == JsonValueKind.Array
            ? el.EnumerateArray()
            : throw new RuleFormatException($"Правило {rule}: '{prop}' должно быть массивом.");

    private static string RequiredString(JsonElement e, string prop, int index) =>
        OptionalString(e, prop) ?? throw new RuleFormatException($"Правило #{index}: отсутствует обязательное поле '{prop}'.");

    private static string? OptionalString(JsonElement e, string prop)
    {
        if (!e.TryGetProperty(prop, out var v) || v.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        return v.ValueKind == JsonValueKind.String
            ? v.GetString()
            : throw new RuleFormatException($"Поле '{prop}' должно быть строкой.");
    }

    private static bool OptionalBool(JsonElement e, string prop)
    {
        if (!e.TryGetProperty(prop, out var v))
        {
            return false;
        }

        return v.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            _ => throw new RuleFormatException($"Поле '{prop}' должно быть логическим."),
        };
    }
}
