namespace Sentinel.Core.ThreatIntel;

/// <summary>
/// Сбор записей для стартовой базы из локальных копий публичных репозиториев IOC (детерминированная офлайн-сборка
/// <c>data/threat_hashes.bin</c>): Neo23x0/signature-base (DRL 1.1) и eset/malware-ioc (BSD-2-Clause).
/// </summary>
public static class ThreatDatabaseSources
{
    private static readonly string[] EsetExtensions = [".sha256", ".txt", ".csv", ".ioc", ".adoc", ".md", ".json", ".misp", ".xml"];

    /// <summary><c>iocs/*.txt</c> (в т.ч. <c>hash-iocs.txt</c>) и мета-хеши правил <c>yara/*.yar</c>.</summary>
    public static IEnumerable<ThreatHashEntry> FromSignatureBase(string root)
    {
        var iocs = Path.Combine(root, "iocs");
        if (Directory.Exists(iocs))
        {
            foreach (var file in Directory.EnumerateFiles(iocs, "*.txt").Order(StringComparer.Ordinal))
            {
                var text = File.ReadAllText(file);
                var entries = Path.GetFileName(file).Equals("hash-iocs.txt", StringComparison.OrdinalIgnoreCase)
                    ? ThreatFeedParsers.ParseSignatureBaseHashIocs(text)
                    : ThreatFeedParsers.ParseHashList(text, "SigBase." + Path.GetFileNameWithoutExtension(file));
                foreach (var e in entries)
                {
                    yield return e;
                }
            }
        }

        var yara = Path.Combine(root, "yara");
        if (Directory.Exists(yara))
        {
            foreach (var file in Directory.EnumerateFiles(yara, "*.yar", SearchOption.AllDirectories).Order(StringComparer.Ordinal))
            {
                foreach (var e in ThreatFeedParsers.ParseYaraMetaHashes(File.ReadAllText(file), "SigBase." + Path.GetFileNameWithoutExtension(file)))
                {
                    yield return e;
                }
            }
        }
    }

    /// <summary>Каталоги семейств ESET: <c>samples.sha256</c>, README и файлы IOC; семейство — имя каталога верхнего уровня.</summary>
    public static IEnumerable<ThreatHashEntry> FromEset(string root)
    {
        foreach (var dir in Directory.EnumerateDirectories(root).Where(d => !Path.GetFileName(d).StartsWith('.')).Order(StringComparer.Ordinal))
        {
            var family = "ESET." + Path.GetFileName(dir);
            foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal))
            {
                if (!EsetExtensions.Contains(Path.GetExtension(file), StringComparer.OrdinalIgnoreCase))
                {
                    continue;
                }

                foreach (var e in ThreatFeedParsers.ParseHashList(File.ReadAllText(file), family))
                {
                    yield return e;
                }
            }
        }
    }

    /// <summary>Тестовая запись EICAR: безопасный стандартный образец для проверки работы базы.</summary>
    public static IEnumerable<ThreatHashEntry> Eicar() => [new ThreatHashEntry(ThreatFeedParsers.EicarSha256, "EICAR-Test-File")];
}
