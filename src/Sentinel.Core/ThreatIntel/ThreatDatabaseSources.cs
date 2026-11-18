namespace Sentinel.Core.ThreatIntel;

/// <summary>
/// Сбор записей для стартовой базы из локальных копий публичных репозиториев IOC (детерминированная офлайн-сборка
/// <c>data/threat_hashes.bin</c>): Neo23x0/signature-base (DRL 1.1), eset/malware-ioc (BSD-2-Clause), отчёты IOC
/// (Cisco-Talos/IOCs, pan-unit42/iocs, sophoslabs/IoCs), выгрузки MalwareBazaar и списки VirusShare.
/// </summary>
public static class ThreatDatabaseSources
{
    private static readonly string[] EsetExtensions = [".sha256", ".sha1", ".md5", ".txt", ".csv", ".ioc", ".adoc", ".md", ".json", ".misp", ".xml"];

    /// <summary>Текстовые файлы отчётов IOC; JSON/STIX пропускаются — те же хеши есть в текстовой копии, а строки там без контекста.</summary>
    private static readonly string[] ReportExtensions = [".txt", ".text", ".csv", ".md", ".ioc", ".sha256", ".sha1", ".md5"];

    /// <summary>Имена файлов, по которым семейство не понять: берётся имя каталога.</summary>
    private static readonly string[] GenericReportNames = ["readme", "iocs", "ioc", "samples", "hashes", "indicators", "index"];

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
                    ? ThreatFeedParsers.ParseSignatureBaseHashIocsAllKinds(text)
                    : ThreatFeedParsers.ParseHashListAllKinds(text, "SigBase." + Path.GetFileNameWithoutExtension(file));
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

                foreach (var e in ThreatFeedParsers.ParseHashListAllKinds(File.ReadAllText(file), family))
                {
                    yield return e;
                }
            }
        }
    }

    /// <summary>
    /// Репозиторий отчётов IOC (Talos, Unit 42, Sophos и подобные): все текстовые файлы, семейство — <paramref name="prefix"/>
    /// и имя отчёта. Строки с пометками легитимного файла пропускаются (<see cref="ThreatFeedParsers.IsBenignContext"/>);
    /// каталоги <c>.git</c> и точки повторной обработки (junction/symlink) не обходятся.
    /// </summary>
    public static IEnumerable<ThreatHashEntry> FromIocReports(string root, string prefix)
    {
        ArgumentException.ThrowIfNullOrEmpty(root);
        ArgumentException.ThrowIfNullOrEmpty(prefix);
        var options = new EnumerationOptions
        {
            RecurseSubdirectories = true,
            AttributesToSkip = FileAttributes.ReparsePoint,
            IgnoreInaccessible = true,
        };
        var files = Directory.EnumerateFiles(root, "*", options)
            .Where(f => ReportExtensions.Contains(Path.GetExtension(f), StringComparer.OrdinalIgnoreCase))
            .Where(f => !Path.GetRelativePath(root, f).Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                .Any(part => part.StartsWith('.')))
            .Order(StringComparer.Ordinal);
        foreach (var file in files)
        {
            foreach (var e in ThreatFeedParsers.ParseIocReportLines(File.ReadLines(file), $"{prefix}.{ReportName(file)}"))
            {
                yield return e;
            }
        }
    }

    private static string ReportName(string file)
    {
        var name = Path.GetFileNameWithoutExtension(file);
        if (name.Length < 3 || GenericReportNames.Contains(name, StringComparer.OrdinalIgnoreCase))
        {
            name = Path.GetFileName(Path.GetDirectoryName(file)) ?? name;
        }

        var clean = new string(name.Select(c => char.IsLetterOrDigit(c) || c is '-' or '_' or '.' ? c : '-').ToArray()).Trim('-');
        return clean.Length > 60 ? clean[..60] : clean.Length == 0 ? "report" : clean;
    }

    /// <summary>
    /// Полная выгрузка MalwareBazaar: zip (<c>full.csv</c> или <c>full_sha256.txt</c> внутри), CSV или TXT. Читается потоком —
    /// выгрузка содержит около миллиона записей.
    /// </summary>
    public static IEnumerable<ThreatHashEntry> FromMalwareBazaarExport(string path)
    {
        if (path.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
        {
            using var zip = System.IO.Compression.ZipFile.OpenRead(path);
            foreach (var entry in zip.Entries.Where(e => e.Length > 0).OrderBy(e => e.FullName, StringComparer.Ordinal))
            {
                using var reader = new StreamReader(entry.Open());
                foreach (var e in ParseMalwareBazaarText(reader, entry.FullName))
                {
                    yield return e;
                }
            }

            yield break;
        }

        using var file = new StreamReader(path);
        foreach (var e in ParseMalwareBazaarText(file, path))
        {
            yield return e;
        }
    }

    /// <summary>Каталог со списками VirusShare (<c>VirusShare_*.md5</c>, можно в zip).</summary>
    public static IEnumerable<ThreatHashEntry> FromVirusShare(string directory)
    {
        foreach (var file in Directory.EnumerateFiles(directory, "VirusShare_*").Order(StringComparer.Ordinal))
        {
            if (file.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
            {
                using var zip = System.IO.Compression.ZipFile.OpenRead(file);
                foreach (var entry in zip.Entries.Where(e => e.Length > 0))
                {
                    using var reader = new StreamReader(entry.Open());
                    foreach (var e in ThreatFeedParsers.ParseVirusShareList(reader))
                    {
                        yield return e;
                    }
                }

                continue;
            }

            using var text = new StreamReader(file);
            foreach (var e in ThreatFeedParsers.ParseVirusShareList(text))
            {
                yield return e;
            }
        }
    }

    private static IEnumerable<ThreatHashEntry> ParseMalwareBazaarText(TextReader reader, string name) =>
        name.EndsWith(".csv", StringComparison.OrdinalIgnoreCase)
            ? ThreatFeedParsers.ParseMalwareBazaarCsv(reader)
            : ParseLines(reader);

    private static IEnumerable<ThreatHashEntry> ParseLines(TextReader reader)
    {
        while (reader.ReadLine() is { } line)
        {
            if (line.Length > 0 && line[0] != '#' && ThreatFeedParsers.TryNormalizeSha256(line, out var hash))
            {
                yield return new ThreatHashEntry(hash, "MalwareBazaar");
            }
        }
    }

    /// <summary>Тестовая запись EICAR: безопасный стандартный образец для проверки работы базы.</summary>
    public static IEnumerable<ThreatHashEntry> Eicar() => [new ThreatHashEntry(ThreatFeedParsers.EicarSha256, "EICAR-Test-File")];
}
