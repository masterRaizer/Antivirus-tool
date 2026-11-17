using System.Buffers;
using System.Security.Cryptography;
using Sentinel.Core.Analysis;
using Sentinel.Core.Detection;
using Sentinel.Core.Hashing;
using Sentinel.Core.Pe;
using Sentinel.Core.Scoring;
using Sentinel.Core.ThreatIntel;
using Sentinel.Core.Signatures;
using Sentinel.Core.Trust;

namespace Sentinel.Core.Scanning;

public sealed class FileAnalyzerOptions
{
    /// <summary>
    /// Размер окна (первые байты файла), загружаемого в память для сигнатурного поиска. SHA-256 и энтропия
    /// всегда считаются потоком по всему файлу буфером 64 КБ, поэтому память не зависит от размера файла.
    /// </summary>
    public long MaxScanBytes { get; init; } = 16L * 1024 * 1024;

    /// <summary>Проверять подпись только у PE-файлов (неисполняемые файлы Authenticode не несут).</summary>
    public bool VerifySignatureOnlyForPe { get; init; } = true;

    /// <summary>
    /// Лимит сигнатурного поиска для приоритетной глубокой проверки (файлы, скрытые от встроенной
    /// защиты исключениями). Заметно выше обычного: такие файлы проверяются целиком.
    /// </summary>
    public long DeepMaxScanBytes { get; init; } = 128L * 1024 * 1024;

    /// <summary>Проверка пользовательского списка <c>allowed_exclusions.json</c> (−100 к баллу).</summary>
    public Func<string, bool>? IsUserAllowed { get; init; }

    /// <summary>Проверка SHA-256 по пользовательскому списку разрешённых хешей.</summary>
    public Func<string, bool>? IsHashAllowed { get; init; }

    /// <summary>Порог балла, с которого неподписанный файл отправляется на облачную проверку хеша.</summary>
    public int CloudLookupScore { get; init; } = 45;

    /// <summary>
    /// Файл из неработающей копии Windows на другом диске (<see cref="OfflineWindowsImage"/>): эвристика без сигнатуры
    /// и хеша для него не становится находкой. <c>null</c> — проверка по умолчанию.
    /// </summary>
    public Func<string, bool>? IsOfflineSystemImage { get; init; }
}

/// <summary>
/// Контекст приоритетной глубокой проверки: файл попал под исключение встроенной защиты Windows,
/// то есть штатный антивирус его не видит. Для таких файлов снимается обычный лимит размера,
/// подпись проверяется всегда, а неподписанный исполняемый код сам по себе считается подозрительным.
/// </summary>
public sealed record PriorityScanContext(string Reason)
{
    /// <summary>Расширения сценариев, исполняемых штатными интерпретаторами Windows.</summary>
    internal static readonly string[] ScriptExtensions =
    [
        ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".scr", ".com",
    ];
}

/// <summary>
/// Анализ одного файла: SHA-256, энтропия, PE-заголовки, подпись, белый список,
/// встроенный EICAR-детект, сигнатурные правила и эвристика упакованных неподписанных PE.
/// Анализатор только читает файл и никогда его не изменяет.
/// </summary>
public sealed class FileAnalyzer
{
    private const int StreamBufferSize = 64 * 1024;

    private readonly SignatureEngine _engine;
    private readonly ISignatureVerifier _verifier;
    private readonly IWhitelistProvider? _whitelist;
    private readonly FileAnalyzerOptions _options;
    private readonly IThreatHashLookup? _intel;
    private readonly ICloudReputationProvider? _cloud;

    public FileAnalyzer(SignatureEngine engine, ISignatureVerifier verifier, IWhitelistProvider? whitelist = null, FileAnalyzerOptions? options = null,
        IThreatHashLookup? threatIntel = null, ICloudReputationProvider? cloud = null)
    {
        _intel = threatIntel;
        _cloud = cloud;
        ArgumentNullException.ThrowIfNull(engine);
        ArgumentNullException.ThrowIfNull(verifier);
        _engine = engine;
        _verifier = verifier;
        _whitelist = whitelist;
        _options = options ?? new FileAnalyzerOptions();
    }

    /// <summary>Белый список, с которым работает анализатор (его же обязаны использовать карантин и нейтрализация).</summary>
    public IWhitelistProvider? Whitelist => _whitelist;

    public FileScanResult Analyze(string path) => Analyze(path, null, null);

    public FileScanResult Analyze(string path, PriorityScanContext? priority) => Analyze(path, priority, null);

    /// <summary>
    /// Анализ файла; при заданном <paramref name="priority"/> — приоритетная глубокая проверка
    /// (см. <see cref="PriorityScanContext"/>).
    /// </summary>
    public FileScanResult Analyze(string path, PriorityScanContext? priority, ScoreContext? context)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        try
        {
            return AnalyzeCore(Path.GetFullPath(path), priority, context ?? ScoreContext.None);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return new FileScanResult { Path = path, Verdict = Verdict.Error, Error = ex.Message };
        }
    }

    private FileScanResult AnalyzeCore(string path, PriorityScanContext? priority, ScoreContext context)
    {
        var maxScan = priority is null
            ? _options.MaxScanBytes
            : Math.Min(Math.Max(_options.MaxScanBytes, _options.DeepMaxScanBytes), Array.MaxLength);

        // Один проход потоком по всему файлу: SHA-256 (IncrementalHash), гистограмма для энтропии Шеннона
        // и копия ограниченного окна для сигнатурного поиска. Весь файл в память не загружается.
        byte[] content;
        string sha256;
        long size;
        bool truncated;
        double entropy;
        PeParseResult pe;
        using var stream = FileHasher.OpenShared(path);
        {
            size = stream.Length;
            truncated = size > maxScan;
            content = new byte[(int)Math.Min(size, maxScan)];
            var counts = new long[256];
            using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var buffer = ArrayPool<byte>.Shared.Rent(StreamBufferSize);
            try
            {
                var filled = 0;
                int read;
                while ((read = stream.Read(buffer, 0, StreamBufferSize)) > 0)
                {
                    sha.AppendData(buffer, 0, read);
                    for (var i = 0; i < read; i++)
                    {
                        counts[buffer[i]]++;
                    }

                    if (filled < content.Length)
                    {
                        var take = Math.Min(read, content.Length - filled);
                        Buffer.BlockCopy(buffer, 0, content, filled, take);
                        filled += take;
                    }
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }

            sha256 = Convert.ToHexString(sha.GetHashAndReset()).ToLowerInvariant();
            entropy = EntropyCalculator.FromHistogram(counts, size);
            pe = PeParser.Parse(stream);
        }

        SignatureVerificationResult? signature = null;
        if (pe.IsPe || !_options.VerifySignatureOnlyForPe || priority is not null)
        {
            signature = _verifier.Verify(path);
        }

        var whitelist = _whitelist?.Evaluate(path);
        var microsoftTrusted = whitelist is { IsWhitelisted: true };
        var signatureValid = signature is { IsValid: true };

        var detections = new List<Detection>();
        string? definitive = null;
        if (Eicar.IsEicar(content))
        {
            detections.Add(new Detection(Eicar.DetectionName, Severity.High, "test", DetectionSource.Builtin, null,
                "Стандартный антивирусный тестовый файл EICAR (безопасен).", [new PatternHit("eicar", 0)]));
            definitive = "EICAR";
        }

        foreach (var m in _engine.Scan(content, size, sha256, new ScanTarget(path, pe.IsPe)))
        {
            // Встроенный EICAR-детект уже сработал — не дублируем правило с тем же смыслом.
            if (m.Category == "test" && detections.Any(d => d.Source == DetectionSource.Builtin && d.Category == "test"))
            {
                continue;
            }

            detections.Add(new Detection(m.RuleName, m.Severity, m.Category, DetectionSource.Signature, m.RuleId,
                m.MatchedByHash ? $"{m.Description} (совпадение по SHA-256)" : m.Description, m.Hits));
            if (m.Severity >= Severity.Medium)
            {
                definitive ??= m.RuleName;
            }
        }

        if (_intel is not null && _intel.TryGetFamily(sha256, out var family)
            && !(definitive == "EICAR" && family is not null && family.StartsWith("EICAR", StringComparison.Ordinal)))
        {
            detections.Add(new Detection($"ThreatDB.{family ?? "Malware"}", Severity.Critical, "malware", DetectionSource.ThreatIntel, null,
                $"SHA-256 найден в базе известных угроз ({family ?? "семейство не указано"}).", []));
            definitive = $"ThreatDB.{family}";
        }

        ThreatScore? score = null;
        if (pe is { IsPe: true, Info: { } info })
        {
            var imports = signatureValid ? new HashSet<string>() : PeImportReader.ReadFunctionNames(stream, info);
            var input = new ScoringInput
            {
                Path = path,
                Pe = info,
                Entropy = entropy,
                SignatureValid = signatureValid,
                MicrosoftTrusted = microsoftTrusted,
                UserAllowed = (_options.IsUserAllowed?.Invoke(path) ?? false) || (_options.IsHashAllowed?.Invoke(sha256) ?? false),
                DefinitiveMatch = definitive,
                Imports = imports,
                Markers = FindMarkers(content, imports),
                DotNetSingleFileBundle = IsDotNetSingleFileBundle(content, size),
                PersistenceBound = context.PersistenceBound,
                ObfuscatedCommandLine = context.ObfuscatedCommandLine,
            };
            score = ThreatScoringEngine.Evaluate(input);

            // Облако: только хеш и только для неподписанных файлов с подозрительным баллом.
            if (_cloud is not null && !signatureValid && !microsoftTrusted && score.Value >= _options.CloudLookupScore && definitive is null)
            {
                var cloud = _cloud.Lookup(sha256);
                if (cloud.Reputation == CloudReputation.Malicious)
                {
                    score = ThreatScoringEngine.Evaluate(input with { CloudMalicious = $"{cloud.Source} {cloud.Detail}".Trim() });
                    detections.Add(new Detection($"Cloud.{cloud.Source}", Severity.Critical, "malware", DetectionSource.ThreatIntel, null,
                        $"Облачная репутация ({cloud.Source}): хеш признан вредоносным. {cloud.Detail}".Trim(), []));
                }
            }

            // Копия Windows на другом диске: подписи её каталогов живой системе не видны, импорты штатных компонентов
            // (AMSI, VirtualProtect, отладка) дают балл — без сигнатуры или хеша это не находка.
            var offlineImage = definitive is null && !signatureValid && detections.Count == 0
                && (_options.IsOfflineSystemImage ?? OfflineWindowsImage.Contains)(path);
            if (definitive is null && !offlineImage && score.Level is { } level && level >= Severity.Low)
            {
                detections.Add(new Detection("Heuristic.ThreatScore", level, "score", DetectionSource.Heuristic, null,
                    $"Балл угрозы {score.Value}/100: {score.Describe()}.", []));
            }
        }

        if (priority is not null && !signatureValid)
        {
            var isScript = PriorityScanContext.ScriptExtensions.Contains(Path.GetExtension(path), StringComparer.OrdinalIgnoreCase);
            if (pe.IsPe || isScript)
            {
                detections.Add(new Detection("Heuristic.DefenderExcludedExecutable", Severity.Medium, "evasion", DetectionSource.Heuristic, null,
                    $"{(pe.IsPe ? "Исполняемый PE-файл" : "Сценарий")} без действительной цифровой подписи скрыт от встроенной защиты Windows ({priority.Reason}).", []));
            }
        }

        var verdict = microsoftTrusted ? Verdict.Trusted : VerdictFrom(detections);

        return new FileScanResult
        {
            Path = path,
            Size = size,
            Sha256 = sha256,
            Entropy = entropy,
            Truncated = truncated,
            Pe = pe,
            Signature = signature,
            Whitelist = whitelist,
            Detections = detections,
            Verdict = verdict,
            PriorityReason = priority?.Reason,
            Score = score,
        };
    }

    /// <summary>
    /// Сигнатура бандла apphost .NET (SHA-256 строки «.net core bundle», bundle_marker.cpp в dotnet/runtime). Перед ней — 8 байт
    /// смещения заголовка бандла: у настоящего однофайлового приложения оно ненулевое и лежит внутри файла.
    /// </summary>
    private static readonly byte[] DotNetBundleSignature =
    [
        0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38, 0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32,
        0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae, 0x33, 0x18, 0xee, 0x3b, 0x2d, 0xce, 0x24, 0xb3, 0x6a, 0xae,
    ];

    internal static bool IsDotNetSingleFileBundle(ReadOnlySpan<byte> content, long fileSize)
    {
        var index = content.IndexOf(DotNetBundleSignature);
        if (index < 8)
        {
            return false;
        }

        var headerOffset = System.Buffers.Binary.BinaryPrimitives.ReadInt64LittleEndian(content[(index - 8)..]);
        return headerOffset > 0 && headerOffset < fileSize;
    }

    private static HashSet<string> FindMarkers(byte[] content, IReadOnlySet<string> imports)
    {
        var found = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        void Probe(string text)
        {
            if (ContainsText(content, text))
            {
                found.Add(text);
            }
        }

        if (imports.Contains("MiniDumpWriteDump"))
        {
            Probe("lsass");
            Probe("SeDebugPrivilege");
        }

        if (imports.Contains("VirtualProtect") || imports.Contains("VirtualProtectEx"))
        {
            Probe("AmsiScanBuffer");
            Probe("EtwEventWrite");
        }

        return found;
    }

    /// <summary>Поиск строки в содержимом в кодировках ASCII и UTF-16LE (без учёта регистра для ASCII-варианта).</summary>
    private static bool ContainsText(ReadOnlySpan<byte> content, string text)
    {
        if (content.IndexOf(System.Text.Encoding.ASCII.GetBytes(text)) >= 0
            || content.IndexOf(System.Text.Encoding.Unicode.GetBytes(text)) >= 0)
        {
            return true;
        }

        var lower = text.ToLowerInvariant();
        return !string.Equals(lower, text, StringComparison.Ordinal)
            && (content.IndexOf(System.Text.Encoding.ASCII.GetBytes(lower)) >= 0
                || content.IndexOf(System.Text.Encoding.Unicode.GetBytes(lower)) >= 0);
    }

    internal static Verdict VerdictFrom(IReadOnlyCollection<Detection> detections)
    {
        if (detections.Count == 0)
        {
            return Verdict.Clean;
        }

        var max = detections.Max(d => d.Severity);
        return max >= Severity.High ? Verdict.Malicious : max >= Severity.Low ? Verdict.Suspicious : Verdict.Clean;
    }
}

/// <summary>Сведения об использовании файла, которые повышают балл угрозы: автозагрузка и обфусцированная командная строка.</summary>
public sealed record ScoreContext(bool PersistenceBound = false, bool ObfuscatedCommandLine = false)
{
    public static ScoreContext None { get; } = new();
}
