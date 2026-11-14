using System.Security.Cryptography;
using Sentinel.Core.Analysis;
using Sentinel.Core.Detection;
using Sentinel.Core.Hashing;
using Sentinel.Core.Pe;
using Sentinel.Core.Signatures;
using Sentinel.Core.Trust;

namespace Sentinel.Core.Scanning;

public sealed class FileAnalyzerOptions
{
    /// <summary>Максимум байт, загружаемых для сигнатурного поиска. Хеш всегда считается по всему файлу.</summary>
    public long MaxScanBytes { get; init; } = 64L * 1024 * 1024;

    /// <summary>Проверять подпись только у PE-файлов (неисполняемые файлы Authenticode не несут).</summary>
    public bool VerifySignatureOnlyForPe { get; init; } = true;
}

/// <summary>
/// Анализ одного файла: SHA-256, энтропия, PE-заголовки, подпись, белый список,
/// встроенный EICAR-детект, сигнатурные правила и эвристика упакованных неподписанных PE.
/// Анализатор только читает файл и никогда его не изменяет.
/// </summary>
public sealed class FileAnalyzer
{
    private readonly SignatureEngine _engine;
    private readonly ISignatureVerifier _verifier;
    private readonly IWhitelistProvider? _whitelist;
    private readonly FileAnalyzerOptions _options;

    public FileAnalyzer(SignatureEngine engine, ISignatureVerifier verifier, IWhitelistProvider? whitelist = null, FileAnalyzerOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(engine);
        ArgumentNullException.ThrowIfNull(verifier);
        _engine = engine;
        _verifier = verifier;
        _whitelist = whitelist;
        _options = options ?? new FileAnalyzerOptions();
    }

    public FileScanResult Analyze(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        try
        {
            return AnalyzeCore(Path.GetFullPath(path));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return new FileScanResult { Path = path, Verdict = Verdict.Error, Error = ex.Message };
        }
    }

    private FileScanResult AnalyzeCore(string path)
    {
        byte[] content;
        string sha256;
        long size;
        bool truncated;
        using (var stream = FileHasher.OpenShared(path))
        {
            size = stream.Length;
            truncated = size > _options.MaxScanBytes;
            var toRead = (int)Math.Min(size, _options.MaxScanBytes);
            content = new byte[toRead];
            stream.ReadExactly(content);
            if (truncated)
            {
                using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                sha.AppendData(content);
                var buffer = new byte[1 << 16];
                int read;
                while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    sha.AppendData(buffer, 0, read);
                }

                sha256 = Convert.ToHexString(sha.GetHashAndReset()).ToLowerInvariant();
            }
            else
            {
                sha256 = FileHasher.ComputeSha256(content);
            }
        }

        var entropy = EntropyCalculator.Calculate(content);
        PeParseResult pe;
        if (truncated)
        {
            using var s = FileHasher.OpenShared(path);
            pe = PeParser.Parse(s);
        }
        else
        {
            using var ms = new MemoryStream(content, writable: false);
            pe = PeParser.Parse(ms);
        }

        SignatureVerificationResult? signature = null;
        if (pe.IsPe || !_options.VerifySignatureOnlyForPe)
        {
            signature = _verifier.Verify(path);
        }

        var whitelist = _whitelist?.Evaluate(path);

        var detections = new List<Detection>();
        if (Eicar.IsEicar(content))
        {
            detections.Add(new Detection(Eicar.DetectionName, Severity.High, "test", DetectionSource.Builtin, null,
                "Стандартный антивирусный тестовый файл EICAR (безопасен).", [new PatternHit("eicar", 0)]));
        }

        foreach (var m in _engine.Scan(content, size, sha256))
        {
            // Встроенный EICAR-детект уже сработал — не дублируем правило с тем же смыслом.
            if (m.Category == "test" && detections.Any(d => d.Source == DetectionSource.Builtin && d.Category == "test"))
            {
                continue;
            }

            detections.Add(new Detection(m.RuleName, m.Severity, m.Category, DetectionSource.Signature, m.RuleId,
                m.MatchedByHash ? $"{m.Description} (совпадение по SHA-256)" : m.Description, m.Hits));
        }

        if (pe is { IsPe: true, Info: { } info } && signature is not { IsValid: true })
        {
            var packed = info.Sections.FirstOrDefault(s => s.IsExecutable && s.Entropy >= EntropyCalculator.HighEntropyThreshold);
            if (packed is not null)
            {
                detections.Add(new Detection("Heuristic.PackedUnsignedPE", Severity.Medium, "packer", DetectionSource.Heuristic, null,
                    $"Неподписанный PE с упакованной исполняемой секцией '{packed.Name}' (энтропия {packed.Entropy:F2}).", []));
            }
        }

        var verdict = whitelist is { IsWhitelisted: true } ? Verdict.Trusted : VerdictFrom(detections);

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
        };
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
