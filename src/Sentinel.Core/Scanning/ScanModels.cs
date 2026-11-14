using Sentinel.Core.Pe;
using Sentinel.Core.Signatures;
using Sentinel.Core.Trust;

namespace Sentinel.Core.Scanning;

public enum Verdict
{
    Clean,
    Suspicious,
    Malicious,
    /// <summary>Доверенный системный файл из белого списка — любые действия над ним запрещены.</summary>
    Trusted,
    Error,
}

public enum DetectionSource
{
    Builtin,
    Signature,
    Heuristic,
}

public sealed record Detection(
    string Name,
    Severity Severity,
    string Category,
    DetectionSource Source,
    string? RuleId,
    string Description,
    IReadOnlyList<PatternHit> Hits);

public sealed record FileScanResult
{
    public required string Path { get; init; }
    public long Size { get; init; }
    public string? Sha256 { get; init; }
    public double Entropy { get; init; }

    /// <summary>Сканировано меньше, чем размер файла (превышен лимит).</summary>
    public bool Truncated { get; init; }

    public PeParseResult? Pe { get; init; }
    public SignatureVerificationResult? Signature { get; init; }
    public WhitelistDecision? Whitelist { get; init; }
    public IReadOnlyList<Detection> Detections { get; init; } = [];
    public Verdict Verdict { get; init; }
    public string? Error { get; init; }
}
