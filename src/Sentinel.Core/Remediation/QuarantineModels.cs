namespace Sentinel.Core.Remediation;

public sealed class QuarantineOptions
{
    public const string ManifestFileName = "quarantine_manifest.json";

    /// <summary>Каталог карантина (создаётся при первом обращении с ограниченными правами доступа).</summary>
    public required string QuarantineDirectory { get; init; }

    /// <summary>
    /// Каталог по умолчанию: <c>%ProgramData%\Sentinel\Quarantine</c> в Windows,
    /// <c>~/.local/share/Sentinel/Quarantine</c> на прочих ОС.
    /// </summary>
    public static QuarantineOptions CreateDefault()
    {
        var root = Environment.GetFolderPath(OperatingSystem.IsWindows()
            ? Environment.SpecialFolder.CommonApplicationData
            : Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrEmpty(root))
        {
            root = Path.GetTempPath();
        }

        return new QuarantineOptions { QuarantineDirectory = Path.Combine(root, "Sentinel", "Quarantine") };
    }
}

public enum QuarantineState
{
    /// <summary>Файл изолирован и хранится в карантине.</summary>
    Quarantined,

    /// <summary>Файл возвращён на исходное место; запись сохранена для истории.</summary>
    Restored,

    /// <summary>Контейнер удалён пользователем навсегда; запись сохранена для истории.</summary>
    Deleted,
}

/// <summary>Запись <c>quarantine_manifest.json</c> — всё необходимое для полного восстановления файла.</summary>
public sealed record QuarantineRecord
{
    public required string Id { get; init; }
    public required string OriginalPath { get; init; }

    /// <summary>Атрибуты файла до изоляции (до снятия ReadOnly/Hidden/System).</summary>
    public FileAttributes OriginalAttributes { get; init; }

    /// <summary>Права доступа Unix до изоляции (вне Windows), иначе <c>null</c>.</summary>
    public UnixFileMode? OriginalUnixMode { get; init; }

    public DateTime OriginalLastWriteTimeUtc { get; init; }
    public long Size { get; init; }

    /// <summary>SHA-256 исходного (не преобразованного) содержимого, hex в нижнем регистре.</summary>
    public required string Sha256 { get; init; }

    public DateTime QuarantinedAtUtc { get; init; }
    public required string Reason { get; init; }

    /// <summary>Ключ обратимого XOR-преобразования (Base64).</summary>
    public required string XorKey { get; init; }

    /// <summary>Имя файла-контейнера внутри каталога карантина.</summary>
    public required string StoredFileName { get; init; }

    public QuarantineState State { get; init; } = QuarantineState.Quarantined;
    public DateTime? RestoredAtUtc { get; init; }
}

public enum QuarantineStatus
{
    Quarantined,

    /// <summary>Предпросмотр (dry-run): файл был бы изолирован, изменений нет.</summary>
    WouldQuarantine,

    /// <summary>Действие запрещено белым списком (подписанный системный файл Windows).</summary>
    BlockedByWhitelist,
    NotFound,
    Failed,
}

public sealed record QuarantineResult(QuarantineStatus Status, string Message, QuarantineRecord? Record = null)
{
    public bool Success => Status == QuarantineStatus.Quarantined;
}

public enum RestoreStatus
{
    Restored,
    NotFound,
    AlreadyRestored,

    /// <summary>На исходном месте уже есть файл; перезапись не выполняется без явного разрешения.</summary>
    TargetExists,

    /// <summary>SHA-256 восстановленных данных не совпал с манифестом — контейнер повреждён, файл не возвращён.</summary>
    HashMismatch,
    Failed,
}

public sealed record RestoreResult(RestoreStatus Status, string Message, QuarantineRecord? Record = null)
{
    public bool Success => Status == RestoreStatus.Restored;
}
