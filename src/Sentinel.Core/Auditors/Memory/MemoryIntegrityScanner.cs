using System.Buffers;
using System.Buffers.Binary;
using Sentinel.Core.Audit;
using Sentinel.Core.Detection;
using Sentinel.Core.Protection;
using Sentinel.Core.Scoring;
using Sentinel.Core.Signatures;
using Sentinel.Core.Trust;

namespace Sentinel.Core.Auditors.Memory;

/// <summary>Лимиты и параметры потокового аудита памяти.</summary>
public sealed class MemoryScanOptions
{
    /// <summary>Размер буфера одного чтения: строго 64 КБ.</summary>
    public const int ChunkBytes = 64 * 1024;

    /// <summary>Перекрытие соседних окон, чтобы сигнатура на границе чанков не разрезалась.</summary>
    public int OverlapBytes { get; init; } = 4 * 1024;

    /// <summary>Сколько байт читать из одного региона (начало региона — там заголовок и распакованный код).</summary>
    public long MaxBytesPerRegion { get; init; } = 4L * 1024 * 1024;

    /// <summary>Общий бюджет чтения на процесс (защита от задержек на JIT-процессах с сотнями RWX-регионов).</summary>
    public long MaxBytesPerProcess { get; init; } = 16L * 1024 * 1024;

    /// <summary>Проверка подписи для <see cref="CriticalProcessGuard"/>; <c>null</c> — решение по имени и каталогу.</summary>
    public ISignatureVerifier? Verifier { get; init; }
}

public enum MemoryAnomalyKind
{
    /// <summary><c>MEM-REFLECTIVE-PE</c>: PE-образ в приватной исполняемой памяти.</summary>
    ReflectivePe,

    /// <summary><c>MEM-YARA-MATCH</c>: сигнатура/EICAR/строки майнера в исполняемой памяти.</summary>
    SignatureMatch,

    /// <summary><c>MEM-RWX-IMAGE-PATCH</c>: страницы образа переведены в RWX.</summary>
    ImagePatch,
}

/// <summary>Одна аномалия памяти: регион, смещение и подробность (правило, тип машины PE).</summary>
public sealed record MemoryAnomaly(
    MemoryAnomalyKind Kind,
    nint RegionBase,
    long RegionSize,
    long Offset,
    uint Protect,
    uint Type,
    Severity Severity,
    string Detail)
{
    public string Id => Kind switch
    {
        MemoryAnomalyKind.ReflectivePe => "MEM-REFLECTIVE-PE",
        MemoryAnomalyKind.SignatureMatch => "MEM-YARA-MATCH",
        _ => "MEM-RWX-IMAGE-PATCH",
    };

    public string Address => $"0x{(long)RegionBase + Offset:X}";
}

/// <summary>Итог аудита памяти одного процесса.</summary>
public sealed record MemoryScanResult(
    int ProcessId,
    string? SkipReason,
    int RegionsTotal,
    int RegionsInspected,
    int PrivateWriteExecuteRegions,
    long BytesRead,
    bool BudgetExhausted,
    IReadOnlyList<MemoryAnomaly> Anomalies,
    ThreatScore Score)
{
    public bool Skipped => SkipReason is not null;

    public bool HasAnomalies => Anomalies.Count > 0;

    public static MemoryScanResult Skip(int pid, string reason) => new(pid, reason, 0, 0, 0, 0, false, [], ThreatScore.Zero);

    /// <summary>Находки аудита (по одной на вид аномалии): для <c>ProcessAuditor</c> и диспетчера.</summary>
    public IReadOnlyList<AuditFinding> ToFindings(string? processName, string? executablePath)
    {
        var findings = new List<AuditFinding>();
        foreach (var group in Anomalies.GroupBy(a => a.Kind))
        {
            var first = group.First();
            var details = string.Join("; ", group.Select(a => $"{a.Detail} @ {a.Address}").Distinct().Take(5));
            var (title, description) = group.Key switch
            {
                MemoryAnomalyKind.ReflectivePe => ("PE-образ в приватной исполняемой памяти",
                    $"В памяти процесса '{processName}' найден PE-заголовок (MZ/PE) в регионе MEM_PRIVATE с правом исполнения, не подкреплённом файлом на диске, — признак рефлективной загрузки или внедрения: {details}."),
                MemoryAnomalyKind.SignatureMatch => ("Сигнатура в исполняемой памяти процесса",
                    $"В исполняемой памяти процесса '{processName}' сработали правила обнаружения: {details}."),
                _ => ("Страницы образа переведены в запись+исполнение",
                    $"У загруженного образа в процессе '{processName}' есть страницы PAGE_EXECUTE_READWRITE — признак патча кода или хука: {details}."),
            };
            findings.Add(AuditFinding.Create(first.Id, group.Max(a => a.Severity), title, description,
                Evidence.Of("pid", ProcessId),
                Evidence.Of("path", executablePath),
                Evidence.Of("address", first.Address),
                Evidence.Of("regions", group.Count()),
                Evidence.Of("score", Score.Value)));
        }

        return findings;
    }
}

/// <summary>
/// Потоковый аудит целостности памяти процесса. Первым шагом — <see cref="CriticalProcessGuard"/>: защищённые процессы ОС и
/// сам Sentinel не открываются вовсе. Затем отбираются только регионы <c>MEM_COMMIT</c> без <c>PAGE_GUARD</c>/<c>PAGE_NOACCESS</c>:
/// приватные с RWX/WCX (текущая защита или защита при выделении) и образы, переведённые в RWX. Каждый регион читается
/// окнами по 64 КБ (буфер из <see cref="ArrayPool{T}"/>) с перекрытием 4 КБ, в пределах бюджета на регион и на процесс.
/// Ищутся PE-заголовок (<c>MEM-REFLECTIVE-PE</c>), EICAR и сигнатурные правила (<c>MEM-YARA-MATCH</c>). Сам по себе RWX-регион
/// (JIT .NET, браузеры, PowerShell) не является находкой и баллов не даёт.
/// </summary>
public sealed class MemoryIntegrityScanner
{
    private const int PageSize = 4096;

    private readonly IMemoryReader _reader;
    private readonly SignatureEngine? _engine;
    private readonly MemoryScanOptions _options;

    public MemoryIntegrityScanner(IMemoryReader reader, SignatureEngine? engine = null, MemoryScanOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(reader);
        _reader = reader;
        _engine = engine;
        _options = options ?? new MemoryScanOptions();
        ArgumentOutOfRangeException.ThrowIfNegative(_options.OverlapBytes);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(_options.OverlapBytes, MemoryScanOptions.ChunkBytes);
    }

    /// <summary>Отбор регионов для чтения (открыт для тестов и диагностики).</summary>
    public static bool IsCandidate(MemoryRegionInfo region) =>
        region.IsCommitted && !region.IsUnreadable
        && ((region.IsPrivate && (region.IsWriteExecute || region.WasAllocatedWriteExecute))
            || (region.IsImage && (region.Protect & MemoryConstants.PAGE_EXECUTE_READWRITE) != 0));

    public MemoryScanResult Scan(int processId, string? processName, string? executablePath)
    {
        // Жёсткий предохранитель: до обращения к IMemoryReader (и, значит, до OpenProcess).
        if (processId == Environment.ProcessId)
        {
            return MemoryScanResult.Skip(processId, "Собственный процесс Sentinel.");
        }

        if (CriticalProcessGuard.IsProtectedProcess(processId, processName, executablePath, _options.Verifier))
        {
            return MemoryScanResult.Skip(processId, "CriticalProcessGuard: защищённый системный процесс или процесс Sentinel.");
        }

        IReadOnlyList<MemoryRegionInfo> regions;
        try
        {
            regions = _reader.EnumerateRegions(processId);
        }
        catch (Exception ex) when (ex is InvalidOperationException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
        {
            return MemoryScanResult.Skip(processId, $"Память недоступна: {ex.Message}");
        }

        var anomalies = new List<MemoryAnomaly>();
        var privateRwx = 0;
        var inspected = 0;
        long bytesRead = 0;
        var exhausted = false;

        var window = ArrayPool<byte>.Shared.Rent(_options.OverlapBytes + MemoryScanOptions.ChunkBytes);
        try
        {
            foreach (var region in regions)
            {
                if (!IsCandidate(region))
                {
                    continue;
                }

                if (region.IsPrivate && region.IsWriteExecute)
                {
                    privateRwx++;
                }

                if (region.IsImage)
                {
                    anomalies.Add(new MemoryAnomaly(MemoryAnomalyKind.ImagePatch, region.BaseAddress, region.RegionSize, 0,
                        region.Protect, region.Type, Severity.Low, "MEM_IMAGE + PAGE_EXECUTE_READWRITE"));
                }

                var remaining = _options.MaxBytesPerProcess - bytesRead;
                if (remaining <= 0)
                {
                    exhausted = true;
                    continue; // регионы образов ещё учитываются как аномалии, но не читаются
                }

                inspected++;
                bytesRead += ScanRegion(processId, region, Math.Min(Math.Min(region.RegionSize, _options.MaxBytesPerRegion), remaining), window, anomalies);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(window, clearArray: true); // содержимое чужой памяти не остаётся в пуле
        }

        var score = ThreatScoringEngine.Evaluate(new ScoringInput
        {
            Path = executablePath ?? processName ?? $"pid:{processId}",
            MemoryReflectivePe = anomalies.Exists(a => a.Kind == MemoryAnomalyKind.ReflectivePe),
            MemorySignatureMatch = anomalies.Exists(a => a.Kind == MemoryAnomalyKind.SignatureMatch)
                ? string.Join(", ", anomalies.Where(a => a.Kind == MemoryAnomalyKind.SignatureMatch).Select(a => a.Detail).Distinct())
                : null,
            MemoryImagePatch = anomalies.Exists(a => a.Kind == MemoryAnomalyKind.ImagePatch),
        });

        // PE и сигнатура в одном процессе — внедрённая полезная нагрузка: критичность по суммарному баллу.
        if (score.Level is { } level)
        {
            for (var i = 0; i < anomalies.Count; i++)
            {
                if (anomalies[i].Kind != MemoryAnomalyKind.ImagePatch && anomalies[i].Severity < level)
                {
                    anomalies[i] = anomalies[i] with { Severity = level };
                }
            }
        }

        return new MemoryScanResult(processId, null, regions.Count, inspected, privateRwx, bytesRead, exhausted, anomalies, score);
    }

    /// <summary>Читает регион окнами по 64 КБ с перекрытием и ищет PE-заголовок и сигнатуры. Возвращает число прочитанных байт.</summary>
    private long ScanRegion(int pid, MemoryRegionInfo region, long budget, byte[] window, List<MemoryAnomaly> anomalies)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var peFound = !region.IsPrivate; // у MEM_IMAGE заголовок MZ штатный — ищем только в приватной памяти
        long offset = 0;
        long total = 0;
        var carry = 0;

        while (offset < budget)
        {
            var want = (int)Math.Min(MemoryScanOptions.ChunkBytes, budget - offset);
            var read = _reader.ReadMemory(pid, region.BaseAddress + (nint)offset, window.AsSpan(carry, want));
            if (read <= 0)
            {
                break;
            }

            read = Math.Min(read, want);
            total += read;
            var length = carry + read;
            var windowStart = offset - carry; // смещение window[0] относительно начала региона
            var data = window.AsSpan(0, length);

            if (!peFound && FindPeHeader(data, windowStart) is { } pe)
            {
                peFound = true;
                anomalies.Add(new MemoryAnomaly(MemoryAnomalyKind.ReflectivePe, region.BaseAddress, region.RegionSize,
                    windowStart + pe.Position, region.Protect, region.Type, Severity.Medium, $"PE ({pe.Machine})"));
            }

            var eicar = Eicar.IndexOfSignature(data);
            if (eicar >= 0 && seen.Add(Eicar.DetectionName))
            {
                anomalies.Add(new MemoryAnomaly(MemoryAnomalyKind.SignatureMatch, region.BaseAddress, region.RegionSize,
                    windowStart + eicar, region.Protect, region.Type, Severity.High, Eicar.DetectionName));
            }

            if (_engine is not null)
            {
                foreach (var match in _engine.Scan(window.AsMemory(0, length), length, null, null))
                {
                    if (seen.Add(match.RuleId))
                    {
                        var hit = match.Hits.Count > 0 ? match.Hits[0].Offset : 0;
                        anomalies.Add(new MemoryAnomaly(MemoryAnomalyKind.SignatureMatch, region.BaseAddress, region.RegionSize,
                            windowStart + hit, region.Protect, region.Type, Max(match.Severity, Severity.Medium),
                            $"{match.RuleName} [{match.RuleId}]"));
                    }
                }
            }

            offset += read;
            if (read < want)
            {
                break; // частичное чтение: дальше страницы недоступны
            }

            // Хвост окна переносится в начало следующего — сигнатура на стыке 64 КБ не разрезается.
            carry = Math.Min(_options.OverlapBytes, length);
            Buffer.BlockCopy(window, length - carry, window, 0, carry);
        }

        return total;
    }

    /// <summary>MZ на границе страницы + адекватный <c>e_lfanew</c> (0x40..0x400) в пределах окна + <c>PE\0\0</c> + известный Machine.</summary>
    private static (int Position, string Machine)? FindPeHeader(ReadOnlySpan<byte> data, long windowStart)
    {
        var first = (int)((PageSize - (windowStart % PageSize)) % PageSize);
        for (var p = first; p + 0x40 <= data.Length; p += PageSize)
        {
            if (data[p] != 0x4D || data[p + 1] != 0x5A)
            {
                continue;
            }

            var lfanew = BinaryPrimitives.ReadInt32LittleEndian(data[(p + 0x3C)..]);
            if (lfanew is < 0x40 or > 0x400 || p + lfanew + 6 > data.Length)
            {
                continue;
            }

            var nt = data[(p + lfanew)..];
            if (nt[0] != 0x50 || nt[1] != 0x45 || nt[2] != 0 || nt[3] != 0)
            {
                continue;
            }

            var machine = BinaryPrimitives.ReadUInt16LittleEndian(nt[4..]) switch
            {
                0x014C => "x86",
                0x8664 => "x64",
                0xAA64 => "ARM64",
                0x01C4 => "ARMv7",
                _ => null,
            };
            if (machine is not null)
            {
                return (p, machine);
            }
        }

        return null;
    }

    private static Severity Max(Severity a, Severity b) => a >= b ? a : b;
}
