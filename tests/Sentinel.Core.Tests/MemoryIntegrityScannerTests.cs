using System.Buffers.Binary;
using System.Text;
using Sentinel.Core.Audit.Process;
using Sentinel.Core.Auditors.Memory;
using Sentinel.Core.Behavioral;
using Sentinel.Core.Detection;
using Sentinel.Core.Monitoring;
using Sentinel.Core.Scoring;
using Sentinel.Core.Signatures;
using static Sentinel.Core.Auditors.Memory.MemoryConstants;

namespace Sentinel.Core.Tests;

/// <summary>Синтетическое адресное пространство: регионы с содержимым; считает обращения и размеры буферов.</summary>
internal sealed class FakeMemoryReader : IMemoryReader
{
    private readonly Dictionary<int, List<(MemoryRegionInfo Region, byte[] Content)>> _processes = [];

    public int EnumerateCalls { get; private set; }

    public int ReadCalls { get; private set; }

    public int MaxBufferRequested { get; private set; }

    /// <summary>Сколько байт отдавать за вызов при частичном чтении (<c>ERROR_PARTIAL_COPY</c>); 0 — полностью.</summary>
    public int PartialReadLimit { get; set; }

    public FakeMemoryReader Add(int pid, nint baseAddress, byte[] content, uint type, uint protect, uint allocationProtect = 0, uint state = MEM_COMMIT)
    {
        if (!_processes.TryGetValue(pid, out var list))
        {
            _processes[pid] = list = [];
        }

        list.Add((new MemoryRegionInfo(baseAddress, content.Length, state, type, protect, allocationProtect == 0 ? protect : allocationProtect), content));
        return this;
    }

    public IReadOnlyList<MemoryRegionInfo> EnumerateRegions(int processId)
    {
        EnumerateCalls++;
        return _processes.TryGetValue(processId, out var list) ? list.Select(r => r.Region).ToArray() : [];
    }

    public int ReadMemory(int processId, nint address, Span<byte> buffer)
    {
        ReadCalls++;
        MaxBufferRequested = Math.Max(MaxBufferRequested, buffer.Length);
        if (!_processes.TryGetValue(processId, out var list))
        {
            return 0;
        }

        foreach (var (region, content) in list)
        {
            var offset = (long)address - (long)region.BaseAddress;
            if (offset < 0 || offset >= content.Length)
            {
                continue;
            }

            var count = (int)Math.Min(buffer.Length, content.Length - offset);
            if (PartialReadLimit > 0)
            {
                count = Math.Min(count, PartialReadLimit);
            }

            content.AsSpan((int)offset, count).CopyTo(buffer);
            return count;
        }

        return 0;
    }
}

internal static class MemoryPayloads
{
    /// <summary>Обычные байты JIT-кода (пролог/эпилог x64) без MZ/PE и сигнатур.</summary>
    public static byte[] JitCode(int size)
    {
        byte[] pattern = [0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0x45, 0x10, 0x5D, 0xC3, 0x90, 0x90];
        var data = new byte[size];
        for (var i = 0; i < size; i++)
        {
            data[i] = pattern[i % pattern.Length];
        }

        return data;
    }

    /// <summary>Синтетический заголовок PE (MZ, e_lfanew = 0x80, PE\0\0, Machine = x64) по смещению.</summary>
    public static byte[] WithPeHeader(byte[] data, int offset)
    {
        data[offset] = 0x4D;
        data[offset + 1] = 0x5A;
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(offset + 0x3C), 0x80);
        "PE\0\0"u8.CopyTo(data.AsSpan(offset + 0x80));
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(offset + 0x84), 0x8664);
        return data;
    }

    public static byte[] With(byte[] data, int offset, byte[] payload)
    {
        payload.CopyTo(data, offset);
        return data;
    }
}

public class MemoryIntegrityScannerTests
{
    private const int Pid = 4242;

    private static MemoryIntegrityScanner Scanner(FakeMemoryReader reader, MemoryScanOptions? options = null) =>
        new(reader, new SignatureEngine(RuleLoader.LoadDirectory(RepoPaths.RulesDirectory)), options);

    [Theory]
    [InlineData(700, "lsass.exe", null)]
    [InlineData(701, "lsass.exe", @"C:\Windows\System32\lsass.exe")]
    [InlineData(702, "svchost.exe", @"C:\Windows\System32\svchost.exe")]
    [InlineData(703, "csrss.exe", @"C:\Windows\System32\csrss.exe")]
    [InlineData(704, "services.exe", @"C:\Windows\System32\services.exe")]
    [InlineData(705, "explorer.exe", @"C:\Windows\explorer.exe")]
    [InlineData(706, "Sentinel.Service.exe", @"C:\Program Files\Sentinel\Sentinel.Service.exe")]
    [InlineData(4, "System", null)]
    public void ProtectedProcess_MemoryIsNeverTouched(int pid, string name, string? path)
    {
        var reader = new FakeMemoryReader()
            .Add(pid, 0x10000, MemoryPayloads.WithPeHeader(MemoryPayloads.JitCode(8192), 0), MEM_PRIVATE, PAGE_EXECUTE_READWRITE);

        var result = Scanner(reader).Scan(pid, name, path);

        Assert.True(result.Skipped);
        Assert.Equal(0, reader.EnumerateCalls);
        Assert.Equal(0, reader.ReadCalls);
        Assert.Empty(result.Anomalies);
    }

    [Fact]
    public void OwnProcess_IsSkipped()
    {
        var reader = new FakeMemoryReader();
        Assert.True(Scanner(reader).Scan(Environment.ProcessId, "testhost", null).Skipped);
        Assert.Equal(0, reader.EnumerateCalls);
    }

    [Fact]
    public void ProcessAuditor_ProtectedSystemProcess_DoesNotOpenMemory()
    {
        var reader = new FakeMemoryReader()
            .Add(702, 0x10000, MemoryPayloads.WithPeHeader(MemoryPayloads.JitCode(8192), 0), MEM_PRIVATE, PAGE_EXECUTE_READWRITE);
        var auditor = new ProcessAuditor(new ProcessAuditorOptions { MemoryScanner = Scanner(reader) });

        var entry = auditor.Audit([new ProcessSnapshot { Pid = 702, Name = "svchost.exe", ExecutablePath = @"C:\Windows\System32\svchost.exe" }]).Entries[0];

        Assert.Equal(0, reader.EnumerateCalls);
        Assert.True(entry.MemoryScan!.Skipped);
        Assert.False(entry.HasFindings);
    }

    [Fact]
    public void ReflectivePe_InPrivateRwx_IsDetected_AndRaisesScore()
    {
        var reader = new FakeMemoryReader()
            .Add(Pid, 0x7FF0_0000, MemoryPayloads.WithPeHeader(MemoryPayloads.JitCode(128 * 1024), 0), MEM_PRIVATE, PAGE_EXECUTE_READWRITE);

        var result = Scanner(reader).Scan(Pid, "loader.exe", @"C:\Users\u\AppData\Local\Temp\loader.exe");

        var anomaly = Assert.Single(result.Anomalies);
        Assert.Equal("MEM-REFLECTIVE-PE", anomaly.Id);
        Assert.Contains("x64", anomaly.Detail, StringComparison.Ordinal);
        Assert.Equal("0x7FF00000", anomaly.Address);
        Assert.InRange(result.Score.Value, 45, 60);
        Assert.Contains(result.Score.Factors, f => f.Code == "MEM-REFLECTIVE-PE");
        var finding = Assert.Single(result.ToFindings("loader.exe", null));
        Assert.Equal("MEM-REFLECTIVE-PE", finding.Id);
        Assert.True(finding.Severity >= Severity.Medium);
    }

    [Fact]
    public void ReflectivePe_OnPageBoundaryInsideSecondChunk_IsDetected()
    {
        var data = MemoryPayloads.WithPeHeader(MemoryPayloads.JitCode(256 * 1024), 64 * 1024 + 2 * 4096);
        var reader = new FakeMemoryReader().Add(Pid, 0x20_0000, data, MEM_PRIVATE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE);

        var result = Scanner(reader).Scan(Pid, "app.exe", @"C:\Apps\app.exe");

        var anomaly = Assert.Single(result.Anomalies);
        Assert.Equal(64 * 1024 + 2 * 4096, anomaly.Offset);
    }

    [Fact]
    public void InvalidPeHeaders_AreIgnored()
    {
        var data = MemoryPayloads.JitCode(64 * 1024);
        data[0] = 0x4D;
        data[1] = 0x5A;
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(0x3C), 0x7FFF_0000); // e_lfanew вне окна
        var reader = new FakeMemoryReader().Add(Pid, 0x10000, data, MEM_PRIVATE, PAGE_EXECUTE_READWRITE);

        Assert.Empty(Scanner(reader).Scan(Pid, "app.exe", null).Anomalies);
    }

    [Fact]
    public void EicarAcrossChunkBoundary_IsFoundThanksToOverlap()
    {
        var data = MemoryPayloads.With(MemoryPayloads.JitCode(256 * 1024), 65520, Eicar.CreateTestFileBytes());
        var reader = new FakeMemoryReader().Add(Pid, 0x40_0000, data, MEM_PRIVATE, PAGE_EXECUTE_READWRITE);

        var result = Scanner(reader).Scan(Pid, "app.exe", @"C:\Apps\app.exe");

        var anomaly = Assert.Single(result.Anomalies);
        Assert.Equal("MEM-YARA-MATCH", anomaly.Id);
        Assert.Equal(Eicar.DetectionName, anomaly.Detail);
        Assert.Equal(65520, anomaly.Offset);
        Assert.InRange(result.Score.Value, 60, 80);
        Assert.Equal(MemoryScanOptions.ChunkBytes, reader.MaxBufferRequested); // чтение строго буфером 64 КБ
    }

    [Fact]
    public void EicarAcrossChunkBoundary_WithoutOverlap_IsMissed()
    {
        // Контроль: без перекрытия сигнатура на стыке разрезается — именно это и закрывает overlap.
        var data = MemoryPayloads.With(MemoryPayloads.JitCode(256 * 1024), 65520, Eicar.CreateTestFileBytes());
        var reader = new FakeMemoryReader().Add(Pid, 0x40_0000, data, MEM_PRIVATE, PAGE_EXECUTE_READWRITE);

        Assert.Empty(Scanner(reader, new MemoryScanOptions { OverlapBytes = 0 }).Scan(Pid, "app.exe", null).Anomalies);
    }

    [Fact]
    public void MinerStrings_InExecutableMemory_MatchRules()
    {
        var payload = Encoding.ASCII.GetBytes("{\"url\":\"stratum+tcp://pool.example:3333\",\"algo\":\"randomx\",\"donate-level\":1}");
        var data = MemoryPayloads.With(MemoryPayloads.JitCode(64 * 1024), 1000, payload);
        var reader = new FakeMemoryReader().Add(Pid, 0x50_0000, data, MEM_PRIVATE, PAGE_EXECUTE_READWRITE);

        var result = Scanner(reader).Scan(Pid, "updater.exe", null);

        Assert.Contains(result.Anomalies, a => a.Kind == MemoryAnomalyKind.SignatureMatch && a.Detail.Contains("SNT-MINER-0001", StringComparison.Ordinal));
    }

    [Fact]
    public void CleanJitRwxRegion_GivesNoFindingAndNoScore()
    {
        var reader = new FakeMemoryReader()
            .Add(Pid, 0x10000, MemoryPayloads.JitCode(512 * 1024), MEM_PRIVATE, PAGE_EXECUTE_READWRITE)
            .Add(Pid, 0x90000, MemoryPayloads.JitCode(64 * 1024), MEM_PRIVATE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE);
        var scanner = Scanner(reader);

        var result = scanner.Scan(Pid, "pwsh.exe", @"C:\Program Files\PowerShell\7\pwsh.exe");

        Assert.Empty(result.Anomalies);
        Assert.Equal(0, result.Score.Value);
        Assert.Null(result.Score.Level);
        Assert.Equal(1, result.PrivateWriteExecuteRegions);
        Assert.Empty(result.ToFindings("pwsh.exe", null));
        var entry = new ProcessAuditor(new ProcessAuditorOptions { MemoryScanner = scanner })
            .Audit([new ProcessSnapshot { Pid = Pid, Name = "pwsh.exe", ExecutablePath = @"C:\Program Files\PowerShell\7\pwsh.exe" }]).Entries[0];
        Assert.False(entry.HasFindings);
    }

    [Fact]
    public void ImageRegions_HeaderIsNormal_RwxPatchIsLowSignal()
    {
        var image = MemoryPayloads.WithPeHeader(MemoryPayloads.JitCode(16 * 1024), 0);
        var reader = new FakeMemoryReader()
            .Add(Pid, unchecked((nint)0x140000000L), image, MEM_IMAGE, PAGE_EXECUTE_READ)
            .Add(Pid, unchecked((nint)0x140010000L), MemoryPayloads.JitCode(4096), MEM_IMAGE, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY);

        var result = Scanner(reader).Scan(Pid, "app.exe", @"C:\Apps\app.exe");

        var anomaly = Assert.Single(result.Anomalies);
        Assert.Equal("MEM-RWX-IMAGE-PATCH", anomaly.Id);
        Assert.Equal(Severity.Low, anomaly.Severity);
        Assert.Equal(10, result.Score.Value);
        Assert.Null(ThreatScoringEngine.LevelFor(result.Score.Value));
    }

    [Theory]
    [InlineData(PAGE_EXECUTE_READWRITE | PAGE_GUARD, MEM_COMMIT)]
    [InlineData(PAGE_NOACCESS, MEM_COMMIT)]
    [InlineData(PAGE_EXECUTE_READWRITE, MEM_RESERVE)]
    [InlineData(PAGE_READWRITE, MEM_COMMIT)]
    public void GuardNoAccessReservedOrNonExecutable_AreNotRead(uint protect, uint state)
    {
        var reader = new FakeMemoryReader()
            .Add(Pid, 0x10000, MemoryPayloads.WithPeHeader(MemoryPayloads.JitCode(8192), 0), MEM_PRIVATE, protect, protect == PAGE_NOACCESS ? PAGE_NOACCESS : 0, state);

        var result = Scanner(reader).Scan(Pid, "app.exe", null);

        Assert.Equal(0, reader.ReadCalls);
        Assert.Empty(result.Anomalies);
    }

    [Fact]
    public void ReadBudget_PerRegionAndPerProcess_IsEnforced()
    {
        var reader = new FakeMemoryReader();
        for (var i = 0; i < 3; i++)
        {
            reader.Add(Pid, 0x100000 * (i + 1), MemoryPayloads.JitCode(256 * 1024), MEM_PRIVATE, PAGE_EXECUTE_READWRITE);
        }

        var result = Scanner(reader, new MemoryScanOptions { MaxBytesPerRegion = 128 * 1024, MaxBytesPerProcess = 192 * 1024 })
            .Scan(Pid, "jit.exe", null);

        Assert.Equal(192 * 1024, result.BytesRead);
        Assert.True(result.BudgetExhausted);
        Assert.Equal(2, result.RegionsInspected);
        Assert.Equal(MemoryScanOptions.ChunkBytes, reader.MaxBufferRequested);
    }

    [Fact]
    public void PartialRead_StopsRegionWithoutError()
    {
        var reader = new FakeMemoryReader { PartialReadLimit = 1000 }
            .Add(Pid, 0x10000, MemoryPayloads.JitCode(256 * 1024), MEM_PRIVATE, PAGE_EXECUTE_READWRITE);

        var result = Scanner(reader).Scan(Pid, "app.exe", null);

        Assert.Equal(1000, result.BytesRead);
        Assert.Equal(1, reader.ReadCalls);
    }

    [Fact]
    public void ReflectivePeAndSignature_Together_AreCritical()
    {
        var data = MemoryPayloads.WithPeHeader(MemoryPayloads.JitCode(64 * 1024), 0);
        MemoryPayloads.With(data, 0x1000, Eicar.CreateTestFileBytes());
        var reader = new FakeMemoryReader().Add(Pid, 0x10000, data, MEM_PRIVATE, PAGE_EXECUTE_READWRITE);

        var result = Scanner(reader).Scan(Pid, "app.exe", null);

        Assert.Equal(100, result.Score.Value);
        Assert.All(result.ToFindings("app.exe", null), f => Assert.Equal(Severity.Critical, f.Severity));
    }

    [Fact]
    public async Task ProcessStart_ObfuscatedLaunchPlusInMemoryPe_ClosesBh05()
    {
        using var b = new DispatcherBench();
        const string ps = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
        var reader = new FakeMemoryReader()
            .Add(7300, 0x30000, MemoryPayloads.WithPeHeader(MemoryPayloads.JitCode(64 * 1024), 0), MEM_PRIVATE, PAGE_EXECUTE_READWRITE);
        var monitor = new ProcessStartMonitor(new FakeProcessCreationEventSource(), b.Dispatcher, new BehavioralCorrelationEngine(), null,
            options: new ProcessStartMonitorOptions { Auditor = new ProcessAuditorOptions { MemoryScanner = Scanner(reader) } });

        var outcome = await monitor.InspectAsync(new ProcessCreationEvent(7300, 100, "powershell.exe", ps,
            "powershell -nop -enc SQBFAFgA", DateTimeOffset.UtcNow));

        Assert.Equal(CorrelationChain.InMemoryPayload, outcome.Correlation!.Chain);
        Assert.Contains(outcome.Findings, f => f.Id == "MEM-REFLECTIVE-PE");
        Assert.Contains(outcome.Findings, f => f.Id == "PROC-BH-05");
        Assert.True(outcome.Score >= 85, $"балл {outcome.Score}");
    }

    [Fact]
    public void Correlation_MemoryAnomalyWithoutSuspiciousStart_IsNotChained()
    {
        var engine = new BehavioralCorrelationEngine();
        engine.ReportProcessStart(@"C:\Program Files\App\app.exe", "app.exe --open x", true);

        Assert.Null(engine.ReportMemoryAnomaly(@"C:\Program Files\App\app.exe", "MEM-REFLECTIVE-PE"));
    }

    [Fact]
    public void Correlation_DroppedThenExecutedThenPayloadInMemory_IsBh05()
    {
        var engine = new BehavioralCorrelationEngine();
        const string path = @"C:\Users\u\AppData\Local\Temp\stage.exe";
        engine.ReportFileWritten(path, false);
        engine.ReportProcessStart(path, "stage.exe", false);

        Assert.Equal(CorrelationChain.InMemoryPayload, engine.ReportMemoryAnomaly(path, "MEM-YARA-MATCH")!.Chain);
    }
}
