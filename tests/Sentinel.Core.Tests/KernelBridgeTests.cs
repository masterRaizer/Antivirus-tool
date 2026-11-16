using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using Sentinel.Core.Audit.Process;
using Sentinel.Core.Kernel;
using Sentinel.Core.Monitoring;
using Sentinel.Core.Protection;

namespace Sentinel.Core.Tests;

/// <summary>Подставной драйвер: статус, принятые списки PID, очередь событий и имитация потери связи.</summary>
internal sealed class FakeKernelBridge : IKernelBridge
{
    public bool IsConnected { get; set; } = true;

    public bool ProcessNotify { get; set; } = true;

    public List<int[]> Sent { get; } = [];

    public Queue<KernelProcessEvent> Events { get; } = new();

    /// <summary>После стольких чтений связь «теряется» (0 — никогда).</summary>
    public int DisconnectAfterReads { get; set; }

    public int Reads { get; private set; }

    public bool Disposed { get; private set; }

    public KernelDriverStatus GetStatus() => IsConnected
        ? new KernelDriverStatus(true, KernelDriverStatus.KernelMode, "fake driver") { ProcessNotifyActive = ProcessNotify, ObCallbacksActive = true }
        : KernelDriverStatus.UserMode();

    public KernelOperationResult SetProtectedProcesses(IReadOnlyCollection<int> processIds)
    {
        Sent.Add(processIds.ToArray());
        return KernelOperationResult.Ok("ok");
    }

    public IReadOnlyList<KernelProcessEvent> ReadEvents(int maxEvents = KernelProtocol.DefaultReadBatch)
    {
        Reads++;
        var batch = new List<KernelProcessEvent>();
        while (batch.Count < maxEvents && Events.TryDequeue(out var e))
        {
            batch.Add(e);
        }

        if (DisconnectAfterReads > 0 && Reads >= DisconnectAfterReads)
        {
            IsConnected = false;
        }

        return batch;
    }

    public void Dispose() => Disposed = true;
}

public class KernelProtocolTests
{
    private static string DriverFile(string name)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Sentinel.sln")))
        {
            dir = dir.Parent;
        }

        return Path.Combine(dir!.FullName, "driver", "SentinelDrv", name);
    }

    [Fact]
    public void IoctlCodes_MatchCtlCodeMacro()
    {
        Assert.Equal(KernelProtocol.IoctlGetStatus, KernelProtocol.CtlCode(KernelProtocol.DeviceType, 0x800, KernelProtocol.MethodBuffered, KernelProtocol.FileReadData));
        Assert.Equal(KernelProtocol.IoctlSetProtectedPids, KernelProtocol.CtlCode(KernelProtocol.DeviceType, 0x801, KernelProtocol.MethodBuffered, KernelProtocol.FileWriteData));
        Assert.Equal(KernelProtocol.IoctlReadEvents, KernelProtocol.CtlCode(KernelProtocol.DeviceType, 0x802, KernelProtocol.MethodBuffered, KernelProtocol.FileReadData));
        Assert.Equal(0x8A536000u, KernelProtocol.IoctlGetStatus);
        Assert.Equal(0x8A53A004u, KernelProtocol.IoctlSetProtectedPids);
        Assert.Equal(0x8A536008u, KernelProtocol.IoctlReadEvents);
    }

    [Fact]
    public void StructSizesAndOffsets_MatchDriverLayout()
    {
        Assert.Equal(48, KernelProtocol.StatusSize);
        Assert.Equal(48, Marshal.SizeOf<KernelProtocol.StatusNative>());
        Assert.Equal(32, (int)Marshal.OffsetOf<KernelProtocol.StatusNative>(nameof(KernelProtocol.StatusNative.HandleStripsTotal)));
        Assert.Equal(40, (int)Marshal.OffsetOf<KernelProtocol.StatusNative>(nameof(KernelProtocol.StatusNative.EventsQueued)));
        Assert.Equal(264, KernelProtocol.ProtectedPidsSize);
        Assert.Equal(16, KernelProtocol.EventBatchHeaderSize);
        Assert.Equal(1576, KernelProtocol.ProcessEventSize);
        Assert.Equal(32, KernelProtocol.ImagePathOffset);
        Assert.Equal(552, KernelProtocol.CommandLineOffset);
    }

    [Fact]
    public void Constants_AreTheSameAsInDriverSources()
    {
        var header = File.ReadAllText(DriverFile("SentinelDrv.h"));
        var source = File.ReadAllText(DriverFile("SentinelDrv.c"));

        uint Define(string name)
        {
            var m = Regex.Match(header, $@"#define\s+{name}\s+(0x[0-9A-Fa-f]+|\d+)u?\b");
            Assert.True(m.Success, $"#define {name} не найден в SentinelDrv.h");
            var v = m.Groups[1].Value;
            return v.StartsWith("0x", StringComparison.Ordinal) ? Convert.ToUInt32(v[2..], 16) : uint.Parse(v, System.Globalization.CultureInfo.InvariantCulture);
        }

        int Assertion(string expression)
        {
            var m = Regex.Match(source, $@"C_ASSERT\({Regex.Escape(expression)}\s*==\s*(\d+)\);");
            Assert.True(m.Success, $"C_ASSERT({expression}) не найден в SentinelDrv.c");
            return int.Parse(m.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture);
        }

        Assert.Equal(KernelProtocol.ProtocolVersion, Define("SENTINEL_PROTOCOL_VERSION"));
        Assert.Equal(KernelProtocol.DeviceType, Define("SENTINEL_DEVICE_TYPE"));
        Assert.Equal((uint)KernelProtocol.MaxProtectedPids, Define("SENTINEL_MAX_PROTECTED_PIDS"));
        Assert.Equal((uint)KernelProtocol.ImagePathChars, Define("SENTINEL_IMAGE_PATH_CHARS"));
        Assert.Equal((uint)KernelProtocol.CommandLineChars, Define("SENTINEL_COMMAND_LINE_CHARS"));
        Assert.Equal(KernelProtocol.EventFlagWasProtected, Define("SENTINEL_EVENT_WAS_PROTECTED"));
        Assert.Equal(KernelProtocol.StatusFlagProcessNotify, Define("SENTINEL_STATUS_PROCESS_NOTIFY"));
        Assert.Contains("L\"\\\\Device\\\\SentinelDrv\"", header, StringComparison.Ordinal);
        Assert.Contains("L\"\\\\DosDevices\\\\SentinelDrv\"", header, StringComparison.Ordinal);
        Assert.Equal(KernelProtocol.StatusSize, Assertion("sizeof(SENTINEL_STATUS)"));
        Assert.Equal(KernelProtocol.ProtectedPidsSize, Assertion("sizeof(SENTINEL_PROTECTED_PIDS)"));
        Assert.Equal(KernelProtocol.EventBatchHeaderSize, Assertion("sizeof(SENTINEL_EVENT_BATCH)"));
        Assert.Equal(KernelProtocol.ProcessEventSize, Assertion("sizeof(SENTINEL_PROCESS_EVENT)"));
        Assert.Equal(KernelProtocol.ImagePathOffset, Assertion("FIELD_OFFSET(SENTINEL_PROCESS_EVENT, ImagePath)"));
        Assert.Equal(KernelProtocol.CommandLineOffset, Assertion("FIELD_OFFSET(SENTINEL_PROCESS_EVENT, CommandLine)"));
        Assert.Contains("/INTEGRITYCHECK", File.ReadAllText(DriverFile("SentinelDrv.vcxproj")), StringComparison.Ordinal);
    }

    [Fact]
    public void EncodeProtectedPids_WritesHeaderAndPids()
    {
        var buffer = KernelProtocol.EncodeProtectedPids([1234, 5678]);

        Assert.Equal(264, buffer.Length);
        Assert.Equal(1u, BinaryPrimitives.ReadUInt32LittleEndian(buffer));
        Assert.Equal(2u, BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(4)));
        Assert.Equal(1234u, BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(8)));
        Assert.Equal(5678u, BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(12)));
        Assert.All(buffer[16..], b => Assert.Equal(0, b));
        Assert.Throws<ArgumentException>(() => KernelProtocol.EncodeProtectedPids(Enumerable.Range(10, 65).ToArray()));
    }

    private static byte[] StatusBytes(uint protocol = 1)
    {
        var b = new byte[48];
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(0), protocol);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(4), 0x00010300);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(8), 0x3);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(12), 7);
        BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(16), 1000);
        BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(24), 2);
        BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(32), 42);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(40), 5);
        return b;
    }

    [Fact]
    public void DecodeStatus_ReadsEveryField()
    {
        var s = KernelProtocol.DecodeStatus(StatusBytes());

        Assert.True(s.Loaded);
        Assert.Equal(KernelDriverStatus.KernelMode, s.Mode);
        Assert.Equal(new Version(1, 3, 0), s.DriverVersion);
        Assert.True(s.ObCallbacksActive);
        Assert.True(s.ProcessNotifyActive);
        Assert.Equal(7, s.ProtectedPidCount);
        Assert.Equal(1000ul, s.ProcessEventsTotal);
        Assert.Equal(2ul, s.EventsDropped);
        Assert.Equal(42ul, s.HandleStripsTotal);
        Assert.Equal(5, s.EventsQueued);
        Assert.Contains("1.3.0", s.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void DecodeStatus_RejectsShortBufferAndForeignProtocol()
    {
        Assert.Throws<KernelProtocolException>(() => KernelProtocol.DecodeStatus(new byte[47]));
        Assert.Throws<KernelProtocolException>(() => KernelProtocol.DecodeStatus(StatusBytes(protocol: 2)));
    }

    private static void WriteEvent(Span<byte> e, uint kind, int pid, int parent, uint flags, DateTimeOffset time, string image, string commandLine)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(e, kind);
        BinaryPrimitives.WriteUInt32LittleEndian(e[4..], (uint)pid);
        BinaryPrimitives.WriteUInt32LittleEndian(e[8..], (uint)parent);
        BinaryPrimitives.WriteUInt32LittleEndian(e[12..], flags);
        BinaryPrimitives.WriteInt64LittleEndian(e[16..], time.ToFileTime());
        BinaryPrimitives.WriteUInt16LittleEndian(e[24..], (ushort)image.Length);
        BinaryPrimitives.WriteUInt16LittleEndian(e[26..], (ushort)commandLine.Length);
        Encoding.Unicode.GetBytes(image, e[32..]);
        Encoding.Unicode.GetBytes(commandLine, e[552..]);
    }

    [Fact]
    public void DecodeEvents_ReadsBatch()
    {
        var time = new DateTimeOffset(2026, 11, 16, 9, 0, 0, TimeSpan.Zero);
        var buffer = new byte[16 + (2 * 1576)];
        BinaryPrimitives.WriteUInt32LittleEndian(buffer, 1);
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(4), 2);
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(8), 9);
        WriteEvent(buffer.AsSpan(16), 1, 4321, 100, 0, time, @"\??\C:\Temp\svchost.exe", "svchost.exe -k fake");
        WriteEvent(buffer.AsSpan(16 + 1576), 2, 777, 0, KernelProtocol.EventFlagWasProtected, time, string.Empty, string.Empty);

        var events = KernelProtocol.DecodeEvents(buffer, out var remaining);

        Assert.Equal(9, remaining);
        Assert.Equal(2, events.Count);
        var created = events[0];
        Assert.Equal(KernelProcessEventKind.Create, created.Kind);
        Assert.Equal(4321, created.ProcessId);
        Assert.Equal(100, created.ParentProcessId);
        Assert.Equal(time, created.TimestampUtc);
        Assert.Equal(@"\??\C:\Temp\svchost.exe", created.ImagePath);
        Assert.Equal("svchost.exe -k fake", created.CommandLine);
        Assert.Equal(KernelProcessEventKind.Exit, events[1].Kind);
        Assert.True(events[1].WasProtected);

        var start = created.ToCreationEvent();
        Assert.Equal(@"C:\Temp\svchost.exe", start.ExecutablePath);
        Assert.Equal("svchost.exe", start.ProcessName);
        Assert.Equal("svchost.exe -k fake", start.CommandLine);
    }

    [Fact]
    public void DecodeEvents_RejectsInconsistentBatch()
    {
        var buffer = new byte[16 + 1576];
        BinaryPrimitives.WriteUInt32LittleEndian(buffer, 1);
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(4), 2); // объявлено 2, в буфере место под 1
        Assert.Throws<KernelProtocolException>(() => KernelProtocol.DecodeEvents(buffer, out _));
        Assert.Throws<KernelProtocolException>(() => KernelProtocol.DecodeEvents(new byte[8], out _));
    }

    [Theory]
    [InlineData(@"\??\C:\Windows\System32\cmd.exe", @"C:\Windows\System32\cmd.exe")]
    [InlineData(@"\\?\C:\Temp\a.exe", @"C:\Temp\a.exe")]
    [InlineData(@"\??\UNC\server\share\tool.exe", @"\\server\share\tool.exe")]
    [InlineData(@"\Device\HarddiskVolume3\Users\u\x.exe", @"D:\Users\u\x.exe")]
    [InlineData(@"\Device\HarddiskVolume30\x.exe", @"\Device\HarddiskVolume30\x.exe")]
    [InlineData(@"C:\Already\Win32.exe", @"C:\Already\Win32.exe")]
    [InlineData("", "")]
    public void NtPath_ConvertsKernelPaths(string input, string expected) =>
        Assert.Equal(expected, NtPath.ToWin32(input, new Dictionary<string, string> { [@"\Device\HarddiskVolume3"] = "D:" }));
}

public class KernelBridgeFallbackTests
{
    [Fact]
    public void NullBridge_NeverThrows_AndReportsUserModeProfile()
    {
        using var bridge = new NullKernelBridge();

        var status = bridge.GetStatus();
        Assert.False(bridge.IsConnected);
        Assert.False(status.Loaded);
        Assert.Equal(KernelDriverStatus.UserModeProfile, status.Mode);
        Assert.Equal("Kernel driver not loaded, running in User-Mode EDR profile", status.Message);
        Assert.False(bridge.SetProtectedProcesses([1, 2]).Success);
        Assert.Empty(bridge.ReadEvents());
    }

    [Fact]
    public void Factory_OutsideWindows_FallsBackToUserMode()
    {
        if (OperatingSystem.IsWindows())
        {
            return; // на Windows результат зависит от того, загружен ли драйвер
        }

        using var bridge = KernelBridgeFactory.CreateDefault();
        Assert.IsType<NullKernelBridge>(bridge);
        Assert.StartsWith(KernelDriverStatus.NotLoadedMessage, bridge.GetStatus().Message, StringComparison.Ordinal);
    }

    [WindowsFact]
    public void WindowsBridge_WithoutDriver_FallsBackWithoutException()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        // На сборочном раннере драйвер не установлен: открытие \\.\SentinelDrv должно вернуть профиль User-Mode.
        using var bridge = WindowsKernelBridge.Open();
        var status = bridge.GetStatus();
        if (bridge.IsConnected)
        {
            Assert.True(status.Loaded);
            return;
        }

        Assert.IsType<NullKernelBridge>(bridge);
        Assert.StartsWith(KernelDriverStatus.NotLoadedMessage, status.Message, StringComparison.Ordinal);
        Assert.Empty(bridge.ReadEvents());
    }
}

public class KernelProtectionSyncTests
{
    private const int OwnPid = 910_000;

    private static ProcessSnapshot P(int pid, string name, string path) => new() { Pid = pid, Name = name, ExecutablePath = path };

    [Fact]
    public void Select_OwnAndVerifiedSystemProcesses_NotMasquerade()
    {
        var pids = KernelProtectionSync.SelectProtectedPids(
        [
            P(910_001, "Sentinel.App.exe", @"C:\Program Files\Sentinel\Sentinel.App.exe"),
            P(910_002, "Sentinel.App.exe", @"C:\Users\Public\Sentinel.App.exe"),   // маскировка под Sentinel
            P(910_003, "csrss.exe", @"C:\Windows\System32\csrss.exe"),
            P(910_004, "csrss.exe", @"C:\Temp\csrss.exe"),                          // маскировка под ядро ОС
            P(910_005, "lsass.exe", @"C:\Windows\System32\lsass.exe"),
            P(910_006, "svchost.exe", @"C:\Windows\System32\svchost.exe"),          // не защищается ядром
            P(910_007, "explorer.exe", @"C:\Windows\explorer.exe"),
            P(910_008, "winlogon.exe", @"C:\Windows\System32\winlogon.exe"),
            P(4, "System", @"C:\Windows\System32\ntoskrnl.exe"),
        ], OwnPid);

        Assert.Equal([OwnPid, 910_001, 910_003, 910_005, 910_008], pids);
    }

    [Fact]
    public void Select_CapsAt64_KeepingSentinelFirst()
    {
        var processes = Enumerable.Range(0, 80).Select(i => P(920_000 + i, "csrss.exe", @"C:\Windows\System32\csrss.exe"))
            .Append(P(930_000, "Sentinel.App.exe", @"C:\Program Files\Sentinel\Sentinel.App.exe"));

        var pids = KernelProtectionSync.SelectProtectedPids(processes, OwnPid);

        Assert.Equal(64, pids.Count);
        Assert.Equal([OwnPid, 930_000], pids.Take(2));
    }

    [Fact]
    public void Synchronize_SendsOnlyOnChange_AndPublishesToGuard()
    {
        var bridge = new FakeKernelBridge();
        var host = new FakeProcessHost().Add(940_001, 1, "Sentinel.App.exe", @"C:\Program Files\Sentinel\Sentinel.App.exe");
        var sync = new KernelProtectionSync(bridge, host, ownProcessId: 940_000);
        try
        {
            Assert.True(sync.Synchronize()!.Success);
            Assert.Null(sync.Synchronize()); // без изменений — повторно не отправляется
            Assert.Equal([940_000, 940_001], Assert.Single(bridge.Sent));
            Assert.True(CriticalProcessGuard.IsProtectedProcess(940_001, "x.exe", @"C:\Temp\x.exe"));

            host.Add(940_002, 1, "Sentinel.Service.exe", @"C:\Program Files\Sentinel\Sentinel.Service.exe");
            Assert.True(sync.Synchronize()!.Success);
            Assert.Equal(2, bridge.Sent.Count);
        }
        finally
        {
            CriticalProcessGuard.SetKernelProtectedProcessIds([]);
        }

        Assert.False(CriticalProcessGuard.IsProtectedProcess(940_001, "x.exe", @"C:\Temp\x.exe"));
    }

    [Fact]
    public void Synchronize_WithoutDriver_DoesNothing()
    {
        var bridge = new FakeKernelBridge { IsConnected = false };
        var sync = new KernelProtectionSync(bridge, new FakeProcessHost(), ownProcessId: 950_000, publishToGuard: false);

        Assert.Null(sync.Synchronize());
        Assert.Empty(bridge.Sent);
    }
}

public class KernelProcessCreationEventSourceTests
{
    private static KernelProcessEvent Created(int pid, string image, string commandLine = "") =>
        new(KernelProcessEventKind.Create, pid, 1, DateTimeOffset.UtcNow, image, commandLine);

    private static async Task<List<ProcessCreationEvent>> CollectAsync(KernelProcessCreationEventSource source, int expected)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var list = new List<ProcessCreationEvent>();
        await foreach (var e in source.ReadEventsAsync(cts.Token))
        {
            list.Add(e);
            if (list.Count == expected)
            {
                break;
            }
        }

        return list;
    }

    [Fact]
    public async Task KernelEvents_BecomeProcessCreationEvents_ExitsSkipped()
    {
        var bridge = new FakeKernelBridge();
        bridge.Events.Enqueue(Created(5000, @"\??\C:\Users\u\AppData\Local\Temp\miner.exe", "miner.exe --donate-level 1"));
        bridge.Events.Enqueue(new KernelProcessEvent(KernelProcessEventKind.Exit, 4000, 0, DateTimeOffset.UtcNow, "", ""));
        bridge.Events.Enqueue(Created(5001, @"\??\C:\Windows\System32\cmd.exe"));
        await using var source = new KernelProcessCreationEventSource(bridge, pollInterval: TimeSpan.FromMilliseconds(5));

        var events = await CollectAsync(source, 2);

        Assert.Equal("kernel", source.Mode);
        Assert.Equal([5000, 5001], events.Select(e => e.ProcessId));
        Assert.Equal(@"C:\Users\u\AppData\Local\Temp\miner.exe", events[0].ExecutablePath);
        Assert.Equal("miner.exe", events[0].ProcessName);
        Assert.Equal("miner.exe --donate-level 1", events[0].CommandLine);
    }

    [Fact]
    public async Task LostDriver_SwitchesToFallbackSource()
    {
        var bridge = new FakeKernelBridge { DisconnectAfterReads = 1 };
        bridge.Events.Enqueue(Created(6000, @"\??\C:\Temp\a.exe"));
        var fallback = new FakeProcessCreationEventSource(new ProcessCreationEvent(6001, 1, "b.exe", @"C:\Temp\b.exe", "", DateTimeOffset.UtcNow));
        await using var source = new KernelProcessCreationEventSource(bridge, () => fallback, TimeSpan.FromMilliseconds(5));
        var logs = new List<string>();
        source.Log += logs.Add;

        var events = await CollectAsync(source, 2);

        Assert.Equal([6000, 6001], events.Select(e => e.ProcessId));
        Assert.Equal("kernel→fake", source.Mode);
        Assert.Contains(logs, l => l.Contains("User-Mode EDR", StringComparison.Ordinal));
    }
}

public class RuntimeKernelTests
{
    [Fact]
    public async Task Runtime_WithoutDriver_RunsInUserModeProfile()
    {
        await using var bench = new RuntimeBench();

        var status = bench.Runtime.GetKernelStatus();
        Assert.False(status.Loaded);
        Assert.Equal(KernelDriverStatus.NotLoadedMessage, status.Message);
        await bench.Runtime.RunKernelBridgeAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(KernelDriverStatus.NotLoadedMessage, (await bench.Runtime.GetStatusAsync()).KernelDriver);
    }

    [Fact]
    public async Task Runtime_WithDriver_UsesKernelTelemetryForProcessStarts_AndSyncsPids()
    {
        var bridge = new FakeKernelBridge { DisconnectAfterReads = 3 };
        bridge.Events.Enqueue(new KernelProcessEvent(KernelProcessEventKind.Create, 7100, 1, DateTimeOffset.UtcNow,
            @"\??\C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell -nop -enc SQBFAFgA"));
        await using var bench = new RuntimeBench(kernelBridge: () => bridge);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        await bench.Runtime.RunProcessStartMonitorAsync(cts.Token);
        await bench.Runtime.RunKernelBridgeAsync(cts.Token);

        Assert.Equal(1, bench.Runtime.ProcessStartsInspected);
        Assert.Contains(bench.Raised, t => t.ProcessId == 7100 && t.Source == ProcessStartMonitor.Source);
        Assert.Empty(bridge.Sent); // связь «потеряна» после чтения событий — синхронизация не выполняется
        Assert.Contains(KernelDriverStatus.NotLoadedMessage, bench.Runtime.GetKernelStatus().Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Runtime_Dispose_ReleasesDriverAndGuardState()
    {
        var bridge = new FakeKernelBridge();
        var bench = new RuntimeBench(kernelBridge: () => bridge);
        Assert.True(bench.Runtime.KernelBridge.IsConnected);

        await bench.DisposeAsync();

        Assert.True(bridge.Disposed);
    }
}
