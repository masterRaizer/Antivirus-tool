using Sentinel.Core.Monitoring.Evasion;
using Sentinel.Core.Realtime;
using Sentinel.Core.Scanning;
using Sentinel.Core.Settings;
using Sentinel.Core.Signatures;
using Sentinel.Core.Trust;

namespace Sentinel.Core.Tests;

/// <summary>
/// Синтетическая машина: процессы с заданной нагрузкой (в ядрах) на каждую секунду, накопленное процессорное время и
/// общая занятость процессоров. Позволяет проиграть сценарий «майнер прячется от Диспетчера задач» без Windows.
/// </summary>
internal sealed class ActivitySim
{
    private readonly Dictionary<int, (int Parent, string Name, long Create, long Cpu, double Cores, double Gpu)> _procs = [];

    /// <summary>Замеряется ли нагрузка видеокарты (как на Windows со счётчиками GPU Engine).</summary>
    public bool GpuAvailable { get; set; } = true;
    private TimeSpan _clock = TimeSpan.FromSeconds(1000);
    private long _busy;

    public int Processors { get; init; } = 8;

    /// <summary>Нагрузка, которую потребляет процесс, скрытый из списка (руткит): видна только в общей занятости.</summary>
    public double HiddenCores { get; set; }

    public ActivitySim Start(int pid, string name, double cores, int parent = 1000, double gpu = 0)
    {
        _procs[pid] = (parent, name, 100_000 + pid, 0, cores, gpu);
        return this;
    }

    /// <summary>Нагрузка на видеокарту, 0–100 %.</summary>
    public ActivitySim Gpu(int pid, double percent)
    {
        var p = _procs[pid];
        _procs[pid] = p with { Gpu = percent };
        return this;
    }

    public ActivitySim Load(int pid, double cores)
    {
        var p = _procs[pid];
        _procs[pid] = p with { Cores = cores };
        return this;
    }

    public ActivitySim Stop(int pid)
    {
        _procs.Remove(pid);
        return this;
    }

    /// <summary>Одна секунда работы и замер в её конце.</summary>
    public ActivitySnapshot Tick(TimeSpan? step = null)
    {
        var dt = step ?? TimeSpan.FromSeconds(1);
        _clock += dt;
        foreach (var pid in _procs.Keys.ToList())
        {
            var p = _procs[pid];
            var used = (long)(p.Cores * dt.Ticks);
            _procs[pid] = p with { Cpu = p.Cpu + used };
            _busy += used;
        }

        _busy += (long)(HiddenCores * dt.Ticks);
        var samples = _procs.Select(kv => new ProcessActivitySample(kv.Key, kv.Value.Parent, kv.Value.Name, kv.Value.Create, kv.Value.Cpu,
            GpuAvailable ? kv.Value.Gpu : -1)).ToList();
        samples.Insert(0, new ProcessActivitySample(0, 0, "System Idle Process", 0, 0));
        return new ActivitySnapshot(_clock, DateTimeOffset.UnixEpoch + _clock, samples, Processors, new SystemCpuTimes(_busy, 0, 0));
    }

    /// <summary>Проигрывает <paramref name="seconds"/> секунд и собирает все находки.</summary>
    public List<MonitorEvasionFinding> Run(MonitorEvasionDetector detector, int seconds, Action<int>? each = null)
    {
        var found = new List<MonitorEvasionFinding>();
        for (var i = 0; i < seconds; i++)
        {
            each?.Invoke(i);
            found.AddRange(detector.Observe(Tick()).Findings);
        }

        return found;
    }
}

public class MonitorEvasionDetectorTests
{
    private const int Miner = 5100;
    private const int TaskManager = 7000;

    private static (ActivitySim Sim, MonitorEvasionDetector Detector) Bench()
    {
        var sim = new ActivitySim()
            .Start(4, "System", 0.02, parent: 0)
            .Start(900, "explorer.exe", 0.05)
            .Start(Miner, "svcupdate.exe", 3.0);
        return (sim, new MonitorEvasionDetector(ownProcessId: 1));
    }

    /// <summary>Майнер, который проверяет список процессов каждые <paramref name="pollSeconds"/> с.</summary>
    private static void HidingMiner(ActivitySim sim, int pid, double cores, ref bool hidden, bool monitorOpen, int second, int pollSeconds = 2)
    {
        if (second % pollSeconds == 0)
        {
            hidden = monitorOpen;
        }

        sim.Load(pid, hidden ? 0.0 : cores);
    }

    [Fact]
    public void HidingMiner_FullCycle_IsDetected()
    {
        var (sim, detector) = Bench();
        Assert.Empty(sim.Run(detector, 40));

        sim.Start(TaskManager, "Taskmgr.exe", 0.1);
        var hidden = false;
        var found = sim.Run(detector, 30, i => HidingMiner(sim, Miner, 3.0, ref hidden, monitorOpen: true, i));
        Assert.Empty(found); // пока Диспетчер открыт — только наблюдение

        sim.Stop(TaskManager);
        found = sim.Run(detector, 20, i => HidingMiner(sim, Miner, 3.0, ref hidden, monitorOpen: false, i));

        var finding = Assert.Single(found);
        Assert.Equal(EvasionKind.HideAndResume, finding.Kind);
        Assert.Equal(Miner, finding.Pid);
        Assert.Equal("Taskmgr.exe", finding.Monitor);
        Assert.Equal(1, finding.CycleCount);
        Assert.InRange(finding.BaselineCores, 2.9, 3.1);
        Assert.True(finding.Reaction <= TimeSpan.FromSeconds(3), finding.Reaction.ToString());
        Assert.NotNull(finding.ResumeDelay);
        Assert.Contains("Taskmgr.exe", finding.Describe(), StringComparison.Ordinal);
    }

    [Fact]
    public void RepeatedCycles_AreCounted()
    {
        var (sim, detector) = Bench();
        sim.Run(detector, 40);
        var hidden = false;
        var all = new List<MonitorEvasionFinding>();
        for (var cycle = 0; cycle < 2; cycle++)
        {
            sim.Start(TaskManager + cycle, "Taskmgr.exe", 0.1);
            all.AddRange(sim.Run(detector, 15, i => HidingMiner(sim, Miner, 3.0, ref hidden, true, i)));
            sim.Stop(TaskManager + cycle);
            all.AddRange(sim.Run(detector, 40, i => HidingMiner(sim, Miner, 3.0, ref hidden, false, i)));
        }

        Assert.Equal([1, 2], all.Where(f => f.Kind == EvasionKind.HideAndResume).Select(f => f.CycleCount));
    }

    [Fact]
    public void QuickReopen_AfterConfirmedCycle_CountsTheSecondCycle()
    {
        var (sim, detector) = Bench();
        sim.Run(detector, 40);
        var hidden = false;
        var all = new List<MonitorEvasionFinding>();
        for (var cycle = 0; cycle < 2; cycle++)
        {
            sim.Start(TaskManager + cycle, "Taskmgr.exe", 0.1);
            all.AddRange(sim.Run(detector, 12, i => HidingMiner(sim, Miner, 3.0, ref hidden, true, i)));
            sim.Stop(TaskManager + cycle);
            // Повторное открытие уже через 12 с после закрытия.
            all.AddRange(sim.Run(detector, 12, i => HidingMiner(sim, Miner, 3.0, ref hidden, false, i)));
        }

        Assert.Equal([1, 2], all.Where(f => f.Kind == EvasionKind.HideAndResume).Select(f => f.CycleCount));
    }

    [Fact]
    public void QuickReopen_WithoutPriorCycle_NeedsFullBaseline()
    {
        var (sim, detector) = Bench();
        sim.Load(Miner, 0);
        sim.Run(detector, 40);
        sim.Load(Miner, 3.0);
        sim.Run(detector, 5); // 5 с нагрузки — мало для нового кандидата
        sim.Start(TaskManager, "Taskmgr.exe", 0.1);
        var found = sim.Run(detector, 12, _ => sim.Load(Miner, 0));
        sim.Stop(TaskManager);
        found.AddRange(sim.Run(detector, 20, _ => sim.Load(Miner, 3.0)));
        Assert.Empty(found);
    }

    /// <summary>GPU-майнер (как «Microsoft Network Realtime lnspection Service.exe» семейства CAAService): процессор почти не грузит.</summary>
    [Fact]
    public void GpuMiner_HidingFromTaskManager_IsDetected()
    {
        const int gpuMiner = 5300;
        var (sim, detector) = Bench();
        sim.Load(Miner, 0.0).Start(gpuMiner, "Microsoft Network Realtime lnspection Service.exe", 0.05, gpu: 74);
        sim.Run(detector, 40);
        var hidden = false;
        sim.Start(TaskManager, "Taskmgr.exe", 0.1);
        var found = sim.Run(detector, 20, i =>
        {
            if (i % 2 == 0)
            {
                hidden = true;
            }

            sim.Gpu(gpuMiner, hidden ? 0 : 74);
        });
        sim.Stop(TaskManager);
        found.AddRange(sim.Run(detector, 20, i =>
        {
            if (i % 2 == 0)
            {
                hidden = false;
            }

            sim.Gpu(gpuMiner, hidden ? 0 : 74);
        }));

        var finding = Assert.Single(found);
        Assert.Equal(ActivityResource.Gpu, finding.Resource);
        Assert.Equal(EvasionKind.HideAndResume, finding.Kind);
        Assert.InRange(finding.BaselineCores, 0.73, 0.75);
        Assert.Contains("видеокарт", finding.Describe(), StringComparison.Ordinal);
    }

    [Fact]
    public void CpuAndGpuMiner_IsReportedOnce()
    {
        var (sim, detector) = Bench();
        sim.Gpu(Miner, 60);
        sim.Run(detector, 40);
        sim.Start(TaskManager, "Taskmgr.exe", 0.1);
        var found = sim.Run(detector, 15, _ => sim.Load(Miner, 0).Gpu(Miner, 0));
        sim.Stop(TaskManager);
        found.AddRange(sim.Run(detector, 20, _ => sim.Load(Miner, 3).Gpu(Miner, 60)));
        Assert.Equal(Miner, Assert.Single(found).Pid);
    }

    [Fact]
    public void UnknownGpuSamples_DoNotBreakTracking()
    {
        var (sim, detector) = Bench();
        sim.Gpu(Miner, 60).Load(Miner, 0.01);
        sim.Run(detector, 40);
        sim.Start(TaskManager, "Taskmgr.exe", 0.1);
        var found = sim.Run(detector, 15, i =>
        {
            sim.Gpu(Miner, 0);
            sim.GpuAvailable = i % 3 != 1; // счётчики иногда не отдают значения
        });
        sim.Stop(TaskManager);
        found.AddRange(sim.Run(detector, 25, i =>
        {
            sim.Gpu(Miner, 60);
            sim.GpuAvailable = i % 3 != 1;
        }));
        Assert.Equal(ActivityResource.Gpu, Assert.Single(found).Resource);
    }

    [Fact]
    public void GpuLoad_ThatKeepsRunning_IsNotReported()
    {
        var (sim, detector) = Bench();
        sim.Load(Miner, 0.01).Gpu(Miner, 80); // игра или видео: видеокарта работает и при открытом Диспетчере
        sim.Run(detector, 40);
        sim.Start(TaskManager, "Taskmgr.exe", 0.1);
        var found = sim.Run(detector, 20);
        sim.Stop(TaskManager);
        found.AddRange(sim.Run(detector, 100));
        Assert.Empty(found);
    }

    [Theory]
    [InlineData("pid_1234_luid_0x00000000_0x0000D1A4_phys_0_eng_0_engtype_3D", 1234, "3D")]
    [InlineData("pid_8_luid_0x0_0x1_phys_0_eng_3_engtype_VideoDecode", 8, "VideoDecode")]
    public void GpuCounterInstance_IsParsed(string instance, int pid, string engine)
    {
        Assert.True(GpuEngineInstance.TryParse(instance, out var parsedPid, out var parsedEngine));
        Assert.Equal(pid, parsedPid);
        Assert.Equal(engine, parsedEngine);
    }

    [Theory]
    [InlineData("_Total")]
    [InlineData("pid_abc_luid")]
    [InlineData(null)]
    public void GpuCounterInstance_Garbage_IsRejected(string? instance) =>
        Assert.False(GpuEngineInstance.TryParse(instance, out _, out _));

    [Fact]
    public void SteadyProcess_ThatDoesNotReact_IsNotReported()
    {
        var (sim, detector) = Bench();
        sim.Start(6000, "encoder.exe", 2.0);
        sim.Run(detector, 40);
        sim.Start(TaskManager, "Taskmgr.exe", 0.1);
        Assert.Empty(sim.Run(detector, 30));
        sim.Stop(TaskManager);
        Assert.Empty(sim.Run(detector, 100));
    }

    [Fact]
    public void BurstyBuild_IsNotACandidate()
    {
        var (sim, detector) = Bench();
        sim.Load(Miner, 0);
        sim.Start(6100, "MSBuild.exe", 0);
        // Сборка: 2 с нагрузки, 3 с ожидания диска — средняя высокая, но не устойчивая.
        sim.Run(detector, 40, i => sim.Load(6100, i % 5 < 2 ? 4.0 : 0.0));
        sim.Start(TaskManager, "Taskmgr.exe", 0.1);
        var found = sim.Run(detector, 20, i => sim.Load(6100, 0));
        sim.Stop(TaskManager);
        found.AddRange(sim.Run(detector, 20, i => sim.Load(6100, i % 5 < 2 ? 4.0 : 0.0)));
        Assert.Empty(found);
    }

    [Fact]
    public void ProcessIdleBeforeMonitor_IsNotReported()
    {
        var (sim, detector) = Bench();
        // Нагрузка закончилась за 2 с до открытия Диспетчера: это не реакция на него.
        sim.Run(detector, 38);
        sim.Load(Miner, 0);
        sim.Run(detector, 2);
        sim.Start(TaskManager, "Taskmgr.exe", 0.1);
        var found = sim.Run(detector, 20);
        sim.Stop(TaskManager);
        found.AddRange(sim.Run(detector, 10, _ => sim.Load(Miner, 3.0)));
        Assert.Empty(found);
    }

    [Fact]
    public void LateDrop_OutsideReactionWindow_IsNotReported()
    {
        var (sim, detector) = Bench();
        sim.Run(detector, 40);
        sim.Start(TaskManager, "Taskmgr.exe", 0.1);
        var found = sim.Run(detector, 40, i => sim.Load(Miner, i < 20 ? 3.0 : 0.0));
        sim.Stop(TaskManager);
        found.AddRange(sim.Run(detector, 30, _ => sim.Load(Miner, 3.0)));
        Assert.Empty(found);
    }

    [Fact]
    public void ResumingWhileMonitorIsOpen_ClearsSuspicion()
    {
        var (sim, detector) = Bench();
        sim.Run(detector, 40);
        sim.Start(TaskManager, "Taskmgr.exe", 0.1);
        // Короткая пауза совпала с открытием, затем работа продолжилась при открытом Диспетчере.
        var found = sim.Run(detector, 30, i => sim.Load(Miner, i is >= 1 and < 6 ? 0.0 : 3.0));
        sim.Stop(TaskManager);
        found.AddRange(sim.Run(detector, 30));
        Assert.Empty(found);
    }

    [Fact]
    public void ExitRightAfterMonitorOpens_IsReported()
    {
        var (sim, detector) = Bench();
        sim.Run(detector, 40);
        sim.Start(TaskManager, "Taskmgr.exe", 0.1);
        var found = sim.Run(detector, 10, i =>
        {
            if (i == 2)
            {
                sim.Stop(Miner);
            }
        });

        var finding = Assert.Single(found);
        Assert.Equal(EvasionKind.ExitOnMonitor, finding.Kind);
        Assert.Equal(1, finding.ExitCount);
    }

    [Fact]
    public void HiddenAndNeverResumed_IsReportedAsWeakerFinding()
    {
        var (sim, detector) = Bench();
        sim.Run(detector, 40);
        sim.Start(TaskManager, "Taskmgr.exe", 0.1);
        var found = sim.Run(detector, 20, _ => sim.Load(Miner, 0.0));
        sim.Stop(TaskManager);
        found.AddRange(sim.Run(detector, 100));

        var finding = Assert.Single(found);
        Assert.Equal(EvasionKind.HiddenWhileMonitorOpen, finding.Kind);
    }

    [Fact]
    public void ReopeningMonitorBeforeResume_KeepsTheCandidate()
    {
        var (sim, detector) = Bench();
        sim.Run(detector, 40);
        var hidden = false;
        sim.Start(TaskManager, "Taskmgr.exe", 0.1);
        var found = sim.Run(detector, 10, i => HidingMiner(sim, Miner, 3.0, ref hidden, true, i));
        sim.Stop(TaskManager);
        found.AddRange(sim.Run(detector, 1, i => HidingMiner(sim, Miner, 3.0, ref hidden, true, i))); // ещё не заметил
        sim.Start(TaskManager + 1, "Taskmgr.exe", 0.1);
        found.AddRange(sim.Run(detector, 10, i => HidingMiner(sim, Miner, 3.0, ref hidden, true, i)));
        sim.Stop(TaskManager + 1);
        found.AddRange(sim.Run(detector, 20, i => HidingMiner(sim, Miner, 3.0, ref hidden, false, i)));

        Assert.Equal(EvasionKind.HideAndResume, Assert.Single(found).Kind);
    }

    [Fact]
    public void MonitorAlreadyOpenAtStart_GivesNoEpisodeUntilReopened()
    {
        var sim = new ActivitySim().Start(Miner, "svcupdate.exe", 3.0).Start(TaskManager, "Taskmgr.exe", 0.1);
        var detector = new MonitorEvasionDetector(ownProcessId: 1);
        Assert.Empty(sim.Run(detector, 30));
        sim.Stop(TaskManager);
        Assert.Empty(sim.Run(detector, 30));
        Assert.Equal(0, detector.Stats.MonitorOpenings);

        var hidden = false;
        sim.Start(TaskManager + 1, "Taskmgr.exe", 0.1);
        var found = sim.Run(detector, 15, i => HidingMiner(sim, Miner, 3.0, ref hidden, true, i));
        sim.Stop(TaskManager + 1);
        found.AddRange(sim.Run(detector, 20, i => HidingMiner(sim, Miner, 3.0, ref hidden, false, i)));
        Assert.Single(found);
        Assert.Equal(1, detector.Stats.MonitorOpenings);
    }

    [Fact]
    public void SampleGap_ResetsHistory()
    {
        var (sim, detector) = Bench();
        sim.Run(detector, 40);
        detector.Observe(sim.Tick(TimeSpan.FromSeconds(30))); // сон ноутбука
        sim.Start(TaskManager, "Taskmgr.exe", 0.1);
        var found = sim.Run(detector, 15, _ => sim.Load(Miner, 0));
        sim.Stop(TaskManager);
        found.AddRange(sim.Run(detector, 20, _ => sim.Load(Miner, 3.0)));
        Assert.Empty(found); // базовой нагрузки после пробуждения ещё нет — подозрение не строится
    }

    [Fact]
    public void ExcludedProcesses_AreNeverCandidates()
    {
        var sim = new ActivitySim()
            .Start(4, "System", 2.0, parent: 0)
            .Start(1, "sentinel-service.exe", 2.0)
            .Start(8100, "Memory Compression", 2.0);
        var detector = new MonitorEvasionDetector(ownProcessId: 1);
        sim.Run(detector, 40);
        sim.Start(TaskManager, "Taskmgr.exe", 0.1);
        var found = sim.Run(detector, 15, _ =>
        {
            sim.Load(4, 0).Load(1, 0).Load(8100, 0);
        });
        sim.Stop(TaskManager);
        found.AddRange(sim.Run(detector, 20, _ => sim.Load(4, 2).Load(1, 2).Load(8100, 2)));
        Assert.Empty(found);
    }

    [Fact]
    public void ChildOfMonitor_IsNotACandidate()
    {
        var (sim, detector) = Bench();
        sim.Start(TaskManager, "procexp64.exe", 0.1);
        sim.Stop(TaskManager);
        sim.Run(detector, 40);
        sim.Start(TaskManager, "procexp64.exe", 0.1).Start(7100, "helper.exe", 1.0, parent: TaskManager);
        sim.Run(detector, 40);
        Assert.Equal(1, detector.Stats.MonitorOpenings);
    }

    [Theory]
    [InlineData("resmon.exe")]
    [InlineData("procexp64.exe")]
    [InlineData("SystemInformer.exe")]
    [InlineData("ProcessHacker.exe")]
    public void OtherMonitoringTools_AreRecognised(string tool)
    {
        var (sim, detector) = Bench();
        sim.Run(detector, 40);
        var hidden = false;
        sim.Start(TaskManager, tool, 0.1);
        var found = sim.Run(detector, 15, i => HidingMiner(sim, Miner, 3.0, ref hidden, true, i));
        sim.Stop(TaskManager);
        found.AddRange(sim.Run(detector, 20, i => HidingMiner(sim, Miner, 3.0, ref hidden, false, i)));
        Assert.Equal(tool, Assert.Single(found).Monitor);
    }

    [Fact]
    public void HiddenCpu_SustainedGap_IsReportedOnceWithCooldown()
    {
        var (sim, detector) = Bench();
        sim.HiddenCores = 2.5;
        var hidden = new List<HiddenCpuFinding>();
        for (var i = 0; i < 200; i++)
        {
            if (detector.Observe(sim.Tick()).HiddenCpu is { } h)
            {
                hidden.Add(h);
            }
        }

        var finding = Assert.Single(hidden);
        Assert.InRange(finding.HiddenCores, 2.4, 2.6);
        Assert.True(finding.Duration >= TimeSpan.FromSeconds(60));
    }

    [Fact]
    public void HiddenCpu_ProcessChurn_IsNotReported()
    {
        var (sim, detector) = Bench();
        sim.HiddenCores = 2.5; // время коротких процессов, не попавших в замер
        var reported = false;
        for (var i = 0; i < 200; i++)
        {
            sim.Start(20_000 + i, "cl.exe", 0.1);
            if (i > 0)
            {
                sim.Stop(20_000 + i - 1);
            }

            sim.Start(30_000 + i, "link.exe", 0.1);
            reported |= detector.Observe(sim.Tick()).HiddenCpu is not null;
            sim.Stop(30_000 + i);
        }

        Assert.False(reported);
    }

    [Fact]
    public void HiddenCpu_SmallGap_IsIgnored()
    {
        var (sim, detector) = Bench();
        sim.HiddenCores = 0.6; // DPC, погрешность учёта — меньше порога (1 ядро и 15 %)
        Assert.DoesNotContain(Enumerable.Range(0, 200).Select(_ => detector.Observe(sim.Tick()).HiddenCpu), h => h is not null);
    }
}

public class MonitorEvasionPolicyTests
{
    private static MonitorEvasionFinding Finding(EvasionKind kind = EvasionKind.HideAndResume, int cycles = 1, double variation = 0.05) => new()
    {
        Kind = kind,
        Pid = 5100,
        Name = "svcupdate.exe",
        Monitor = "Taskmgr.exe",
        BaselineCores = 3,
        BaselineVariation = variation,
        CycleCount = kind == EvasionKind.HideAndResume ? cycles : cycles - 1,
        ExitCount = kind == EvasionKind.ExitOnMonitor ? 1 : 0,
    };

    [Fact]
    public void SingleCycle_UnsignedInProfile_AsksUser()
    {
        var score = MonitorEvasionPolicy.Score(Finding(), new EvasionScoreContext { UserWritableLocation = true, UserObjects = 0 });
        Assert.Equal(80, score.Score);
        Assert.False(score.AllowAutoAction);
    }

    [Fact]
    public void TwoCycles_AllowAutoAction()
    {
        var score = MonitorEvasionPolicy.Score(Finding(cycles: 2), new EvasionScoreContext { UserWritableLocation = true, UserObjects = 0 });
        Assert.Equal(95, score.Score);
        Assert.True(score.AllowAutoAction);
    }

    [Fact]
    public void WindowedApplication_IsPenalisedAndNeverAutoNeutralised()
    {
        var score = MonitorEvasionPolicy.Score(Finding(cycles: 3, variation: 0.4), new EvasionScoreContext { UserObjects = 240 });
        Assert.Equal(65, score.Score); // 60 + 30 (повторы) − 25 (окна)
        Assert.False(score.AllowAutoAction);
        Assert.Contains(score.Factors, f => f.Contains("окна", StringComparison.Ordinal));
    }

    [Fact]
    public void TrustedSigned_IsNotAutoNeutralised()
    {
        var score = MonitorEvasionPolicy.Score(Finding(cycles: 3), new EvasionScoreContext { TrustedSigned = true, UserObjects = 0 });
        Assert.False(score.AllowAutoAction);
    }

    [Fact]
    public void FlaggedImage_AllowsAutoActionAtOnce()
    {
        var score = MonitorEvasionPolicy.Score(Finding(EvasionKind.HiddenWhileMonitorOpen), new EvasionScoreContext { FileFlagged = true, FileScore = 85 });
        Assert.Equal(95, score.Score);
        Assert.True(score.AllowAutoAction);
    }

    [Fact]
    public void SingleExit_StaysBelowAskThreshold()
    {
        var score = MonitorEvasionPolicy.Score(Finding(EvasionKind.ExitOnMonitor, variation: 0.5), new EvasionScoreContext());
        Assert.True(score.Score < 50, score.Score.ToString(System.Globalization.CultureInfo.InvariantCulture));
    }

    [Fact]
    public void TrustedSystemComponent_WithoutConfirmation_IsOnlyLogged()
    {
        // SearchIndexer, обслуживание Windows: подписаны Microsoft и сами затихают при активности пользователя.
        var score = MonitorEvasionPolicy.Score(Finding(cycles: 3), new EvasionScoreContext { TrustedSigned = true, SystemLocation = true, UserObjects = 0 });
        Assert.Equal(MonitorEvasionPolicy.TrustedSystemCap, score.Score);
        Assert.False(score.AllowAutoAction);
    }

    [Fact]
    public void TrustedSystemComponent_WithMemoryPayload_IsNotCapped()
    {
        var score = MonitorEvasionPolicy.Score(Finding(), new EvasionScoreContext { TrustedSigned = true, SystemLocation = true, MemoryAnomaly = true });
        Assert.True(score.Score > MonitorEvasionPolicy.TrustedSystemCap);
        Assert.True(score.AllowAutoAction);
    }

    [Fact]
    public void HollowingHost_SignatureDoesNotProtect()
    {
        // RegAsm.exe из .NET Framework, долго грузящий процессор и прячущийся, — типичный внедрённый XMRig.
        var score = MonitorEvasionPolicy.Score(Finding(cycles: 2), new EvasionScoreContext { SystemLocation = true, HollowingHost = true, UserObjects = 0 });
        Assert.True(score.Score >= 80);
        Assert.True(score.AllowAutoAction);
        Assert.Contains("RegAsm.exe", MonitorEvasionPolicy.HollowingHosts);
    }

    [Theory]
    [InlineData(@"C:\Windows\System32\SearchIndexer.exe", true)]
    [InlineData(@"D:\Program Files (x86)\Steam\steam.exe", true)]
    [InlineData(@"C:\Users\Bob\AppData\Local\Temp\x.exe", false)]
    public void SystemLocations(string path, bool expected) =>
        Assert.Equal(expected, MonitorEvasionPolicy.IsSystemLocation(path));

    [Theory]
    [InlineData(@"C:\Users\Bob\AppData\Roaming\svc\svcupdate.exe", true)]
    [InlineData(@"C:\ProgramData\Intel\audio.exe", true)]
    [InlineData(@"C:\Windows\Temp\x.exe", true)]
    [InlineData(@"C:\Program Files\Game\game.exe", false)]
    [InlineData(null, false)]
    public void UserWritableLocations(string? path, bool expected) =>
        Assert.Equal(expected, MonitorEvasionPolicy.IsUserWritableLocation(path));
}

[Collection(KernelGuardStateGroup.Name)]
public class MonitorEvasionWatcherTests
{
    private sealed class FakeInspector : IEvasionProcessInspector
    {
        public Dictionary<int, string?> Paths { get; } = [];

        public int UserObjects { get; set; }

        public List<int> Described { get; } = [];

        public string? GetImagePath(int pid) => Paths.GetValueOrDefault(pid);

        public EvasionProcessDetails Describe(int pid)
        {
            Described.Add(pid);
            return new EvasionProcessDetails($"svcupdate.exe --pid {pid}", UserObjects);
        }
    }

    private sealed class NoSampler : IProcessActivitySampler
    {
        public ActivitySnapshot Capture() => throw new InvalidOperationException("не используется");

        public void Dispose()
        {
        }
    }

    private static MonitorEvasionFinding Finding(int pid, string name, int cycles = 1) => new()
    {
        Kind = EvasionKind.HideAndResume,
        Pid = pid,
        Name = name,
        Monitor = "Taskmgr.exe",
        BaselineCores = 3,
        BaselineVariation = 0.05,
        CycleCount = cycles,
        CreateTimeTicks = new DateTime(2026, 11, 17, 10, 0, 0, DateTimeKind.Utc).ToFileTimeUtc(),
    };

    private static MonitorEvasionWatcher Watcher(DispatcherBench bench, FakeInspector inspector, FileAnalyzer? analyzer = null, bool shadow = false) =>
        new(new NoSampler(), new MonitorEvasionDetector(), inspector, bench.Dispatcher, analyzer, () => bench.Allowed.Load(), () => shadow);

    [Fact]
    public async Task CriticalProcess_IsProtected_AndNotInspected()
    {
        using var bench = new DispatcherBench();
        var inspector = new FakeInspector { Paths = { [800] = @"C:\Windows\System32\svchost.exe" } };
        var outcome = await Watcher(bench, inspector).HandleAsync(Finding(800, "svchost.exe"));
        Assert.Equal(EvasionDecision.Protected, outcome.Decision);
        Assert.Empty(inspector.Described);
        Assert.Empty(bench.Raised);
    }

    [Fact]
    public async Task SingleCycle_GoesToUserDecision()
    {
        using var bench = new DispatcherBench();
        var path = bench.Tmp.Write(@"Users\Bob\AppData\Roaming\svc\svcupdate.exe", [0x4D, 0x5A, 0, 0]);
        bench.Host.Add(5100, 900, "svcupdate.exe", path);
        var inspector = new FakeInspector { Paths = { [5100] = path } };
        var outcome = await Watcher(bench, inspector).HandleAsync(Finding(5100, "svcupdate.exe"));

        Assert.Equal(EvasionDecision.AskUser, outcome.Decision);
        Assert.Equal(ThreatStatus.PendingDecision, outcome.Threat?.Status);
        Assert.Contains(MonitorEvasionWatcher.FindingHide, outcome.Threat!.Reason, StringComparison.Ordinal);
        Assert.Empty(bench.Host.Killed);
    }

    [Fact]
    public async Task RepeatedCycles_AreNeutralised()
    {
        using var bench = new DispatcherBench();
        var path = bench.Tmp.Write(@"Users\Bob\AppData\Roaming\svc\svcupdate.exe", [0x4D, 0x5A, 0, 0]);
        bench.Host.Add(5100, 900, "svcupdate.exe", path);
        var inspector = new FakeInspector { Paths = { [5100] = path } };
        var outcome = await Watcher(bench, inspector).HandleAsync(Finding(5100, "svcupdate.exe", cycles: 2));

        Assert.Equal(EvasionDecision.Act, outcome.Decision);
        Assert.Contains(5100, bench.Host.Killed);
    }

    [Fact]
    public async Task SecondCycle_ResolvesThePendingCard()
    {
        using var bench = new DispatcherBench();
        var path = bench.Tmp.Write(@"Users\Bob\AppData\Roaming\svc\svcupdate.exe", [0x4D, 0x5A, 0x90, 0]);
        bench.Host.Add(5100, 900, "svcupdate.exe", path);
        var analyzer = new FileAnalyzer(new SignatureEngine(RuleSet.Empty), new UnavailableSignatureVerifier());
        var watcher = Watcher(bench, new FakeInspector { Paths = { [5100] = path } }, analyzer);

        var first = await watcher.HandleAsync(Finding(5100, "svcupdate.exe"));
        Assert.Equal(ThreatStatus.PendingDecision, first.Threat?.Status);
        Assert.Empty(bench.Host.Killed);

        var second = await watcher.HandleAsync(Finding(5100, "svcupdate.exe", cycles: 2));
        Assert.Equal(EvasionDecision.Act, second.Decision);
        Assert.Equal(first.Threat!.Id, second.Threat?.Id);
        Assert.Contains(5100, bench.Host.Killed);
        Assert.False(File.Exists(path)); // образ в карантине — не перезапустится
        Assert.Empty(bench.Dispatcher.Pending());
    }

    [Fact]
    public async Task ShadowMode_NeverActs()
    {
        using var bench = new DispatcherBench();
        var path = bench.Tmp.Write(@"Users\Bob\AppData\Roaming\svc\svcupdate.exe", [0x4D, 0x5A, 0, 0]);
        bench.Host.Add(5100, 900, "svcupdate.exe", path);
        var outcome = await Watcher(bench, new FakeInspector { Paths = { [5100] = path } }, shadow: true)
            .HandleAsync(Finding(5100, "svcupdate.exe", cycles: 3));
        Assert.Equal(EvasionDecision.AskUser, outcome.Decision);
        Assert.Empty(bench.Host.Killed);
    }

    [Fact]
    public async Task WindowedApplication_OnlyLogged()
    {
        using var bench = new DispatcherBench();
        var path = bench.Tmp.Write(@"Games\game.exe", [0x4D, 0x5A, 0, 0]);
        var inspector = new FakeInspector { Paths = { [5200] = path }, UserObjects = 400 };
        var finding = Finding(5200, "game.exe") with { BaselineVariation = 0.4 };
        var outcome = await Watcher(bench, inspector).HandleAsync(finding);
        Assert.Equal(EvasionDecision.LogOnly, outcome.Decision);
        Assert.Empty(bench.Raised);
    }

    [Fact]
    public async Task AllowedProcess_IsSkipped()
    {
        using var bench = new DispatcherBench();
        var path = bench.Tmp.Write(@"Users\Bob\AppData\Roaming\svc\svcupdate.exe", [0x4D, 0x5A, 0, 0]);
        bench.Allowed.AddPath(path);
        var outcome = await Watcher(bench, new FakeInspector { Paths = { [5100] = path } }).HandleAsync(Finding(5100, "svcupdate.exe", cycles: 3));
        Assert.Equal(EvasionDecision.Allowed, outcome.Decision);
        Assert.Empty(bench.Raised);
    }

    [Fact]
    public async Task RuntimeWatcher_RecordsChain_AndQueuesDecision()
    {
        await using var b = new RuntimeBench();
        var path = b.Tmp.Write(@"Users\Bob\AppData\Roaming\svc\svcupdate.exe", [0x4D, 0x5A, 0x90, 0]);
        var watcher = b.Runtime.CreateMonitorEvasionWatcher(new NoSampler(), new FakeInspector { Paths = { [5100] = path } });
        var outcome = await watcher.HandleAsync(Finding(5100, "svcupdate.exe"));

        Assert.Equal(EvasionDecision.AskUser, outcome.Decision);
        Assert.Contains(b.Runtime.GetBehavioralStatus().RecentChains, c => c.Contains("Evasion: svcupdate.exe", StringComparison.Ordinal));
        Assert.Contains(watcher.Recent, r => r.Contains("svcupdate.exe", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ConfirmedNeutralisation_QuarantinesTheImage()
    {
        using var bench = new DispatcherBench();
        var path = bench.Tmp.Write(@"Users\Bob\AppData\Roaming\svc\svcupdate.exe", [0x4D, 0x5A, 0x90, 0, 3, 0, 0, 0]);
        bench.Host.Add(5100, 900, "svcupdate.exe", path);
        var analyzer = new FileAnalyzer(new SignatureEngine(RuleSet.Empty), new UnavailableSignatureVerifier());
        var outcome = await Watcher(bench, new FakeInspector { Paths = { [5100] = path } }, analyzer).HandleAsync(Finding(5100, "svcupdate.exe"));
        Assert.Equal(ThreatStatus.PendingDecision, outcome.Threat?.Status);

        var resolved = await bench.Dispatcher.ResolveAsync(outcome.Threat!.Id, ThreatDecision.Quarantine);
        Assert.Contains(5100, bench.Host.Killed);
        Assert.False(File.Exists(path));
        Assert.NotNull(resolved.QuarantineId);
    }
}
