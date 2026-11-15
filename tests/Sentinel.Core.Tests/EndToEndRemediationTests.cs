using System.Text.Json;
using Sentinel.Core.Audit.Config;
using Sentinel.Core.Audit.Persistence;
using Sentinel.Core.Audit.Persistence.Registry;
using Sentinel.Core.Audit.Process;
using Sentinel.Core.Detection;
using Sentinel.Core.Hashing;
using Sentinel.Core.Remediation;
using Sentinel.Core.Reporting;
using Sentinel.Core.Scanning;
using Sentinel.Core.Signatures;
using Sentinel.Core.Testing;
using Sentinel.Core.Trust;

namespace Sentinel.Core.Tests;

/// <summary>
/// Имитация MSFT_MpPreference поверх реестра в памяти: Remove/Add меняют те же ключи,
/// которые читает <see cref="ConfigIntegrityAuditor"/>, поэтому повторный аудит видит результат.
/// </summary>
internal sealed class RegistryBackedDefender(InMemoryRegistryProvider registry) : IDefenderPreferenceProvider
{
    private const string Root = @"SOFTWARE\Microsoft\Windows Defender\Exclusions\";

    public List<string> Calls { get; } = [];

    private static RegistryKeyPath Key(DefenderExclusionKind kind) => new(RegistryHive.LocalMachine, Root + kind switch
    {
        DefenderExclusionKind.Path => "Paths",
        DefenderExclusionKind.Process => "Processes",
        DefenderExclusionKind.Extension => "Extensions",
        _ => "IpAddresses",
    });

    public ProviderResult RemoveExclusion(DefenderExclusionKind kind, string value)
    {
        Calls.Add($"MSFT_MpPreference.Remove({kind}={value})");
        return registry.DeleteValue(Key(kind), value) ? ProviderResult.Ok : ProviderResult.Fail("исключение не найдено");
    }

    public ProviderResult AddExclusion(DefenderExclusionKind kind, string value)
    {
        Calls.Add($"MSFT_MpPreference.Add({kind}={value})");
        registry.Set(Key(kind), value, "0", RegistryValueKind.Dword);
        return ProviderResult.Ok;
    }
}

/// <summary>
/// Сквозной цикл: обнаружение исключения и файла → завершение процесса → изоляция в карантин →
/// откат исключений и реестра → восстановление из манифестов → HTML/JSON-отчёты.
/// </summary>
public class EndToEndRemediationTests
{
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string ExclusionsRoot = @"SOFTWARE\Microsoft\Windows Defender\Exclusions\";
    private const string MsSubject = "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US";
    private const int MinerPid = 4100;
    private const int WorkerPid = 4101;
    private const int ExplorerPid = 900;

    private sealed class Scenario : IDisposable
    {
        public TempDir Tmp { get; } = new();
        public InMemoryRegistryProvider Registry { get; } = new();
        public FakeProcessHost Host { get; } = new();
        public RegistryBackedDefender Defender { get; }
        public SystemWhitelist Whitelist { get; }
        public FileAnalyzer Analyzer { get; }

        public string ExcludedDir { get; }
        public string Miner { get; }
        public string Dropper { get; }
        public string SystemDll { get; }
        public string Hosts { get; }
        public byte[] MinerBytes { get; } = Eicar.CreateTestFileBytes();
        public byte[] DropperBytes { get; } = SyntheticArtifacts.BuildPe(new() { HighEntropyText = true, TextSize = 0x4000 });

        public const string HostsOriginal = "127.0.0.1 localhost\r\n203.0.113.9 wdcp.microsoft.com\r\n";

        public RegistryKeyPath Run { get; } = new(RegistryHive.CurrentUser, RunKey);
        public RegistryKeyPath ExclPaths { get; } = new(RegistryHive.LocalMachine, ExclusionsRoot + "Paths");
        public RegistryKeyPath ExclProcesses { get; } = new(RegistryHive.LocalMachine, ExclusionsRoot + "Processes");
        public RegistryKeyPath ExclExtensions { get; } = new(RegistryHive.LocalMachine, ExclusionsRoot + "Extensions");

        public string DataDir => Path.Combine(Tmp.Path, "sentinel-data");

        public Scenario()
        {
            Defender = new RegistryBackedDefender(Registry);

            // «Заражённая» система: каталог скрыт от Defender, в нём работающий «майнер» (EICAR) и упакованный дроппер.
            ExcludedDir = Path.Combine(Tmp.Path, "Users", "Public", "Libraries");
            Miner = Tmp.Write(Path.Combine("Users", "Public", "Libraries", "svchost.exe"), MinerBytes);
            Dropper = Tmp.Write(Path.Combine("Users", "Public", "Libraries", "upd", "dropper.exe"), DropperBytes);
            Tmp.WriteText(Path.Combine("Users", "Public", "Libraries", "readme.txt"), "ничего интересного");
            File.SetAttributes(Miner, File.GetAttributes(Miner) | FileAttributes.ReadOnly);

            // Легитимный системный файл в том же «исключённом» дереве трогать нельзя.
            var system32 = Path.Combine(Tmp.Path, "Users", "Public", "Libraries", "System32");
            SystemDll = Tmp.Write(Path.Combine("Users", "Public", "Libraries", "System32", "kernel32.dll"), SyntheticArtifacts.BuildPe(new() { IsDll = true }));
            var verifier = new FakeVerifier(p => p == SystemDll
                ? new SignatureVerificationResult(SignatureStatus.Valid, SignatureSource.Catalog, MsSubject, null, null, null, 0, "ok")
                : new SignatureVerificationResult(SignatureStatus.NotSigned, SignatureSource.None, null, null, null, null, 0, "нет подписи"));
            Whitelist = new SystemWhitelist(verifier, new WhitelistOptions { ProtectedDirectories = [system32] });
            Analyzer = new FileAnalyzer(new SignatureEngine(RuleLoader.LoadDirectory(RepoPaths.RulesDirectory)), verifier, Whitelist);

            Registry.Set(ExclPaths, ExcludedDir, "0", RegistryValueKind.Dword);
            Registry.Set(ExclProcesses, "powershell.exe", "0", RegistryValueKind.Dword);
            Registry.Set(ExclExtensions, "exe", "0", RegistryValueKind.Dword);
            Registry.Set(Run, "WindowsUpdateSvc", Miner);
            Hosts = Tmp.WriteText("hosts", HostsOriginal);

            // Родитель носит системное имя вне штатного каталога (находка High), но исключениями не скрыт:
            // обработка конфигурации не должна его затрагивать.
            Host.Add(ExplorerPid, 1, "explorer.exe", Path.Combine(Tmp.Path, "explorer.exe"))
                .Add(MinerPid, ExplorerPid, "svchost.exe", Miner)
                .Add(WorkerPid, MinerPid, "worker.exe", Dropper)
                .Add(5000, ExplorerPid, "notepad.exe", Path.Combine(Tmp.Path, "notepad.exe"));
        }

        public PersistenceAuditorOptions PersistenceOptions => new() { HostsFilePath = Hosts };

        public (SentinelReport Report, QuarantineManager Quarantine, RemediationEngine Engine) Run_(bool remediate, bool dryRun)
        {
            var started = DateTime.UtcNow;
            var builder = new ReportBuilder("e2e" + (remediate ? " --remediate" : string.Empty) + (dryRun ? " --dry-run" : string.Empty), started);

            // 1. Обнаружение: конфигурация → исключения → приоритетная проверка файлов и процессов → автозагрузка.
            var config = new ConfigIntegrityAuditor(new ConfigIntegrityAuditorOptions(), Registry).Audit();
            var scanner = new ExclusionPriorityScanner(Analyzer, new ProcessAuditor(new ProcessAuditorOptions(), Analyzer));
            var exclusionScan = scanner.Scan(config.DefenderExclusions, Host.GetProcesses());
            var persistence = new PersistenceAuditor(PersistenceOptions, Registry, analyzer: Analyzer).Audit();

            builder.AddConfigAudit(config).AddExclusionScan(exclusionScan);
            foreach (var p in exclusionScan.ExcludedProcesses)
            {
                builder.AddProcessFinding(p, "Процессы под исключениями Defender");
            }

            builder.AddPersistenceAudit(persistence);

            // 2. Реагирование.
            var quarantine = new QuarantineManager(Whitelist, new QuarantineOptions { QuarantineDirectory = Path.Combine(DataDir, "Quarantine") });
            var engine = new RemediationEngine(
                Whitelist,
                new RemediationOptions { RollbackManifestPath = Path.Combine(DataDir, "rollback_manifest.json"), DryRun = dryRun, CurrentProcessId = 999_999 },
                Host, Host, Registry, new FakeTaskEditor(), Defender);
            if (remediate)
            {
                var coordinator = new ResponseCoordinator(quarantine, engine, builder, new ResponsePolicy { DryRun = dryRun });
                coordinator.HandleConfigAsync(config, exclusionScan).GetAwaiter().GetResult();
                coordinator.HandlePersistenceAsync(persistence).GetAwaiter().GetResult();
            }

            var mode = !remediate ? "audit" : dryRun ? "dry-run" : "remediate";
            return (builder.Build(DateTime.UtcNow - started, mode), quarantine, engine);
        }

        public void Dispose()
        {
            foreach (var f in new[] { Miner })
            {
                if (File.Exists(f))
                {
                    File.SetAttributes(f, FileAttributes.Normal);
                }
            }

            Tmp.Dispose();
        }
    }

    [Fact]
    public void Detection_FindsExclusions_HiddenFiles_Processes_AndPersistence()
    {
        using var s = new Scenario();
        var (report, quarantine, _) = s.Run_(remediate: false, dryRun: false);
        using var q = quarantine;

        Assert.Equal("audit", report.Mode);
        Assert.Equal(3, report.Findings.Count(f => f.Key.StartsWith("excl:", StringComparison.Ordinal)));
        Assert.Contains(report.Findings, f => f.Path == s.Miner && f.Sha256 == FileHasher.ComputeSha256(s.MinerBytes) && f.Severity == Severity.High);
        Assert.Contains(report.Findings, f => f.Path == s.Dropper && f.Rule.Contains("Heuristic.PackedUnsignedPE", StringComparison.Ordinal));
        Assert.Contains(report.Findings, f => f.Key == ReportBuilder.ProcessKey(MinerPid) && f.Rule.Contains("PROC-DEFENDER-EXCLUDED", StringComparison.Ordinal));
        Assert.Contains(report.Findings, f => f.Area == "Автозагрузка" && f.Name.StartsWith("WindowsUpdateSvc", StringComparison.Ordinal));
        Assert.Contains(report.Findings, f => f.Rule.Contains("PERS-HOSTS-SECURITY", StringComparison.Ordinal));
        Assert.DoesNotContain(report.Findings, f => f.Path == s.SystemDll); // доверенный системный файл не является находкой
        Assert.All(report.Findings, f => Assert.Equal(FindingActionStatus.Detected, f.ActionStatus));
        Assert.False(Directory.Exists(s.DataDir));
    }

    [Fact]
    public void DryRun_PlansEverything_ButChangesNothing()
    {
        using var s = new Scenario();
        var (report, quarantine, engine) = s.Run_(remediate: true, dryRun: true);
        using var q = quarantine;

        Assert.Equal("dry-run", report.Mode);
        Assert.True(report.Findings.Count(f => f.ActionStatus == FindingActionStatus.Planned) >= 7);
        Assert.Equal(0, report.Quarantined + report.ConfigCleaned + report.ProcessesTerminated);

        Assert.True(File.Exists(s.Miner));
        Assert.True(File.GetAttributes(s.Miner).HasFlag(FileAttributes.ReadOnly));
        Assert.True(File.Exists(s.Dropper));
        Assert.Empty(s.Host.Killed);
        Assert.Empty(s.Defender.Calls);
        Assert.NotNull(s.Registry.GetValue(s.Run, "WindowsUpdateSvc"));
        Assert.NotNull(s.Registry.GetValue(s.ExclPaths, s.ExcludedDir));
        Assert.Equal(Scenario.HostsOriginal, File.ReadAllText(s.Hosts));
        Assert.False(Directory.Exists(s.DataDir));
        Assert.Empty(engine.ListRollbackEntries());
    }

    [Fact]
    public async Task FullCycle_Detect_Terminate_Quarantine_Rollback_Report_Restore()
    {
        using var s = new Scenario();
        var minerSha = FileHasher.ComputeSha256(s.MinerBytes);
        var dropperSha = FileHasher.ComputeSha256(s.DropperBytes);

        var (report, quarantine, engine) = s.Run_(remediate: true, dryRun: false);
        using var q = quarantine;

        // --- Процессы: дерево майнера остановлено, посторонние процессы живы -----
        Assert.Equal([MinerPid, WorkerPid], s.Host.Killed.ToArray());
        Assert.True(s.Host.IsRunning(ExplorerPid));
        Assert.True(s.Host.IsRunning(5000));
        Assert.Equal(FindingActionStatus.Terminated, report.Findings.Single(f => f.Key == ReportBuilder.ProcessKey(MinerPid)).ActionStatus);

        // --- Карантин: вредоносные файлы изолированы, системный и безобидный — на месте
        Assert.False(File.Exists(s.Miner));
        Assert.False(File.Exists(s.Dropper));
        Assert.True(File.Exists(s.SystemDll));
        Assert.True(File.Exists(Path.Combine(s.ExcludedDir, "readme.txt")));
        var records = await quarantine.ListAsync();
        Assert.Equal(2, records.Count);
        var minerRecord = records.Single(r => r.OriginalPath == s.Miner);
        Assert.Equal(minerSha, minerRecord.Sha256);
        Assert.True(minerRecord.OriginalAttributes.HasFlag(FileAttributes.ReadOnly));
        Assert.Equal(dropperSha, records.Single(r => r.OriginalPath == s.Dropper).Sha256);
        Assert.All(records, r => Assert.NotEqual(r.Sha256,
            FileHasher.ComputeSha256(Path.Combine(quarantine.QuarantineDirectory, r.StoredFileName)))); // в хранилище — не исходные байты
        Assert.Equal(2, report.Quarantined);

        // --- Исключения Defender удалены через MSFT_MpPreference.Remove ---------
        Assert.Equal(3, s.Defender.Calls.Count(c => c.StartsWith("MSFT_MpPreference.Remove", StringComparison.Ordinal)));
        Assert.Empty(new ConfigIntegrityAuditor(new ConfigIntegrityAuditorOptions(), s.Registry).Audit().DefenderExclusions);

        // --- Автозагрузка и hosts возвращены к эталону --------------------------
        Assert.Null(s.Registry.GetValue(s.Run, "WindowsUpdateSvc"));
        Assert.Equal("127.0.0.1 localhost\r\n", File.ReadAllText(s.Hosts));
        Assert.Equal(0, new PersistenceAuditor(s.PersistenceOptions, s.Registry, analyzer: s.Analyzer).Audit().FlaggedCount);
        Assert.Equal(5, report.ConfigCleaned); // 3 исключения + Run + hosts

        // --- Манифест отката: резервные копии всех изменённых параметров --------
        var backups = engine.ListRollbackEntries();
        Assert.Equal(5, backups.Count);
        Assert.Equal(3, backups.Count(b => b.Kind == RollbackKind.DefenderExclusion));
        Assert.Contains(backups, b => b.Kind == RollbackKind.RegistryValue && b.Name == "WindowsUpdateSvc" && b.PreviousValue == s.Miner);
        Assert.Contains(backups, b => b.Kind == RollbackKind.HostsFile && b.PreviousValue == Scenario.HostsOriginal);

        // --- Отчёты ------------------------------------------------------------
        var htmlPath = Path.Combine(s.Tmp.Path, "reports", "report.html");
        var jsonPath = Path.Combine(s.Tmp.Path, "reports", "report.json");
        ReportGenerator.WriteHtml(report, htmlPath);
        ReportGenerator.WriteJson(report, jsonPath);

        using (var doc = JsonDocument.Parse(File.ReadAllText(jsonPath)))
        {
            var root = doc.RootElement;
            Assert.Equal("remediate", root.GetProperty("Mode").GetString());
            Assert.Equal(2, root.GetProperty("Quarantined").GetInt32());
            Assert.Equal(5, root.GetProperty("ConfigCleaned").GetInt32());
            Assert.Equal(1, root.GetProperty("ProcessesTerminated").GetInt32());
            var miner = root.GetProperty("Findings").EnumerateArray().Single(f => f.GetProperty("Path").GetString() == s.Miner
                && f.GetProperty("Key").GetString()!.StartsWith("file:", StringComparison.Ordinal));
            Assert.Equal(minerSha, miner.GetProperty("Sha256").GetString());
            Assert.Equal("Quarantined", miner.GetProperty("ActionStatus").GetString());
            Assert.Equal("High", miner.GetProperty("Severity").GetString());
            Assert.True(root.GetProperty("Actions").GetArrayLength() >= 5);
        }

        var html = File.ReadAllText(htmlPath);
        Assert.Contains(minerSha, html);
        Assert.Contains(System.Net.WebUtility.HtmlEncode(s.Miner), html);
        Assert.Contains("data-status=\"Quarantined\"", html);
        Assert.Contains("data-status=\"Cleaned\"", html);
        Assert.Contains("data-status=\"Terminated\"", html);
        Assert.Contains("NotSigned", html);
        Assert.Contains("ExclusionPath", html);
        Assert.DoesNotContain("http://", html);
        Assert.DoesNotContain("https://", html);

        // --- Восстановление из манифестов: система возвращается в исходное состояние
        foreach (var record in records)
        {
            var restored = await quarantine.RestoreAsync(record.Id);
            Assert.True(restored.Success, restored.Message);
        }

        Assert.Equal(s.MinerBytes, File.ReadAllBytes(s.Miner));
        Assert.True(File.GetAttributes(s.Miner).HasFlag(FileAttributes.ReadOnly));
        Assert.Equal(s.DropperBytes, File.ReadAllBytes(s.Dropper));

        foreach (var backup in backups)
        {
            var undo = engine.Undo(backup.Id);
            Assert.True(undo.Success, undo.Message);
        }

        Assert.Equal(s.Miner, s.Registry.GetValue(s.Run, "WindowsUpdateSvc")!.Value);
        Assert.Equal(Scenario.HostsOriginal, File.ReadAllText(s.Hosts));
        Assert.Equal(3, new ConfigIntegrityAuditor(new ConfigIntegrityAuditorOptions(), s.Registry).Audit().DefenderExclusions.Count);
        Assert.All(engine.ListRollbackEntries(), b => Assert.NotNull(b.UndoneAtUtc));
        Assert.All(await quarantine.ListAsync(), r => Assert.Equal(QuarantineState.Restored, r.State));
    }

    [Fact]
    public async Task WhitelistedSystemFile_SurvivesRemediation_EvenWhenExplicitlyTargeted()
    {
        using var s = new Scenario();
        var (report, quarantine, engine) = s.Run_(remediate: true, dryRun: false);
        using var q = quarantine;

        // Прямая попытка изолировать подписанный системный файл и завершить его процесс.
        var blocked = await quarantine.QuarantineAsync(s.SystemDll, "ручной запрос");
        Assert.Equal(QuarantineStatus.BlockedByWhitelist, blocked.Status);
        Assert.True(File.Exists(s.SystemDll));

        s.Host.Add(7000, 4, "lsass.exe", s.SystemDll);
        Assert.Equal(RemediationStatus.Blocked, engine.TerminateProcessTree(7000).Status);
        Assert.True(s.Host.IsRunning(7000));
        Assert.DoesNotContain(report.Findings, f => f.Path == s.SystemDll);
    }
}
