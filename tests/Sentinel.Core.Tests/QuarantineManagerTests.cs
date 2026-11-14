using System.Text.Json;
using Sentinel.Core.Detection;
using Sentinel.Core.Hashing;
using Sentinel.Core.Remediation;
using Sentinel.Core.Testing;
using Sentinel.Core.Trust;

namespace Sentinel.Core.Tests;

/// <summary>Белый список для тестов: доверены только явно перечисленные пути.</summary>
internal sealed class FakeWhitelist(params string[] trusted) : IWhitelistProvider
{
    public List<string> Evaluated { get; } = [];

    public WhitelistDecision Evaluate(string path)
    {
        Evaluated.Add(path);
        return trusted.Contains(path, StringComparer.OrdinalIgnoreCase)
            ? new WhitelistDecision(true, "тестовый системный файл", null)
            : WhitelistDecision.No("не в списке");
    }

    public bool IsProtectedLocation(string path) => trusted.Contains(path, StringComparer.OrdinalIgnoreCase);
}

public class QuarantineManagerTests
{
    private static QuarantineManager Create(TempDir tmp, IWhitelistProvider? whitelist = null) =>
        new(whitelist ?? new FakeWhitelist(), new QuarantineOptions { QuarantineDirectory = Path.Combine(tmp.Path, "vault") });

    [Fact]
    public async Task Quarantine_MovesFile_XorsContent_AndWritesManifest()
    {
        using var tmp = new TempDir();
        var content = SyntheticArtifacts.BuildPe();
        var path = tmp.Write("stub.exe", content);
        var expectedSha = FileHasher.ComputeSha256(content);
        using var manager = Create(tmp);

        var result = await manager.QuarantineAsync(path, "Heuristic.Test");

        Assert.True(result.Success, result.Message);
        Assert.False(File.Exists(path));
        var record = result.Record!;
        Assert.Equal(path, record.OriginalPath);
        Assert.Equal(expectedSha, record.Sha256);
        Assert.Equal(content.Length, record.Size);
        Assert.Equal("Heuristic.Test", record.Reason);
        Assert.Equal(QuarantineState.Quarantined, record.State);

        var stored = File.ReadAllBytes(Path.Combine(manager.QuarantineDirectory, record.StoredFileName));
        Assert.Equal(content.Length, stored.Length);
        Assert.NotEqual((byte)'M', stored[0]);
        Assert.NotEqual((byte)'Z', stored[1]);
        // Ни один байт не остался прежним — контейнер не является ни PE, ни EICAR.
        Assert.DoesNotContain(true, content.Zip(stored, (a, b) => a == b));

        // Обратное преобразование ключом из манифеста даёт исходные байты.
        QuarantineManager.Xor(stored, Convert.FromBase64String(record.XorKey), 0);
        Assert.Equal(content, stored);
    }

    [Fact]
    public async Task Manifest_ContainsAllRequiredFields()
    {
        using var tmp = new TempDir();
        var path = tmp.Write("eicar.com", Eicar.CreateTestFileBytes());
        using var manager = Create(tmp);
        var record = (await manager.QuarantineAsync(path, "EICAR")).Record!;

        Assert.Equal("quarantine_manifest.json", Path.GetFileName(manager.ManifestPath));
        using var doc = JsonDocument.Parse(File.ReadAllText(manager.ManifestPath));
        var entry = Assert.Single(doc.RootElement.GetProperty("Entries").EnumerateArray());
        Assert.Equal(record.Id, entry.GetProperty("Id").GetString());
        Assert.Equal(path, entry.GetProperty("OriginalPath").GetString());
        Assert.Equal("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", entry.GetProperty("Sha256").GetString());
        Assert.Equal("EICAR", entry.GetProperty("Reason").GetString());
        Assert.False(string.IsNullOrEmpty(entry.GetProperty("XorKey").GetString()));
        Assert.True(entry.TryGetProperty("OriginalAttributes", out _));
        Assert.True(entry.TryGetProperty("QuarantinedAtUtc", out _));
        Assert.Equal("Quarantined", entry.GetProperty("State").GetString());
    }

    [Fact]
    public async Task ReadOnlyFile_IsQuarantined_AndAttributesRestored()
    {
        using var tmp = new TempDir();
        var content = Eicar.CreateTestFileBytes();
        var path = tmp.Write("locked.com", content);
        var stamp = new DateTime(2024, 3, 1, 12, 0, 0, DateTimeKind.Utc);
        File.SetLastWriteTimeUtc(path, stamp);
        File.SetAttributes(path, File.GetAttributes(path) | FileAttributes.ReadOnly);
        using var manager = Create(tmp);

        var q = await manager.QuarantineAsync(path, "test");
        Assert.True(q.Success, q.Message);
        Assert.True(q.Record!.OriginalAttributes.HasFlag(FileAttributes.ReadOnly));
        Assert.False(File.Exists(path));

        var r = await manager.RestoreAsync(q.Record.Id);
        Assert.True(r.Success, r.Message);
        Assert.Equal(content, File.ReadAllBytes(path));
        Assert.True(File.GetAttributes(path).HasFlag(FileAttributes.ReadOnly));
        Assert.Equal(stamp, File.GetLastWriteTimeUtc(path));

        File.SetAttributes(path, FileAttributes.Normal); // чтобы TempDir смог удалить файл
    }

    [WindowsFact]
    public async Task HiddenSystemAttributes_AreStrippedAndRestored_OnWindows()
    {
        using var tmp = new TempDir();
        var path = tmp.Write("hidden.com", Eicar.CreateTestFileBytes());
        File.SetAttributes(path, FileAttributes.Hidden | FileAttributes.System | FileAttributes.ReadOnly);
        using var manager = Create(tmp);

        var q = await manager.QuarantineAsync(path, "test");
        Assert.True(q.Success, q.Message);
        var r = await manager.RestoreAsync(q.Record!.Id);
        Assert.True(r.Success, r.Message);
        var attrs = File.GetAttributes(path);
        Assert.True(attrs.HasFlag(FileAttributes.Hidden | FileAttributes.System | FileAttributes.ReadOnly));
        File.SetAttributes(path, FileAttributes.Normal);
    }

    [Fact]
    public async Task WhitelistedSystemFile_IsNeverQuarantined()
    {
        using var tmp = new TempDir();
        var path = tmp.Write("kernel32.dll", SyntheticArtifacts.BuildPe(new() { IsDll = true }));
        File.SetAttributes(path, File.GetAttributes(path) | FileAttributes.ReadOnly);
        var before = File.GetAttributes(path);
        var whitelist = new FakeWhitelist(path);
        using var manager = Create(tmp, whitelist);

        var result = await manager.QuarantineAsync(path, "ложное срабатывание");

        Assert.Equal(QuarantineStatus.BlockedByWhitelist, result.Status);
        Assert.Null(result.Record);
        Assert.True(File.Exists(path));
        Assert.Equal(before, File.GetAttributes(path)); // атрибуты не тронуты
        Assert.False(Directory.Exists(manager.QuarantineDirectory)); // ни каталога, ни манифеста
        Assert.Contains(path, whitelist.Evaluated);
        File.SetAttributes(path, FileAttributes.Normal);
    }

    [Fact]
    public async Task RealSystemWhitelist_BlocksSignedMicrosoftFile_ButNotUnsignedPlantedOne()
    {
        using var tmp = new TempDir();
        var system32 = Path.Combine(tmp.Path, "Windows", "System32");
        var signed = tmp.Write(Path.Combine("Windows", "System32", "signed.dll"), SyntheticArtifacts.BuildPe(new() { IsDll = true }));
        var planted = tmp.Write(Path.Combine("Windows", "System32", "planted.dll"), SyntheticArtifacts.BuildPe(new() { IsDll = true, Seed = 7 }));
        var verifier = new FakeVerifier(p => p == signed
            ? new SignatureVerificationResult(SignatureStatus.Valid, SignatureSource.Catalog, "CN=Microsoft Windows, O=Microsoft Corporation", null, null, null, 0, "ok")
            : new SignatureVerificationResult(SignatureStatus.NotSigned, SignatureSource.None, null, null, null, null, 0, "нет подписи"));
        var whitelist = new SystemWhitelist(verifier, new WhitelistOptions { ProtectedDirectories = [system32] });
        using var manager = Create(tmp, whitelist);

        Assert.Equal(QuarantineStatus.BlockedByWhitelist, (await manager.QuarantineAsync(signed, "x")).Status);
        Assert.True((await manager.QuarantineAsync(planted, "x")).Success);
        Assert.True(File.Exists(signed));
        Assert.False(File.Exists(planted));
    }

    [Fact]
    public async Task DryRun_ChangesNothing()
    {
        using var tmp = new TempDir();
        var path = tmp.Write("eicar.com", Eicar.CreateTestFileBytes());
        using var manager = Create(tmp);

        var result = await manager.QuarantineAsync(path, "test", dryRun: true);

        Assert.Equal(QuarantineStatus.WouldQuarantine, result.Status);
        Assert.False(result.Success);
        Assert.True(File.Exists(path));
        Assert.False(Directory.Exists(manager.QuarantineDirectory));
        Assert.Empty(await manager.ListAsync());
    }

    [Fact]
    public async Task MissingFile_Directory_AndVaultContent_AreRejected()
    {
        using var tmp = new TempDir();
        using var manager = Create(tmp);
        Assert.Equal(QuarantineStatus.NotFound, (await manager.QuarantineAsync(Path.Combine(tmp.Path, "nope.exe"), "x")).Status);
        Assert.Equal(QuarantineStatus.NotFound, (await manager.QuarantineAsync(tmp.Path, "x")).Status);

        var record = (await manager.QuarantineAsync(tmp.Write("a.com", Eicar.CreateTestFileBytes()), "x")).Record!;
        var container = Path.Combine(manager.QuarantineDirectory, record.StoredFileName);
        Assert.Equal(QuarantineStatus.Failed, (await manager.QuarantineAsync(container, "x")).Status);
        Assert.True(File.Exists(container));
    }

    [Fact]
    public async Task Restore_ReturnsFileToOriginalPlace_AndMarksRecord()
    {
        using var tmp = new TempDir();
        var content = SyntheticArtifacts.BuildPe(new() { HighEntropyText = true, TextSize = 0x30000 });
        var path = tmp.Write(Path.Combine("deep", "dir", "packed.exe"), content);
        using var manager = Create(tmp);
        var record = (await manager.QuarantineAsync(path, "packed")).Record!;
        Directory.Delete(Path.GetDirectoryName(path)!); // исходный каталог исчез — должен быть воссоздан

        var result = await manager.RestoreAsync(record.Id[..8]); // уникальный префикс

        Assert.True(result.Success, result.Message);
        Assert.Equal(content, File.ReadAllBytes(path));
        Assert.Equal(record.Sha256, FileHasher.ComputeSha256(path));
        Assert.False(File.Exists(Path.Combine(manager.QuarantineDirectory, record.StoredFileName)));

        var listed = Assert.Single(await manager.ListAsync());
        Assert.Equal(QuarantineState.Restored, listed.State);
        Assert.NotNull(listed.RestoredAtUtc);
        Assert.Equal(RestoreStatus.AlreadyRestored, (await manager.RestoreAsync(record.Id)).Status);
    }

    [Fact]
    public async Task Restore_UnknownId_IsNotFound()
    {
        using var tmp = new TempDir();
        using var manager = Create(tmp);
        Assert.Equal(RestoreStatus.NotFound, (await manager.RestoreAsync("deadbeefdeadbeef")).Status);
    }

    [Fact]
    public async Task Restore_TamperedContainer_FailsHashCheck_AndLeavesNothingBehind()
    {
        using var tmp = new TempDir();
        var path = tmp.Write("eicar.com", Eicar.CreateTestFileBytes());
        using var manager = Create(tmp);
        var record = (await manager.QuarantineAsync(path, "x")).Record!;
        var container = Path.Combine(manager.QuarantineDirectory, record.StoredFileName);
        var bytes = File.ReadAllBytes(container);
        bytes[5] ^= 0xFF;
        File.WriteAllBytes(container, bytes);

        var result = await manager.RestoreAsync(record.Id);

        Assert.Equal(RestoreStatus.HashMismatch, result.Status);
        Assert.False(File.Exists(path));
        Assert.Empty(Directory.GetFiles(tmp.Path)); // временных файлов восстановления не осталось
        Assert.True(File.Exists(container)); // контейнер сохранён для разбора
        Assert.Equal(QuarantineState.Quarantined, Assert.Single(await manager.ListAsync()).State);
    }

    [Fact]
    public async Task Restore_DoesNotOverwriteExistingFile_UnlessAllowed()
    {
        using var tmp = new TempDir();
        var original = Eicar.CreateTestFileBytes();
        var path = tmp.Write("eicar.com", original);
        using var manager = Create(tmp);
        var record = (await manager.QuarantineAsync(path, "x")).Record!;
        File.WriteAllText(path, "новый файл на том же месте");

        Assert.Equal(RestoreStatus.TargetExists, (await manager.RestoreAsync(record.Id)).Status);
        Assert.Equal("новый файл на том же месте", File.ReadAllText(path));

        Assert.True((await manager.RestoreAsync(record.Id, overwrite: true)).Success);
        Assert.Equal(original, File.ReadAllBytes(path));
    }

    [Fact]
    public async Task MultipleFiles_GetDistinctRecords_AndSurviveManagerRestart()
    {
        using var tmp = new TempDir();
        var a = tmp.Write("a.com", Eicar.CreateTestFileBytes());
        var b = tmp.Write("b.exe", SyntheticArtifacts.BuildPe());
        QuarantineRecord ra, rb;
        using (var first = Create(tmp))
        {
            ra = (await first.QuarantineAsync(a, "A")).Record!;
            rb = (await first.QuarantineAsync(b, "B")).Record!;
        }

        Assert.NotEqual(ra.Id, rb.Id);
        Assert.NotEqual(ra.XorKey, rb.XorKey);

        using var second = Create(tmp); // новый экземпляр читает манифест с диска
        Assert.Equal(2, (await second.ListAsync()).Count);
        Assert.True((await second.RestoreAsync(rb.Id)).Success);
        Assert.True(File.Exists(b));
        Assert.False(File.Exists(a));
    }

    [Fact]
    public async Task LargeFile_SpanningManyBuffers_RoundTrips()
    {
        using var tmp = new TempDir();
        var content = new byte[(1 << 16) * 3 + 12345];
        new Random(42).NextBytes(content);
        var path = tmp.Write("big.bin", content);
        using var manager = Create(tmp);

        var record = (await manager.QuarantineAsync(path, "big")).Record!;
        Assert.Equal(FileHasher.ComputeSha256(content), record.Sha256);
        Assert.True((await manager.RestoreAsync(record.Id)).Success);
        Assert.Equal(content, File.ReadAllBytes(path));
    }

    [Fact]
    public async Task VaultDirectory_AndContainer_HaveRestrictedUnixPermissions()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var tmp = new TempDir();
        var path = tmp.Write("run.sh", "#!/bin/sh\n"u8.ToArray());
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        using var manager = Create(tmp);
        var record = (await manager.QuarantineAsync(path, "x")).Record!;

        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, File.GetUnixFileMode(manager.QuarantineDirectory));
        var containerMode = File.GetUnixFileMode(Path.Combine(manager.QuarantineDirectory, record.StoredFileName));
        Assert.Equal(UnixFileMode.None, containerMode & (UnixFileMode.UserExecute | UnixFileMode.GroupExecute | UnixFileMode.OtherExecute));

        Assert.True((await manager.RestoreAsync(record.Id)).Success);
        Assert.True(File.GetUnixFileMode(path).HasFlag(UnixFileMode.UserExecute)); // бит исполнения возвращён
    }
}
