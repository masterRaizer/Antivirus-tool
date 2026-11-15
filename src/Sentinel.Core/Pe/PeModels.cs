namespace Sentinel.Core.Pe;

public enum PeMachine : ushort
{
    Unknown = 0x0000,
    I386 = 0x014c,
    Arm = 0x01c0,
    ArmNt = 0x01c4,
    Amd64 = 0x8664,
    Arm64 = 0xaa64,
}

public enum PeSubsystem : ushort
{
    Unknown = 0,
    Native = 1,
    WindowsGui = 2,
    WindowsCui = 3,
    EfiApplication = 10,
    EfiBootServiceDriver = 11,
    EfiRuntimeDriver = 12,
}

[Flags]
public enum SectionCharacteristics : uint
{
    None = 0,
    Code = 0x0000_0020,
    InitializedData = 0x0000_0040,
    UninitializedData = 0x0000_0080,
    Discardable = 0x0200_0000,
    Shared = 0x1000_0000,
    Execute = 0x2000_0000,
    Read = 0x4000_0000,
    Write = 0x8000_0000,
}

public sealed record PeSection(
    string Name,
    uint VirtualAddress,
    uint VirtualSize,
    uint PointerToRawData,
    uint SizeOfRawData,
    SectionCharacteristics Characteristics,
    double Entropy)
{
    public bool IsExecutable => Characteristics.HasFlag(SectionCharacteristics.Execute) || Characteristics.HasFlag(SectionCharacteristics.Code);
    public bool IsWritable => Characteristics.HasFlag(SectionCharacteristics.Write);

    public bool ContainsRva(uint rva)
    {
        var size = Math.Max(VirtualSize, SizeOfRawData);
        return rva >= VirtualAddress && rva < (ulong)VirtualAddress + size;
    }
}

public sealed record PeDataDirectory(uint VirtualAddress, uint Size)
{
    public bool IsPresent => VirtualAddress != 0 && Size != 0;
}

public sealed record PeInfo
{
    public required PeMachine Machine { get; init; }
    public required bool Is64Bit { get; init; }
    public required bool IsDll { get; init; }
    public required PeSubsystem Subsystem { get; init; }
    public required DateTimeOffset TimeDateStamp { get; init; }
    public required uint EntryPointRva { get; init; }
    public required ulong ImageBase { get; init; }
    public required uint SizeOfImage { get; init; }
    public required uint CheckSum { get; init; }
    public required ushort Characteristics { get; init; }
    public required ushort DllCharacteristics { get; init; }
    public required IReadOnlyList<PeSection> Sections { get; init; }
    public required IReadOnlyList<PeDataDirectory> DataDirectories { get; init; }
    public required long OverlayOffset { get; init; }
    public required long OverlaySize { get; init; }
    public required IReadOnlyList<string> Anomalies { get; init; }

    public bool IsDriver => Subsystem == PeSubsystem.Native;

    /// <summary>Управляемая (.NET) сборка: заполнен IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR (индекс 14).</summary>
    public bool IsManaged => DataDirectories.Count > 14 && DataDirectories[14].IsPresent;
    public PeSection? EntryPointSection => Sections.FirstOrDefault(s => s.ContainsRva(EntryPointRva));

    /// <summary>Наличие каталога IMAGE_DIRECTORY_ENTRY_SECURITY (Authenticode).</summary>
    public bool HasAuthenticodeDirectory => DataDirectories.Count > 4 && DataDirectories[4].IsPresent;

    /// <summary>Флаг IMAGE_FILE_DLL_CHARACTERISTICS_FORCE_INTEGRITY — образ требует проверки подписи.</summary>
    public bool ForceIntegrity => (DllCharacteristics & 0x0080) != 0;
}

public sealed record PeParseResult(bool IsPe, PeInfo? Info, string? Error)
{
    public static PeParseResult NotPe(string reason) => new(false, null, reason);
    public static PeParseResult Success(PeInfo info) => new(true, info, null);
}
