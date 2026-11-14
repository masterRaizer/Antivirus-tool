using System.Buffers.Binary;
using System.Text;

namespace Sentinel.Core.Testing;

/// <summary>
/// Генератор безопасных синтетических артефактов для автотестов и самопроверки:
/// PE-заглушки без исполняемого кода (секция заполнена случайными байтами или RET/нулями)
/// и тестовые строки. Никакой реальной вредоносной функциональности.
/// </summary>
public static class SyntheticArtifacts
{
    public const int FileAlignment = 0x200;
    public const int SectionAlignment = 0x1000;

    public sealed record PeOptions
    {
        public bool Is64Bit { get; init; } = true;
        public bool IsDll { get; init; }
        public bool HighEntropyText { get; init; }
        public bool WritableText { get; init; }
        public int TextSize { get; init; } = 0x1000;
        public bool AddDataSection { get; init; } = true;
        public byte[] DataContent { get; init; } = [];
        public int OverlaySize { get; init; }
        public uint? EntryPointOverride { get; init; }
        public int Seed { get; init; } = 1337;
    }

    public static byte[] BuildPe(PeOptions? options = null)
    {
        var o = options ?? new PeOptions();
        var rng = new Random(o.Seed);
        var sectionCount = o.AddDataSection ? 2 : 1;
        var optionalSize = o.Is64Bit ? 240 : 224;
        const int peOffset = 0x40;
        var headersRaw = Align(peOffset + 24 + optionalSize + (sectionCount * 40), FileAlignment);

        var textRaw = Align(o.TextSize, FileAlignment);
        var dataContent = o.DataContent.Length > 0 ? o.DataContent : Encoding.ASCII.GetBytes("synthetic data section");
        var dataRaw = o.AddDataSection ? Align(dataContent.Length, FileAlignment) : 0;
        var textVa = SectionAlignment;
        var dataVa = textVa + Align(o.TextSize, SectionAlignment);
        var sizeOfImage = (o.AddDataSection ? dataVa + Align(dataContent.Length, SectionAlignment) : dataVa);

        var file = new byte[headersRaw + textRaw + dataRaw + o.OverlaySize];
        var span = file.AsSpan();

        // IMAGE_DOS_HEADER
        span[0] = (byte)'M';
        span[1] = (byte)'Z';
        BinaryPrimitives.WriteInt32LittleEndian(span[0x3C..], peOffset);

        // PE\0\0 + IMAGE_FILE_HEADER
        var nt = span[peOffset..];
        BinaryPrimitives.WriteUInt32LittleEndian(nt, 0x0000_4550);
        BinaryPrimitives.WriteUInt16LittleEndian(nt[4..], o.Is64Bit ? (ushort)0x8664 : (ushort)0x014C);
        BinaryPrimitives.WriteUInt16LittleEndian(nt[6..], (ushort)sectionCount);
        BinaryPrimitives.WriteUInt32LittleEndian(nt[8..], 0x6500_0000);
        BinaryPrimitives.WriteUInt16LittleEndian(nt[20..], (ushort)optionalSize);
        ushort characteristics = 0x0002; // EXECUTABLE_IMAGE
        characteristics |= o.Is64Bit ? (ushort)0x0020 : (ushort)0x0100; // LARGE_ADDRESS_AWARE / 32BIT_MACHINE
        if (o.IsDll)
        {
            characteristics |= 0x2000;
        }

        BinaryPrimitives.WriteUInt16LittleEndian(nt[22..], characteristics);

        // Optional header
        var opt = nt[24..];
        BinaryPrimitives.WriteUInt16LittleEndian(opt, o.Is64Bit ? (ushort)0x020B : (ushort)0x010B);
        BinaryPrimitives.WriteUInt32LittleEndian(opt[4..], (uint)textRaw);              // SizeOfCode
        BinaryPrimitives.WriteUInt32LittleEndian(opt[16..], o.EntryPointOverride ?? (uint)textVa);
        BinaryPrimitives.WriteUInt32LittleEndian(opt[20..], (uint)textVa);              // BaseOfCode
        if (o.Is64Bit)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(opt[24..], 0x1_4000_0000UL);
        }
        else
        {
            BinaryPrimitives.WriteUInt32LittleEndian(opt[28..], 0x0040_0000);
        }

        BinaryPrimitives.WriteUInt32LittleEndian(opt[32..], SectionAlignment);
        BinaryPrimitives.WriteUInt32LittleEndian(opt[36..], FileAlignment);
        BinaryPrimitives.WriteUInt16LittleEndian(opt[40..], 6);                          // MajorOSVersion
        BinaryPrimitives.WriteUInt16LittleEndian(opt[48..], 6);                          // MajorSubsystemVersion
        BinaryPrimitives.WriteUInt32LittleEndian(opt[56..], (uint)sizeOfImage);
        BinaryPrimitives.WriteUInt32LittleEndian(opt[60..], (uint)headersRaw);
        BinaryPrimitives.WriteUInt16LittleEndian(opt[68..], 3);                          // WINDOWS_CUI
        BinaryPrimitives.WriteUInt16LittleEndian(opt[70..], 0x8160);                     // NX|DYNAMIC_BASE|HIGH_ENTROPY_VA|TS_AWARE
        var dirCountOffset = o.Is64Bit ? 108 : 92;
        BinaryPrimitives.WriteUInt32LittleEndian(opt[dirCountOffset..], 16);

        // Section table
        var sections = opt[optionalSize..];
        uint textFlags = 0x6000_0020; // CODE | EXECUTE | READ
        if (o.WritableText)
        {
            textFlags |= 0x8000_0000;
        }

        WriteSection(sections, ".text", (uint)o.TextSize, (uint)textVa, (uint)textRaw, (uint)headersRaw, textFlags);
        if (o.AddDataSection)
        {
            WriteSection(sections[40..], ".data", (uint)dataContent.Length, (uint)dataVa, (uint)dataRaw,
                (uint)(headersRaw + textRaw), 0xC000_0040); // INITIALIZED_DATA | READ | WRITE
        }

        // .text: случайные байты (высокая энтропия) или RET + нули (низкая)
        var text = span.Slice(headersRaw, o.TextSize);
        if (o.HighEntropyText)
        {
            rng.NextBytes(text);
        }
        else
        {
            text[0] = 0xC3;
        }

        if (o.AddDataSection)
        {
            dataContent.CopyTo(span[(headersRaw + textRaw)..]);
        }

        if (o.OverlaySize > 0)
        {
            rng.NextBytes(span[(headersRaw + textRaw + dataRaw)..]);
        }

        return file;
    }

    /// <summary>Безопасный текстовый «конфиг майнера» для проверки сигнатур (без исполняемого кода).</summary>
    public static byte[] MinerConfigSample() => Encoding.UTF8.GetBytes(
        "{\n  \"autosave\": true,\n  \"donate-level\": 1,\n  \"randomx\": { \"mode\": \"auto\" },\n" +
        "  \"pools\": [ { \"url\": \"stratum+tcp://127.0.0.1:3333\", \"user\": \"SENTINEL-TEST\" } ]\n}\n");

    private static void WriteSection(Span<byte> s, string name, uint virtualSize, uint va, uint rawSize, uint rawPtr, uint flags)
    {
        Encoding.ASCII.GetBytes(name).CopyTo(s);
        BinaryPrimitives.WriteUInt32LittleEndian(s[8..], virtualSize);
        BinaryPrimitives.WriteUInt32LittleEndian(s[12..], va);
        BinaryPrimitives.WriteUInt32LittleEndian(s[16..], rawSize);
        BinaryPrimitives.WriteUInt32LittleEndian(s[20..], rawPtr);
        BinaryPrimitives.WriteUInt32LittleEndian(s[36..], flags);
    }

    private static int Align(int value, int alignment) => (value + alignment - 1) / alignment * alignment;
}
