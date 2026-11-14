using System.Buffers.Binary;
using System.Text;
using Sentinel.Core.Analysis;

namespace Sentinel.Core.Pe;

/// <summary>
/// Разбор PE/COFF заголовков (MS PE/COFF spec): DOS-заголовок, сигнатура "PE\0\0",
/// File Header, Optional Header (PE32/PE32+), каталоги данных и таблица секций.
/// Парсер устойчив к повреждённым файлам: никогда не читает за пределами потока
/// и возвращает <see cref="PeParseResult.NotPe"/> с причиной вместо исключения.
/// </summary>
public static class PeParser
{
    private const ushort DosMagic = 0x5A4D;          // "MZ"
    private const uint PeSignature = 0x0000_4550;    // "PE\0\0"
    private const ushort Pe32Magic = 0x010B;
    private const ushort Pe32PlusMagic = 0x020B;
    private const ushort FileDllFlag = 0x2000;
    private const int MaxSections = 96;              // предел загрузчика Windows
    private const int MaxDataDirectories = 16;
    private const long MaxSectionBytesForEntropy = 64L * 1024 * 1024;

    public static PeParseResult ParseFile(string path)
    {
        using var stream = Hashing.FileHasher.OpenShared(path);
        return Parse(stream);
    }

    public static PeParseResult Parse(ReadOnlySpan<byte> data)
    {
        using var ms = new MemoryStream(data.ToArray(), writable: false);
        return Parse(ms);
    }

    public static PeParseResult Parse(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanSeek)
        {
            throw new ArgumentException("Поток должен поддерживать позиционирование.", nameof(stream));
        }

        var length = stream.Length;
        Span<byte> dos = stackalloc byte[64];
        if (!ReadAt(stream, 0, dos))
        {
            return PeParseResult.NotPe("Файл меньше DOS-заголовка (64 байта).");
        }

        if (BinaryPrimitives.ReadUInt16LittleEndian(dos) != DosMagic)
        {
            return PeParseResult.NotPe("Отсутствует сигнатура MZ.");
        }

        var eLfanew = BinaryPrimitives.ReadInt32LittleEndian(dos[0x3C..]);
        if (eLfanew <= 0 || eLfanew > length - 24)
        {
            return PeParseResult.NotPe($"Некорректное смещение e_lfanew: {eLfanew}.");
        }

        // PE signature (4) + IMAGE_FILE_HEADER (20)
        Span<byte> nt = stackalloc byte[24];
        if (!ReadAt(stream, eLfanew, nt) || BinaryPrimitives.ReadUInt32LittleEndian(nt) != PeSignature)
        {
            return PeParseResult.NotPe("Отсутствует сигнатура PE\\0\\0.");
        }

        var fileHeader = nt[4..];
        var machine = (PeMachine)BinaryPrimitives.ReadUInt16LittleEndian(fileHeader);
        var numberOfSections = BinaryPrimitives.ReadUInt16LittleEndian(fileHeader[2..]);
        var timeDateStamp = BinaryPrimitives.ReadUInt32LittleEndian(fileHeader[4..]);
        var sizeOfOptionalHeader = BinaryPrimitives.ReadUInt16LittleEndian(fileHeader[16..]);
        var characteristics = BinaryPrimitives.ReadUInt16LittleEndian(fileHeader[18..]);

        if (numberOfSections > MaxSections)
        {
            return PeParseResult.NotPe($"Слишком много секций: {numberOfSections}.");
        }

        var optionalOffset = (long)eLfanew + 24;
        if (sizeOfOptionalHeader < 2 || optionalOffset + sizeOfOptionalHeader > length)
        {
            return PeParseResult.NotPe("Optional Header обрезан или отсутствует.");
        }

        var optional = new byte[sizeOfOptionalHeader];
        if (!ReadAt(stream, optionalOffset, optional))
        {
            return PeParseResult.NotPe("Не удалось прочитать Optional Header.");
        }

        var magic = BinaryPrimitives.ReadUInt16LittleEndian(optional);
        bool is64;
        int dataDirOffset;
        switch (magic)
        {
            case Pe32Magic:
                is64 = false;
                dataDirOffset = 96;
                break;
            case Pe32PlusMagic:
                is64 = true;
                dataDirOffset = 112;
                break;
            default:
                return PeParseResult.NotPe($"Неизвестная сигнатура Optional Header: 0x{magic:X4}.");
        }

        if (optional.Length < dataDirOffset)
        {
            return PeParseResult.NotPe("Optional Header короче обязательной части.");
        }

        var opt = optional.AsSpan();
        var entryPoint = BinaryPrimitives.ReadUInt32LittleEndian(opt[16..]);
        var imageBase = is64 ? BinaryPrimitives.ReadUInt64LittleEndian(opt[24..]) : BinaryPrimitives.ReadUInt32LittleEndian(opt[28..]);
        var sizeOfImage = BinaryPrimitives.ReadUInt32LittleEndian(opt[56..]);
        var sizeOfHeaders = BinaryPrimitives.ReadUInt32LittleEndian(opt[60..]);
        var checkSum = BinaryPrimitives.ReadUInt32LittleEndian(opt[64..]);
        var subsystem = (PeSubsystem)BinaryPrimitives.ReadUInt16LittleEndian(opt[68..]);
        var dllCharacteristics = BinaryPrimitives.ReadUInt16LittleEndian(opt[70..]);
        var numberOfRvaAndSizes = BinaryPrimitives.ReadUInt32LittleEndian(opt[(dataDirOffset - 4)..]);

        var dirCount = (int)Math.Min(Math.Min(numberOfRvaAndSizes, MaxDataDirectories), (uint)((optional.Length - dataDirOffset) / 8));
        var dataDirectories = new List<PeDataDirectory>(dirCount);
        for (var i = 0; i < dirCount; i++)
        {
            var d = opt[(dataDirOffset + (i * 8))..];
            dataDirectories.Add(new PeDataDirectory(
                BinaryPrimitives.ReadUInt32LittleEndian(d),
                BinaryPrimitives.ReadUInt32LittleEndian(d[4..])));
        }

        var anomalies = new List<string>();
        var sectionTableOffset = optionalOffset + sizeOfOptionalHeader;
        var sectionTable = new byte[numberOfSections * 40];
        if (!ReadAt(stream, sectionTableOffset, sectionTable))
        {
            return PeParseResult.NotPe("Таблица секций обрезана.");
        }

        var sections = new List<PeSection>(numberOfSections);
        long maxRawEnd = sizeOfHeaders;
        for (var i = 0; i < numberOfSections; i++)
        {
            var s = sectionTable.AsSpan(i * 40, 40);
            var name = DecodeSectionName(s[..8]);
            var virtualSize = BinaryPrimitives.ReadUInt32LittleEndian(s[8..]);
            var virtualAddress = BinaryPrimitives.ReadUInt32LittleEndian(s[12..]);
            var sizeOfRawData = BinaryPrimitives.ReadUInt32LittleEndian(s[16..]);
            var pointerToRawData = BinaryPrimitives.ReadUInt32LittleEndian(s[20..]);
            var flags = (SectionCharacteristics)BinaryPrimitives.ReadUInt32LittleEndian(s[36..]);

            double entropy = 0;
            if (sizeOfRawData > 0)
            {
                var rawEnd = (long)pointerToRawData + sizeOfRawData;
                if (rawEnd > length)
                {
                    anomalies.Add($"Секция '{name}' выходит за пределы файла.");
                }

                var available = Math.Clamp(length - pointerToRawData, 0, Math.Min(sizeOfRawData, MaxSectionBytesForEntropy));
                if (available > 0)
                {
                    entropy = SectionEntropy(stream, pointerToRawData, available);
                }

                maxRawEnd = Math.Max(maxRawEnd, Math.Min(rawEnd, length));
            }

            var section = new PeSection(name, virtualAddress, virtualSize, pointerToRawData, sizeOfRawData, flags, entropy);
            sections.Add(section);

            if (section.IsExecutable && section.IsWritable)
            {
                anomalies.Add($"Секция '{name}' одновременно исполняемая и записываемая (W+X).");
            }

            if (section.IsExecutable && entropy >= EntropyCalculator.HighEntropyThreshold)
            {
                anomalies.Add($"Исполняемая секция '{name}' имеет высокую энтропию ({entropy:F2}) — вероятна упаковка.");
            }

            if (section.IsExecutable && sizeOfRawData == 0 && virtualSize > 0)
            {
                anomalies.Add($"Исполняемая секция '{name}' пуста на диске (распаковка в памяти).");
            }
        }

        var info = new PeInfo
        {
            Machine = machine,
            Is64Bit = is64,
            IsDll = (characteristics & FileDllFlag) != 0,
            Subsystem = subsystem,
            TimeDateStamp = DateTimeOffset.FromUnixTimeSeconds(timeDateStamp),
            EntryPointRva = entryPoint,
            ImageBase = imageBase,
            SizeOfImage = sizeOfImage,
            CheckSum = checkSum,
            Characteristics = characteristics,
            DllCharacteristics = dllCharacteristics,
            Sections = sections,
            DataDirectories = dataDirectories,
            OverlayOffset = maxRawEnd,
            OverlaySize = 0,
            Anomalies = anomalies,
        };

        // Оверлей: данные после последней секции. Подпись Authenticode законно лежит в конце файла,
        // поэтому каталог безопасности (его смещение — файловое, не RVA) исключается из оверлея.
        var overlayEnd = length;
        if (info.HasAuthenticodeDirectory)
        {
            var sec = dataDirectories[4];
            if (sec.VirtualAddress >= maxRawEnd && (long)sec.VirtualAddress + sec.Size >= length)
            {
                overlayEnd = sec.VirtualAddress;
            }
        }

        var overlaySize = Math.Max(0, overlayEnd - maxRawEnd);
        if (overlaySize > 0)
        {
            anomalies.Add($"Обнаружен оверлей: {overlaySize} байт после последней секции.");
        }

        if (numberOfSections > 0 && entryPoint != 0 && info.EntryPointSection is null)
        {
            anomalies.Add($"Точка входа 0x{entryPoint:X} находится вне секций.");
        }
        else if (info.EntryPointSection is { IsWritable: true } eps)
        {
            anomalies.Add($"Точка входа находится в записываемой секции '{eps.Name}'.");
        }

        return PeParseResult.Success(info with { OverlaySize = overlaySize });
    }

    private static string DecodeSectionName(ReadOnlySpan<byte> raw)
    {
        var end = raw.IndexOf((byte)0);
        var slice = end < 0 ? raw : raw[..end];
        return Encoding.UTF8.GetString(slice);
    }

    private static double SectionEntropy(Stream stream, long offset, long count)
    {
        stream.Position = offset;
        return EntropyCalculator.Calculate(stream, count);
    }

    private static bool ReadAt(Stream stream, long offset, Span<byte> buffer)
    {
        if (offset < 0 || offset + buffer.Length > stream.Length)
        {
            return false;
        }

        stream.Position = offset;
        stream.ReadExactly(buffer);
        return true;
    }
}
