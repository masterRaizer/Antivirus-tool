using System.Xml;
using System.Xml.Linq;

namespace Sentinel.Core.Auditors.Persistence;

/// <summary>Извлечённые из XML-задачи данные (без разрешения CLSID — это делает источник через реестр).</summary>
public sealed record TaskXmlData(
    bool? Enabled,
    bool Hidden,
    string? UserId,
    string? RunLevel,
    IReadOnlyList<RawExecAction> ExecActions,
    IReadOnlyList<(string ClassId, string? Data)> ComHandlers);

/// <summary>
/// Потоковое чтение XML задачи планировщика (MS-TSCH). Файл читается через <see cref="FileStream"/> с буфером 64 КБ
/// и разбирается защищённым <see cref="XmlReader"/> (<c>DtdProcessing.Prohibit</c>, <c>XmlResolver = null</c> — защита от
/// XXE и внешних DTD). Кодировка (UTF-8/UTF-16) определяется ридером по BOM/декларации. Пространства имён игнорируются
/// (сопоставление по локальному имени элемента). <see cref="File.ReadAllText"/>/<see cref="File.ReadAllBytes"/> не используются.
/// </summary>
public static class TaskXmlStreamReader
{
    private const int BufferSize = 65536;

    private static readonly XmlReaderSettings Settings = new()
    {
        DtdProcessing = DtdProcessing.Prohibit,
        XmlResolver = null,
        IgnoreComments = true,
        IgnoreProcessingInstructions = true,
        IgnoreWhitespace = true,
        CloseInput = false,
    };

    public static TaskXmlData ReadFile(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete, BufferSize, FileOptions.SequentialScan);
        return Read(stream);
    }

    public static TaskXmlData Read(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        using var reader = XmlReader.Create(stream, Settings);
        var doc = XDocument.Load(reader);
        var root = doc.Root ?? throw new XmlException("Пустой документ задачи.");

        var enabled = ParseBool(Local(root, "Settings", "Enabled"));
        var hidden = ParseBool(Local(root, "Settings", "Hidden")) ?? false;
        var principal = root.Descendants().FirstOrDefault(e => e.Name.LocalName == "Principal");
        var userId = Trim(principal is null ? null : Child(principal, "UserId"));
        var runLevel = Trim(principal is null ? null : Child(principal, "RunLevel"));

        var execs = new List<RawExecAction>();
        var coms = new List<(string, string?)>();
        foreach (var action in root.Descendants().Where(e => e.Name.LocalName == "Exec"))
        {
            execs.Add(new RawExecAction(
                Trim(Child(action, "Command")) ?? string.Empty,
                Trim(Child(action, "Arguments")),
                Trim(Child(action, "WorkingDirectory"))));
        }

        foreach (var action in root.Descendants().Where(e => e.Name.LocalName == "ComHandler"))
        {
            coms.Add((Trim(Child(action, "ClassId")) ?? string.Empty, Trim(Child(action, "Data"))));
        }

        return new TaskXmlData(enabled, hidden, userId, runLevel, execs, coms);
    }

    private static string? Child(XElement parent, string localName) =>
        parent.Elements().FirstOrDefault(e => e.Name.LocalName == localName)?.Value;

    private static string? Local(XElement root, string parentName, string childName)
    {
        var parent = root.Descendants().FirstOrDefault(e => e.Name.LocalName == parentName);
        return parent is null ? null : Child(parent, childName);
    }

    private static string? Trim(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private static bool? ParseBool(string? value) => value?.Trim().ToLowerInvariant() switch
    {
        "true" => true,
        "false" => false,
        _ => null,
    };
}
