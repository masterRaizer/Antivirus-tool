using Sentinel.Core.Pe;
using Sentinel.Core.Signatures;

namespace Sentinel.Core.Scoring;

/// <summary>Один вклад в итоговый балл: код, очки (могут быть отрицательными) и человекочитаемое объяснение.</summary>
public sealed record ScoreFactor(string Code, int Points, string Description);

/// <summary>Результат скоринга: балл 0–100 и все факторы, из которых он сложен.</summary>
public sealed record ThreatScore(int Value, IReadOnlyList<ScoreFactor> Factors)
{
    public static ThreatScore Zero { get; } = new(0, []);

    /// <summary>Уровень по порогам: 0–24 чисто, 25–44 Info, 45–64 Low, 65–84 Medium, 85+ High (100 — Critical).</summary>
    public Severity? Level => ThreatScoringEngine.LevelFor(Value);

    public string Describe() => string.Join("; ", Factors.Where(f => f.Points != 0).Select(f => $"{f.Description} ({f.Points:+#;-#;0})"));
}

/// <summary>Всё, что известно о файле на момент оценки. Заполняется анализатором и аудиторами.</summary>
public sealed record ScoringInput
{
    public required string Path { get; init; }

    public PeInfo? Pe { get; init; }

    /// <summary>Энтропия Шеннона всего файла (0–8).</summary>
    public double Entropy { get; init; }

    /// <summary>Действительная подпись: встроенная Authenticode или каталожная (.cat).</summary>
    public bool SignatureValid { get; init; }

    /// <summary>Подпись Microsoft в защищённом системном каталоге (решение <c>IWhitelistProvider</c>).</summary>
    public bool MicrosoftTrusted { get; init; }

    /// <summary>Объект есть в пользовательском списке <c>allowed_exclusions.json</c>.</summary>
    public bool UserAllowed { get; init; }

    /// <summary>Совпадение с базой угроз, YARA-правилом или EICAR.</summary>
    public string? DefinitiveMatch { get; init; }

    /// <summary>Облачная репутация признала хеш вредоносным.</summary>
    public string? CloudMalicious { get; init; }

    /// <summary>Имена импортируемых функций (IAT).</summary>
    public IReadOnlySet<string> Imports { get; init; } = new HashSet<string>();

    /// <summary>Подстроки, найденные в содержимом (<c>lsass</c>, <c>SeDebugPrivilege</c>, <c>AmsiScanBuffer</c>, <c>EtwEventWrite</c>).</summary>
    public IReadOnlySet<string> Markers { get; init; } = new HashSet<string>();

    /// <summary>Файл — цель активной точки автозагрузки.</summary>
    public bool PersistenceBound { get; init; }

    /// <summary>Командная строка запуска содержит обфусцированный вызов интерпретатора.</summary>
    public bool ObfuscatedCommandLine { get; init; }

    /// <summary>
    /// Однофайловое приложение .NET (apphost с сигнатурой бандла): сжатые сборки дают высокую энтропию, а строки
    /// AmsiScanBuffer/EtwEventWrite принадлежат самому рантайму .NET — это не упаковщик и не патчинг AMSI/ETW.
    /// </summary>
    public bool DotNetSingleFileBundle { get; init; }

    /// <summary>В приватной исполняемой памяти процесса найден PE-образ без файла на диске (<c>MEM-REFLECTIVE-PE</c>).</summary>
    public bool MemoryReflectivePe { get; init; }

    /// <summary>Сигнатурные правила/EICAR, сработавшие на исполняемой памяти процесса (<c>MEM-YARA-MATCH</c>).</summary>
    public string? MemorySignatureMatch { get; init; }

    /// <summary>Страницы образа (<c>MEM_IMAGE</c>) переведены в RWX — признак патча или хука (<c>MEM-RWX-IMAGE-PATCH</c>).</summary>
    public bool MemoryImagePatch { get; init; }
}

/// <summary>
/// Многофакторный скоринг угрозы (0–100). Сложение независимых признаков вместо одного жёсткого правила:
/// сама по себе высокая энтропия .NET-сборки или отсутствие подписи у библиотеки угрозой не считаются.
/// </summary>
public static class ThreatScoringEngine
{
    public const double HighEntropyThreshold = 7.35;

    private static readonly string[] PackerSectionNames = [".upx", "upx0", "upx1", ".vmp0", ".vmp1", ".vmp2", ".themida", ".winlice"];

    public static ThreatScore Evaluate(ScoringInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        var factors = new List<ScoreFactor>();

        if (input.DefinitiveMatch is { Length: > 0 } match)
        {
            factors.Add(new("MATCH", 100, $"Совпадение с базой угроз/правилом: {match}"));
        }

        if (input.CloudMalicious is { Length: > 0 } cloud)
        {
            factors.Add(new("CLOUD", 100, $"Облачная репутация: {cloud}"));
        }

        if (input.MicrosoftTrusted)
        {
            factors.Add(new("MS-SIGNED", -100, "Действительная подпись Microsoft в защищённом каталоге"));
        }

        if (input.UserAllowed)
        {
            factors.Add(new("USER-ALLOWED", -100, "Объект в списке разрешённых пользователем"));
        }

        var extension = System.IO.Path.GetExtension(input.Path).ToLowerInvariant();
        var pe = input.Pe;
        if (pe is not null && !input.SignatureValid)
        {
            if (pe.IsDll || extension == ".dll" || extension == ".ocx" || extension == ".cpl")
            {
                factors.Add(new("UNSIGNED-DLL", 5, "Библиотека без цифровой подписи"));
            }
            else
            {
                factors.Add(new("UNSIGNED-EXE", 10, "Исполняемый файл без цифровой подписи"));
            }
        }

        if (input.DotNetSingleFileBundle)
        {
            factors.Add(new ScoreFactor("DOTNET-BUNDLE", 0, "Однофайловое приложение .NET (сигнатура бандла apphost)"));
        }

        if (pe is not null && input.Entropy > HighEntropyThreshold)
        {
            // Сжатые метаданные IL у .NET-сборок и сжатые сборки однофайлового бандла дают высокую энтропию штатно — это не упаковщик.
            factors.Add(pe.IsManaged || input.DotNetSingleFileBundle
                ? new ScoreFactor("ENTROPY-MANAGED", 0, "Высокая энтропия .NET-сборки или однофайлового бандла .NET (не упаковщик)")
                : new ScoreFactor("ENTROPY-NATIVE", 15, $"Высокая энтропия нативного PE ({input.Entropy:F2})"));
        }

        if (pe is not null)
        {
            var section = pe.Sections.FirstOrDefault(s => s.IsExecutable && s.IsWritable)
                ?? pe.Sections.FirstOrDefault(s => PackerSectionNames.Contains(s.Name, StringComparer.OrdinalIgnoreCase));
            if (section is not null)
            {
                factors.Add(new("SECTION", 20, $"Секция '{section.Name}': запись+исполнение или имя упаковщика"));
            }
        }

        AddImportClusters(input, factors);

        if (input.PersistenceBound)
        {
            factors.Add(new("PERSISTENCE", 20, "Привязан к автозагрузке"));
        }

        if (input.ObfuscatedCommandLine)
        {
            factors.Add(new("OBFUSCATED-CMD", 15, "Обфусцированная командная строка интерпретатора"));
        }

        // Память процесса: весомы только PE-образ и сигнатуры. Сам по себе RWX-регион (JIT .NET, браузеров, PowerShell) баллов не даёт.
        if (input.MemoryReflectivePe)
        {
            factors.Add(new("MEM-REFLECTIVE-PE", 50, "PE-образ в приватной исполняемой памяти без файла на диске"));
        }

        if (input.MemorySignatureMatch is { Length: > 0 } memoryMatch)
        {
            factors.Add(new("MEM-YARA-MATCH", 70, $"Сигнатура в исполняемой памяти процесса: {memoryMatch}"));
        }

        if (input.MemoryImagePatch)
        {
            factors.Add(new("MEM-RWX-IMAGE-PATCH", 10, "Страницы загруженного образа переведены в запись+исполнение"));
        }

        var raw = factors.Sum(f => f.Points);
        return new ThreatScore(Math.Clamp(raw, 0, 100), factors);
    }

    /// <summary>Уровень вердикта по баллу; <c>null</c> — файл чист (0–24).</summary>
    public static Severity? LevelFor(int score) => score switch
    {
        < 25 => null,
        < 45 => Severity.Info,
        < 65 => Severity.Low,
        < 85 => Severity.Medium,
        < 100 => Severity.High,
        _ => Severity.Critical,
    };

    private static void AddImportClusters(ScoringInput input, List<ScoreFactor> factors)
    {
        var imports = input.Imports;
        var markers = input.Markers;
        bool Has(string name) => imports.Contains(name) || imports.Contains(name + "A") || imports.Contains(name + "W");
        bool Marker(string name) => markers.Contains(name);

        if (Has("VirtualAllocEx") && Has("WriteProcessMemory")
            && (Has("CreateRemoteThread") || Has("NtCreateThreadEx") || Has("QueueUserAPC") || Has("RtlCreateUserThread")))
        {
            factors.Add(new("API-INJECT", 35, "Импорты внедрения кода: VirtualAllocEx + WriteProcessMemory + создание удалённого потока/APC"));
        }

        if (Has("MiniDumpWriteDump") && (Marker("lsass") || Marker("SeDebugPrivilege")))
        {
            factors.Add(new("API-LSASS", 45, "MiniDumpWriteDump вместе с lsass/SeDebugPrivilege — дамп учётных данных"));
        }

        // Строки AmsiScanBuffer/EtwEventWrite в однофайловом бандле .NET — из рантайма (coreclr вызывает AMSI для Assembly.Load(byte[])),
        // поэтому для бандла учитываются только прямые импорты этих функций.
        // ETW: импорт EtwEventWrite — обычная трассировка (так делает почти любая системная библиотека Windows, например rtscom.dll);
        // признак патчинга — только динамическое получение адреса: строка есть, а в таблице импорта функции нет, и есть GetProcAddress.
        var amsi = Has("AmsiScanBuffer") || (!input.DotNetSingleFileBundle && Marker("AmsiScanBuffer"));
        var etwDynamic = !input.DotNetSingleFileBundle && Marker("EtwEventWrite") && !Has("EtwEventWrite") && Has("GetProcAddress");
        if ((amsi || etwDynamic) && Has("VirtualProtect"))
        {
            factors.Add(new("API-AMSI-ETW", 40, "Патчинг AMSI/ETW: AmsiScanBuffer/EtwEventWrite + VirtualProtect"));
        }

        if (Has("SetWindowsHookEx") && Has("GetAsyncKeyState"))
        {
            factors.Add(new("API-KEYLOG", 25, "SetWindowsHookEx + GetAsyncKeyState — перехват нажатий клавиш"));
        }
    }
}
