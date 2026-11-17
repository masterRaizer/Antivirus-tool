namespace Sentinel.Core.Monitoring.Evasion;

/// <summary>Обстоятельства, которые watcher выяснил о процессе после находки детектора.</summary>
public sealed record EvasionScoreContext
{
    /// <summary>Образ процесса признан угрозой анализатором файлов (сигнатуры, база хешей, эвристика).</summary>
    public bool FileFlagged { get; init; }

    /// <summary>Балл <c>ThreatScoringEngine</c> для образа (0, если не проверялся).</summary>
    public int FileScore { get; init; }

    /// <summary>Образ подписан доверенным издателем (WinVerifyTrust).</summary>
    public bool TrustedSigned { get; init; }

    /// <summary>Образ лежит в каталоге, куда пишет обычный пользователь (профиль, Temp, ProgramData, Public).</summary>
    public bool UserWritableLocation { get; init; }

    /// <summary>Файла образа на диске уже нет (удалён после запуска — типично для загрузчиков).</summary>
    public bool ImageMissing { get; init; }

    /// <summary>Число USER-объектов процесса (окна, меню, курсоры): −1 — неизвестно.</summary>
    public int UserObjects { get; init; } = -1;

    /// <summary>
    /// Образ — подписанный системный инструмент, в который майнеры чаще всего внедряются (RegAsm, AppLaunch, vbc, notepad…):
    /// его подпись принадлежит носителю, а не полезной нагрузке, и подозрение не снижает.
    /// </summary>
    public bool HollowingHost { get; init; }

    /// <summary>В памяти процесса найден PE-образ без файла или сигнатура (<c>MemoryIntegrityScanner</c>).</summary>
    public bool MemoryAnomaly { get; init; }

    /// <summary>Образ лежит в каталоге Windows или Program Files (не в пользовательском каталоге).</summary>
    public bool SystemLocation { get; init; }
}

/// <summary>Итоговая оценка: балл, можно ли действовать без пользователя, и из чего балл сложился.</summary>
public sealed record EvasionScore(int Score, bool AllowAutoAction, IReadOnlyList<string> Factors);

/// <summary>
/// Оценка находки детектора уклонения. Балл складывается из вида находки, повторений, характера нагрузки и сведений об
/// образе. Защита от ложных срабатываний: у процесса с окнами (игра, видео, редактор) нагрузка часто падает сама, когда
/// пользователь переключается на Диспетчер задач, поэтому такой процесс получает −25 и не нейтрализуется автоматически.
/// Без подтверждения анализатором файлов автоматическое действие разрешено только после двух и более полных циклов.
/// </summary>
public static class MonitorEvasionPolicy
{
    /// <summary>С этого числа USER-объектов процесс считается оконным (интерактивным).</summary>
    public const int InteractiveUserObjects = 30;

    /// <summary>Потолок балла для доверенного компонента в системном каталоге без подтверждения (ниже порога вопроса 50).</summary>
    public const int TrustedSystemCap = 45;

    /// <summary>
    /// Подписанные носители, в которые чаще всего внедряют майнеры (process hollowing): инструменты .NET Framework и
    /// простые программы Windows. Процесс с таким образом, долго грузящий процессор и прячущийся от мониторинга, —
    /// почти всегда внедрённая полезная нагрузка.
    /// </summary>
    public static readonly IReadOnlySet<string> HollowingHosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "RegAsm.exe", "RegSvcs.exe", "AppLaunch.exe", "vbc.exe", "csc.exe", "jsc.exe", "InstallUtil.exe", "MSBuild.exe",
        "aspnet_compiler.exe", "aspnet_regbrowsers.exe", "cvtres.exe", "ilasm.exe", "CasPol.exe", "AddInProcess.exe",
        "AddInProcess32.exe", "AddInUtil.exe", "dfsvc.exe", "ieexec.exe", "Microsoft.Workflow.Compiler.exe",
        "notepad.exe", "dllhost.exe", "conhost.exe", "nslookup.exe", "wuapp.exe", "attrib.exe", "calc.exe", "mspaint.exe",
        "werfault.exe", "bitsadmin.exe", "colorcpl.exe", "sihost.exe", "upnpcont.exe",
    };

    public static EvasionScore Score(MonitorEvasionFinding finding, EvasionScoreContext context)
    {
        ArgumentNullException.ThrowIfNull(finding);
        ArgumentNullException.ThrowIfNull(context);
        var factors = new List<string>();
        int score;
        switch (finding.Kind)
        {
            case EvasionKind.HideAndResume:
                score = 60;
                factors.Add("спрятал нагрузку при открытии мониторинга и вернул после закрытия (+60)");
                break;
            case EvasionKind.HiddenWhileMonitorOpen:
                score = 40;
                factors.Add("спрятал нагрузку при открытии мониторинга (+40)");
                break;
            default:
                score = 35;
                factors.Add("завершился сразу после открытия мониторинга (+35)");
                break;
        }

        var priorCycles = finding.Kind == EvasionKind.HideAndResume ? finding.CycleCount - 1 : finding.CycleCount;
        var priorExits = finding.Kind == EvasionKind.ExitOnMonitor ? finding.ExitCount - 1 : finding.ExitCount;
        var repeat = Math.Min(30, (Math.Max(0, priorCycles) * 15) + (Math.Max(0, priorExits) * 10));
        if (repeat > 0)
        {
            score += repeat;
            factors.Add($"повторяется за сутки: циклов {finding.CycleCount}, завершений {finding.ExitCount} (+{repeat})");
        }

        if (finding.BaselineVariation <= 0.15 && finding.BaselineCores >= 0.5)
        {
            score += 10;
            factors.Add("ровная длительная нагрузка, как у майнера (+10)");
        }

        var interactive = context.UserObjects >= InteractiveUserObjects;
        if (interactive)
        {
            score -= 25;
            factors.Add($"у процесса есть окна ({context.UserObjects} USER-объектов) — нагрузка могла упасть из-за потери фокуса (−25)");
        }

        if (context.UserWritableLocation && !context.TrustedSigned)
        {
            score += 10;
            factors.Add("образ без доверенной подписи в пользовательском каталоге (+10)");
        }

        if (context.ImageMissing)
        {
            score += 10;
            factors.Add("файла образа уже нет на диске (+10)");
        }

        if (context.FileFlagged)
        {
            score = Math.Max(score, context.FileScore) + 10;
            factors.Add($"образ признан угрозой анализатором файлов (балл {context.FileScore}, +10)");
        }

        if (context.HollowingHost)
        {
            score += 10;
            factors.Add("системный инструмент, в который часто внедряют майнеры: его подпись не снижает подозрение (+10)");
        }

        if (context.MemoryAnomaly)
        {
            score += 30;
            factors.Add("в памяти процесса найден PE-образ без файла или сигнатура (+30)");
        }

        // Подписанные доверенным издателем компоненты Windows и программ сами затихают, когда пользователь активен
        // (индексатор поиска, обслуживание, обновления), — а пользователь активен как раз когда открывает Диспетчер задач.
        // Без подтверждения памятью или анализатором такая находка только пишется в журнал.
        var confirmed = context.FileFlagged || context.MemoryAnomaly;
        if (context.TrustedSigned && context.SystemLocation && !context.HollowingHost && !confirmed && score > TrustedSystemCap)
        {
            score = TrustedSystemCap;
            factors.Add($"доверенный компонент в системном каталоге: снижение нагрузки при активности пользователя — штатное поведение (не выше {TrustedSystemCap})");
        }

        var auto = confirmed
            || (finding.Kind == EvasionKind.HideAndResume && finding.CycleCount >= 2 && !interactive && (!context.TrustedSigned || context.HollowingHost));
        if (!auto)
        {
            factors.Add("автоматическое действие только после повторного цикла или подтверждения анализатором");
        }

        return new EvasionScore(Math.Clamp(score, 0, 100), auto, factors);
    }

    /// <summary>Каталог Windows или Program Files любого диска.</summary>
    public static bool IsSystemLocation(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var p = path.Replace('/', '\\');
        return p.Contains(@":\Windows\", StringComparison.OrdinalIgnoreCase)
            || p.Contains(@":\Program Files\", StringComparison.OrdinalIgnoreCase)
            || p.Contains(@":\Program Files (x86)\", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Каталоги, куда пишет обычный пользователь: оттуда запускаются почти все скрытые майнеры.</summary>
    public static bool IsUserWritableLocation(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var p = path.Replace('/', '\\');
        return p.Contains(@"\Users\", StringComparison.OrdinalIgnoreCase)
            || p.Contains(@"\ProgramData\", StringComparison.OrdinalIgnoreCase)
            || p.Contains(@"\Windows\Temp\", StringComparison.OrdinalIgnoreCase)
            || p.Contains(@"\$Recycle.Bin\", StringComparison.OrdinalIgnoreCase);
    }
}
