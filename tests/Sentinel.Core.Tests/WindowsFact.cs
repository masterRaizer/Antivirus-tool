namespace Sentinel.Core.Tests;

/// <summary>
/// Факт, выполняемый только в Windows. На других ОС тест помечается как пропущенный
/// (интеграция с реальным реестром/хранилищем сертификатов недоступна вне Windows).
/// </summary>
public sealed class WindowsFactAttribute : FactAttribute
{
    public WindowsFactAttribute()
    {
        if (!OperatingSystem.IsWindows())
        {
            Skip = "Интеграционный тест выполняется только в Windows.";
        }
    }
}
