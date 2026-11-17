using Sentinel.Core.ThreatFamilies;

namespace Sentinel.Core.Runtime;

public sealed partial class SentinelRuntime
{
    /// <summary>
    /// Перепроверка после перезагрузки, если плейбук семейства оставил отметку: файлы не вернулись, процессов и соединений нет,
    /// исключения и закрепление не восстановлены. Результат пишется в журнал службы; при проблемах отметка остаётся.
    /// </summary>
    public FamilyVerification? RunPendingFamilyRecheck()
    {
        if (_o.FamilyProbe is null || !ThreatFamilyPlaybook.HasPendingRecheck(_o.DataDirectory))
        {
            return null;
        }

        var playbook = new ThreatFamilyPlaybook(null, null, new ThreatFamilyPlaybookOptions { DataDirectory = _o.DataDirectory }, _o.FamilyProbe());
        var result = playbook.RunPendingRecheck();
        if (result is null)
        {
            return null;
        }

        if (result.Clean)
        {
            Info?.Invoke($"Перепроверка после чистки семейства: чисто ({string.Join(", ", result.Checked)}).");
        }
        else
        {
            Log?.Invoke("Перепроверка после чистки семейства: остался механизм перезапуска — " + string.Join(" ", result.Problems)
                + " Запустите «sentinel family-scan».");
        }

        return result;
    }
}
