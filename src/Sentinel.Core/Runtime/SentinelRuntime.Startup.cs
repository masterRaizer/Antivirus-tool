using Sentinel.Core.Audit.Config;
using Sentinel.Core.Audit.Persistence;
using Sentinel.Core.Ipc;
using Sentinel.Core.Reporting;
using Sentinel.Core.Signatures;
using Sentinel.Core.Trust;

namespace Sentinel.Core.Runtime;

/// <summary>Сводная таблица автозагрузки: автозапуск, службы, задачи, hosts и исключения Defender.</summary>
public sealed partial class SentinelRuntime
{
    private StartupSnapshot? _startup;
    private Dictionary<string, object> _startupTargets = new(StringComparer.Ordinal);

    public async Task<StartupSnapshot> GetStartupAsync(bool refresh = false, CancellationToken cancellationToken = default)
    {
        lock (_sync)
        {
            if (!refresh && _startup is not null)
            {
                return _startup;
            }
        }

        if (_o.PersistenceAudit is null && _o.ConfigAudit is null)
        {
            return new StartupSnapshot([], _o.TimeProvider.GetUtcNow().UtcDateTime,
                "Аудит автозагрузки доступен только в Windows (реестр, службы, планировщик, WMI).");
        }

        var (snapshot, targets) = await Task.Run(BuildStartup, cancellationToken).ConfigureAwait(false);
        lock (_sync)
        {
            _startup = snapshot;
            _startupTargets = targets;
        }

        return snapshot;
    }

    public async Task<OperationResult> CleanStartupItemAsync(string key, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);
        if (_o.Engine is null)
        {
            return OperationResult.Fail("Очистка автозагрузки доступна только в Windows.");
        }

        object? target;
        lock (_sync)
        {
            _startupTargets.TryGetValue(key, out target);
        }

        var action = target switch
        {
            PersistenceEntry entry => _o.Engine.RollbackPersistence(entry),
            (DefenderExclusion exclusion, string reason) => _o.Engine.RemoveDefenderExclusion(exclusion, reason),
            _ => null,
        };
        if (action is null)
        {
            return OperationResult.Fail("Запись не найдена — обновите таблицу.");
        }

        if (action.Success)
        {
            await GetStartupAsync(refresh: true, cancellationToken).ConfigureAwait(false);
        }

        return new OperationResult(action.Success, action.Message);
    }

    private void InvalidateStartup()
    {
        lock (_sync)
        {
            _startup = null;
        }
    }

    private (StartupSnapshot Snapshot, Dictionary<string, object> Targets) BuildStartup()
    {
        var items = new List<StartupItem>();
        var targets = new Dictionary<string, object>(StringComparer.Ordinal);
        var canAct = _o.Engine is not null;

        if (_o.PersistenceAudit is not null)
        {
            foreach (var e in _o.PersistenceAudit().Entries)
            {
                var key = Unique(ReportBuilder.PersistenceKey(e));
                targets[key] = e;
                items.Add(new StartupItem
                {
                    Key = key,
                    Category = e.Kind switch
                    {
                        PersistenceKind.Service => "Служба",
                        PersistenceKind.ScheduledTask => "Задача",
                        PersistenceKind.WmiSubscription => "WMI",
                        PersistenceKind.HostsFile => "Hosts",
                        _ => "Автозапуск",
                    },
                    Name = e.Name,
                    Location = e.Location,
                    Command = e.Command,
                    Target = e.ResolvedTarget,
                    SignatureStatus = e.FileScan is null ? "не проверялась" : ReportBuilder.DescribeSignature(e.FileScan),
                    NotSigned = e.FileScan?.Signature is { IsValid: false, Status: not SignatureStatus.Unsupported },
                    Flagged = e.HasFindings,
                    Severity = e.MaxSeverity,
                    Remarks = e.HasFindings ? string.Join("; ", e.Findings.Select(f => f.Title).Distinct()) : null,
                    CanClean = canAct && e.HasFindings,
                });
            }
        }

        if (_o.ConfigAudit is not null)
        {
            var allowed = _allowed.Load();
            foreach (var (exclusion, finding) in PairExclusions(_o.ConfigAudit()))
            {
                var key = Unique(ReportBuilder.ExclusionKey(exclusion));
                var userAllowed = allowed.IsAllowed(exclusion);
                targets[key] = (exclusion, finding.Id);
                items.Add(new StartupItem
                {
                    Key = key,
                    Category = "Исключение Defender",
                    Name = exclusion.ToString(),
                    Location = exclusion.SourceKey,
                    Target = exclusion.Kind is DefenderExclusionKind.Path or DefenderExclusionKind.Process ? exclusion.ExpandedValue : null,
                    Flagged = !userAllowed,
                    Severity = userAllowed ? Severity.Info : finding.Severity,
                    Remarks = userAllowed ? "Разрешено пользователем (allowed_exclusions.json)." : finding.Description,
                    CanClean = canAct && !userAllowed,
                });
            }
        }

        var ordered = items.OrderByDescending(i => i.Flagged).ThenByDescending(i => i.Severity).ThenBy(i => i.Category, StringComparer.Ordinal).ToArray();
        return (new StartupSnapshot(ordered, _o.TimeProvider.GetUtcNow().UtcDateTime), targets);

        string Unique(string key)
        {
            var candidate = key;
            for (var n = 2; targets.ContainsKey(candidate); n++)
            {
                candidate = $"{key}#{n}";
            }

            return candidate;
        }
    }
}
