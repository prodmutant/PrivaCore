using System;
using System.Collections.Generic;
using System.Linq;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Services.Siem
{
    /// <summary>
    /// The SIEM detection / correlation engine (the Elastic Security "rules" layer). Evaluates each
    /// enabled <see cref="SiemRule"/> on a timer over <see cref="SiemStore"/>; when a rule's
    /// threshold trips it raises a <see cref="SiemAlert"/> (with per-rule/per-group cooldown so it
    /// doesn't re-fire every tick) and drops an alert event into the store. Singleton, shared by the
    /// dashboard so console and collector see the same alerts.
    /// </summary>
    /// <summary>One hypothetical hit from a rule preview/backtest (no side-effects).</summary>
    public sealed class SiemPreviewHit
    {
        public int Count { get; set; }
        public string Group { get; set; } = "";
        public string Message { get; set; } = "";
    }

    public sealed class SiemRuleEngine
    {
        public static SiemRuleEngine Instance { get; } = new();

        private readonly ISiemStore _store = SiemStoreProvider.Current;
        private readonly System.Timers.Timer _timer;
        private readonly object _lock = new();
        private readonly LinkedList<SiemAlert> _alerts = new();           // newest first
        private readonly Dictionary<string, DateTime> _cooldown = new();  // rule|group → last fired
        private bool _started;
        private List<SiemPreviewHit>? _previewSink;   // non-null during Preview() — diverts Fire() into a no-side-effect list

        public List<SiemRule> Rules { get; private set; }
        public int AlertCapacity { get; set; } = 2000;

        /// <summary>Evaluation cadence. Default 15s — keeps alerts responsive without scanning too often.</summary>
        public double IntervalSeconds { get; set; } = 15;

        /// <summary>Source of threat-intel indicators for <see cref="SiemRuleType.IndicatorMatch"/> rules (defaults to the managed store; overridable for tests).</summary>
        public Func<IReadOnlyCollection<SiemIndicator>> IndicatorSource { get; set; } = () => SiemIndicatorStore.Instance.All();

        public event EventHandler<SiemAlert>? AlertRaised;
        public event Action? RulesChanged;
        public event Action? AlertsChanged;

        private SiemRuleEngine()
        {
            Rules = SiemRuleStore.Load();
            _timer = new System.Timers.Timer { AutoReset = true };
            _timer.Elapsed += (_, _) => Evaluate();
        }

        public void Start()
        {
            if (_started) return;
            _started = true;
            _timer.Interval = Math.Max(2, IntervalSeconds) * 1000;
            _timer.Start();
        }

        /// <summary>
        /// Backtest a rule against the events already in the store over the last <paramref name="lookbackMinutes"/>:
        /// returns the hits it WOULD raise, with no cooldown / alert / store / webhook side-effects. The rule's
        /// counting window is widened to the lookback so "what would this have caught" is answered in one pass.
        /// </summary>
        public List<SiemPreviewHit> Preview(SiemRule rule, int lookbackMinutes)
        {
            var sink = new List<SiemPreviewHit>();
            var window = TimeSpan.FromMinutes(Math.Max(rule.WindowMinutes, Math.Max(1, lookbackMinutes)));
            lock (_lock) _previewSink = sink;
            try { EvaluateRule(rule, window); } catch { /* a bad rule must not throw into the UI */ }
            finally { lock (_lock) _previewSink = null; }
            return sink;
        }

        // ── rule management ──
        public void AddRule(SiemRule r) { Rules.Add(r); Persist(); }
        public void RemoveRule(SiemRule r) { Rules.Remove(r); Persist(); }
        public void Persist() { SiemRuleStore.Save(Rules); RulesChanged?.Invoke(); }

        // ── alerts access / triage ──
        public List<SiemAlert> Alerts() { lock (_lock) return _alerts.ToList(); }
        public int OpenCount() { lock (_lock) return _alerts.Count(a => a.Status == SiemAlertStatus.Open); }

        /// <summary>Clear all alerts, cooldowns and rules (used by tests and "reset" actions).</summary>
        public void Reset()
        {
            lock (_lock) { _alerts.Clear(); _cooldown.Clear(); }
            Rules.Clear();
            AlertsChanged?.Invoke();
        }

        public void ClearClosed()
        {
            lock (_lock)
            {
                var keep = _alerts.Where(a => a.Status != SiemAlertStatus.Closed).ToList();
                _alerts.Clear();
                foreach (var a in keep) _alerts.AddLast(a);
            }
            AlertsChanged?.Invoke();
        }

        // ── evaluation ──
        public void Evaluate()
        {
            foreach (var rule in Rules.Where(r => r.Enabled).ToList())
            {
                try { EvaluateRule(rule); } catch { /* a bad rule must not kill the engine */ }
            }
        }

        private void EvaluateRule(SiemRule rule, TimeSpan? windowOverride = null)
        {
            var window = windowOverride ?? TimeSpan.FromMinutes(Math.Max(1, rule.WindowMinutes));
            var q = SiemQuery.Parse(rule.Query);
            var keep = NotExcluded(rule);

            if (rule.Type == SiemRuleType.NewTerms && !string.IsNullOrWhiteSpace(rule.GroupBy))
            {
                // a GroupBy value seen in the recent window but never before in retained history
                var all = _store.Query(q, null, 200_000).Where(e => !IsAlertEvent(e) && keep(e)).ToList();
                var cutoff = DateTime.Now - window;
                var history = new HashSet<string>(
                    all.Where(e => e.Timestamp < cutoff).Select(e => GroupValue(rule, e)).Where(v => v.Length > 0),
                    StringComparer.OrdinalIgnoreCase);
                foreach (var g in all.Where(e => e.Timestamp >= cutoff).GroupBy(e => GroupValue(rule, e)))
                {
                    if (string.IsNullOrEmpty(g.Key) || history.Contains(g.Key)) continue;
                    int c = g.Count();
                    if (c >= Math.Max(1, rule.Threshold)) Fire(rule, c, g.Key, window, newTerm: true);
                }
                return;
            }

            if (rule.Type == SiemRuleType.Sequence)
            {
                EvaluateSequence(rule, q, window, keep);
                return;
            }

            if (rule.Type == SiemRuleType.Anomaly)
            {
                EvaluateAnomaly(rule, q, window, keep);
                return;
            }

            if (rule.Type == SiemRuleType.IndicatorMatch)
            {
                EvaluateIndicatorMatch(rule, q, window, keep);
                return;
            }

            var matches = _store.Query(q, window, 200_000).Where(e => !IsAlertEvent(e) && keep(e)).ToList();

            if (rule.Type == SiemRuleType.GroupThreshold && !string.IsNullOrWhiteSpace(rule.GroupBy))
            {
                foreach (var g in matches.GroupBy(e => GroupValue(rule, e)))
                {
                    if (string.IsNullOrEmpty(g.Key)) continue;
                    int c = g.Count();
                    if (c >= rule.Threshold) Fire(rule, c, g.Key, window);
                }
            }
            else if (matches.Count >= rule.Threshold)
            {
                Fire(rule, matches.Count, "", window);
            }
        }

        /// <summary>
        /// EQL-style sequence: ≥Threshold of step-A then a step-B event from the same group, in order.
        /// Supports a multi-field <c>by</c> (comma-separated GroupBy) and an optional <c>maxspan</c>
        /// (step-B must occur within <see cref="SiemRule.MaxSpanMinutes"/> of the first step-A).
        /// </summary>
        private void EvaluateSequence(SiemRule rule, SiemQuery qa, TimeSpan window, Func<SiemEvent, bool> keep)
        {
            var qb = SiemQuery.Parse(rule.SecondQuery);
            var all = _store.Query(SiemQuery.Parse(null), window, 200_000).Where(e => !IsAlertEvent(e) && keep(e)).ToList();
            var maxspan = rule.MaxSpanMinutes > 0 ? TimeSpan.FromMinutes(rule.MaxSpanMinutes) : TimeSpan.MaxValue;

            string GroupKey(SiemEvent e) => string.IsNullOrWhiteSpace(rule.GroupBy) ? "*" : GroupValue(rule, e);
            foreach (var g in all.GroupBy(GroupKey))
            {
                if (!string.IsNullOrWhiteSpace(rule.GroupBy) && string.IsNullOrEmpty(g.Key)) continue;
                var aEvents = g.Where(qa.Matches).ToList();
                if (aEvents.Count < Math.Max(1, rule.Threshold)) continue;
                var firstA = aEvents.Min(a => a.Timestamp);
                // a step-B event must occur at/after the first step-A event, within maxspan
                if (g.Any(b => qb.Matches(b) && b.Timestamp >= firstA && (b.Timestamp - firstA) <= maxspan))
                    Fire(rule, aEvents.Count, g.Key == "*" ? "" : g.Key, window, sequence: true);
            }
        }

        /// <summary>
        /// Resolve a rule's group key for an event. Supports a multi-field key (comma-separated GroupBy,
        /// e.g. <c>source.ip,user.name</c>) — all parts must be present or the event is skipped (returns "").
        /// </summary>
        private static string GroupValue(SiemRule rule, SiemEvent e)
        {
            if (string.IsNullOrWhiteSpace(rule.GroupBy)) return "";
            if (!rule.GroupBy.Contains(',')) return e.Get(rule.GroupBy) ?? "";
            var parts = rule.GroupBy.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            var vals = parts.Select(f => e.Get(f) ?? "").ToList();
            return vals.Any(string.IsNullOrEmpty) ? "" : string.Join("|", vals);
        }

        /// <summary>
        /// ML-style anomaly: bucket matching events into windows of <see cref="SiemRule.WindowMinutes"/>,
        /// build a mean+std-dev baseline from the prior <see cref="SiemRule.BaselineWindows"/> buckets, and
        /// fire when the current bucket's rate exceeds baseline + Threshold·σ. Optionally per GroupBy entity.
        /// </summary>
        private void EvaluateAnomaly(SiemRule rule, SiemQuery q, TimeSpan window, Func<SiemEvent, bool> keep)
        {
            int baseline = Math.Max(3, rule.BaselineWindows);
            double sigma = Math.Max(2, rule.Threshold);
            var span = TimeSpan.FromTicks(window.Ticks * (baseline + 1));
            var all = _store.Query(q, span, 500_000).Where(e => !IsAlertEvent(e) && keep(e)).ToList();
            if (all.Count == 0) return;

            var now = DateTime.Now;
            // bucket index 0 = current window, 1..baseline = history (older)
            int BucketOf(DateTime t) => (int)((now - t).TotalMilliseconds / window.TotalMilliseconds);

            string GroupKey(SiemEvent e) => string.IsNullOrWhiteSpace(rule.GroupBy) ? "*" : GroupValue(rule, e);
            foreach (var g in all.GroupBy(GroupKey))
            {
                if (!string.IsNullOrWhiteSpace(rule.GroupBy) && string.IsNullOrEmpty(g.Key)) continue;
                var counts = new int[baseline + 1];
                foreach (var e in g) { int b = BucketOf(e.Timestamp); if (b >= 0 && b <= baseline) counts[b]++; }

                int current = counts[0];
                if (current < 5) continue;   // floor: ignore tiny absolute counts to avoid noise

                // baseline stats over buckets 1..baseline
                double mean = 0; for (int i = 1; i <= baseline; i++) mean += counts[i]; mean /= baseline;
                double var2 = 0; for (int i = 1; i <= baseline; i++) { double d = counts[i] - mean; var2 += d * d; } var2 /= baseline;
                double std = Math.Sqrt(var2);
                double limit = mean + sigma * Math.Max(std, 1);   // floor σ so a flat baseline still needs a real spike

                if (current > limit && current > mean * 1.5)
                    Fire(rule, current, g.Key == "*" ? "" : g.Key, window, anomaly: true,
                         detail: $"rate {current} > baseline {mean:0.0}±{std:0.0} ({sigma:0}σ ⇒ {limit:0.0})");
            }
        }

        /// <summary>ECS observable fields checked against the indicator list when the rule sets no explicit GroupBy.</summary>
        private static readonly string[] ObservableFields =
            { "source.ip", "destination.ip", "user.name", "file.hash.sha256", "file.hash.md5", "url.domain", "dns.question.name", "host.name" };

        /// <summary>
        /// Threat-intel indicator-match: events in the window (optionally pre-filtered by Query) whose
        /// observable fields hit a managed IOC raise an alert per matched indicator value (≥Threshold hits).
        /// </summary>
        private void EvaluateIndicatorMatch(SiemRule rule, SiemQuery q, TimeSpan window, Func<SiemEvent, bool> keep)
        {
            var indicators = IndicatorSource();
            if (indicators == null || indicators.Count == 0) return;
            var lookup = new Dictionary<string, SiemIndicator>(StringComparer.OrdinalIgnoreCase);
            foreach (var i in indicators)
                if (!string.IsNullOrWhiteSpace(i.Value)) lookup[i.Value.Trim()] = i;
            if (lookup.Count == 0) return;

            var fields = string.IsNullOrWhiteSpace(rule.GroupBy) ? ObservableFields : new[] { rule.GroupBy };
            var matches = _store.Query(q, window, 200_000).Where(e => !IsAlertEvent(e) && keep(e)).ToList();

            // count event hits per matched indicator value (each event counted once)
            var hits = new Dictionary<string, (int count, SiemIndicator ind, string field)>(StringComparer.OrdinalIgnoreCase);
            foreach (var e in matches)
            {
                foreach (var f in fields)
                {
                    var v = e.Get(f);
                    if (string.IsNullOrEmpty(v) || !lookup.TryGetValue(v, out var ind)) continue;
                    hits[v] = hits.TryGetValue(v, out var cur) ? (cur.count + 1, cur.ind, cur.field) : (1, ind, f);
                    break;   // one event counts once even if several fields hit
                }
            }

            int min = Math.Max(1, rule.Threshold);
            foreach (var kv in hits)
                if (kv.Value.count >= min)
                    Fire(rule, kv.Value.count, kv.Key, window, indicator: true,
                         detail: $"{kv.Value.ind.Type} indicator '{kv.Key}' (source {kv.Value.ind.Source}) matched in {kv.Value.field}");
        }

        private static bool IsAlertEvent(SiemEvent e)
            => e.Fields.TryGetValue("event.kind", out var k) && k == "alert";

        /// <summary>Predicate that excludes events matching the rule's exception/allowlist query.</summary>
        private static Func<SiemEvent, bool> NotExcluded(SiemRule rule)
        {
            if (string.IsNullOrWhiteSpace(rule.ExcludeQuery)) return _ => true;
            var ex = SiemQuery.Parse(rule.ExcludeQuery);
            return e => !ex.Matches(e);
        }

        /// <summary>Build the human-readable alert message for a trip (shared by live alerts and preview/backtest).</summary>
        private static string BuildAlertMessage(SiemRule rule, int count, string group, TimeSpan window, bool newTerm, bool sequence, bool anomaly, bool indicator, string? detail)
            => indicator
                ? $"threat-intel match: {detail} ({count} event(s) in {window.TotalMinutes:0}m)"
                : anomaly
                ? $"anomalous spike{(group.Length > 0 ? $" for {rule.GroupBy}={group}" : "")}: {detail}"
                : sequence
                ? $"sequence matched{(group.Length > 0 ? $" for {rule.GroupBy}={group}" : "")}: {count}× step-A then step-B in {window.TotalMinutes:0}m"
                : newTerm
                ? $"new {rule.GroupBy} value '{group}' ({count} event(s) in {window.TotalMinutes:0}m, not seen before)"
                : group.Length > 0
                ? $"{count} events from {rule.GroupBy}={group} in {window.TotalMinutes:0}m (threshold {rule.Threshold})"
                : $"{count} matching events in {window.TotalMinutes:0}m (threshold {rule.Threshold})";

        private void Fire(SiemRule rule, int count, string group, TimeSpan window, bool newTerm = false, bool sequence = false, bool anomaly = false, bool indicator = false, string? detail = null)
        {
            // preview/backtest mode: record the hypothetical hit, no cooldown / store / webhook side-effects
            if (_previewSink != null)
            {
                _previewSink.Add(new SiemPreviewHit
                {
                    Count = count, Group = group,
                    Message = BuildAlertMessage(rule, count, group, window, newTerm, sequence, anomaly, indicator, detail),
                });
                return;
            }

            string key = rule.Id + "|" + group;
            // suppression/dedupe window: explicit SuppressMinutes overrides the evaluation window
            var suppress = rule.SuppressMinutes > 0 ? TimeSpan.FromMinutes(rule.SuppressMinutes) : window;
            lock (_lock)
            {
                // don't re-alert the same rule/group until the suppression window rolls over
                if (_cooldown.TryGetValue(key, out var last) && (DateTime.Now - last) < suppress) return;
                _cooldown[key] = DateTime.Now;
            }

            // risk score: base risk for the rule, bumped by how far the count overshot the threshold (cap 100)
            int risk = rule.EffectiveRisk;
            if (rule.Threshold > 0 && count > rule.Threshold)
                risk = Math.Min(100, risk + (int)Math.Round(Math.Min(20, 6 * Math.Log2((double)count / rule.Threshold + 1))));

            string msg = BuildAlertMessage(rule, count, group, window, newTerm, sequence, anomaly, indicator, detail);

            var alert = new SiemAlert
            {
                RuleId = rule.Id, RuleName = rule.Name, Timestamp = DateTime.Now, Severity = rule.Severity,
                Message = msg, Count = count, GroupValue = group, MitreId = rule.MitreId, MitreName = rule.MitreName, MitreTactic = rule.MitreTactic,
                RiskScore = risk,
            };
            lock (_lock) { _alerts.AddFirst(alert); while (_alerts.Count > AlertCapacity) _alerts.RemoveLast(); }

            // also surface it as an event so it appears in Discover / dashboards
            var ev = new SiemEvent
            {
                Severity = rule.Severity, Category = "alert", EventType = "Detection: " + rule.Name,
                Message = $"{rule.Name} — {msg}", Source = "SIEM Rules", Host = "SIEM",
            };
            ev.Fields["event.kind"] = "alert";
            ev.Fields["rule.name"] = rule.Name;
            ev.Fields["alert.count"] = count.ToString();
            ev.Fields["event.risk_score"] = risk.ToString();
            if (!string.IsNullOrEmpty(rule.MitreId)) { ev.Fields["threat.technique.id"] = rule.MitreId; ev.Fields["threat.technique.name"] = rule.MitreName; }
            if (indicator) { ev.Fields["threat.matched"] = "true"; ev.Fields["threat.indicator"] = group; }
            if (group.Length > 0 && !string.IsNullOrWhiteSpace(rule.GroupBy)) ev.Fields[rule.GroupBy] = group;
            _store.Add(ev, applyPipeline: false);

            if (!string.IsNullOrWhiteSpace(rule.WebhookUrl)) SiemWebhook.Send(rule.WebhookUrl, alert);
            if (!string.IsNullOrWhiteSpace(rule.EmailTo)) SiemEmail.Send(SiemEmailSettings.Current, rule.EmailTo, alert);

            AlertRaised?.Invoke(this, alert);
            AlertsChanged?.Invoke();
        }
    }
}
