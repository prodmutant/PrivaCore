using System;

namespace PROSCANNERCONT.Models
{
    /// <summary>How a detection rule decides to fire.</summary>
    public enum SiemRuleType
    {
        Threshold,        // total matching events in the window ≥ Threshold
        GroupThreshold,   // matching events grouped by GroupBy field; any group ≥ Threshold
        NewTerms,         // a GroupBy value appears in the window that was never seen before in history
        Sequence,         // EQL-style: ≥Threshold of [Query] then a [SecondQuery] event from same GroupBy, in order
        Anomaly,          // ML-style: current window's rate exceeds the rolling baseline by Threshold std-devs
        IndicatorMatch,   // threat-intel: [Query] events whose observable fields hit a managed IOC fire per indicator
    }

    /// <summary>
    /// A SIEM detection / correlation rule — the Elastic Security "rule" equivalent. A saved query
    /// plus a threshold and a time window; the rule engine evaluates it on a timer over the store
    /// and raises a <see cref="SiemAlert"/> (and an alert event) when it trips.
    /// </summary>
    public sealed class SiemRule
    {
        public string Id { get; set; } = Guid.NewGuid().ToString("N");
        public string Name { get; set; } = "";
        public bool Enabled { get; set; } = true;
        public string Query { get; set; } = "";                       // KQL-ish, same as Discover (step A for Sequence)
        public string SecondQuery { get; set; } = "";                 // Sequence: the "then" step B
        public string ExcludeQuery { get; set; } = "";                // exception/allowlist: matching events are ignored
        public SiemRuleType Type { get; set; } = SiemRuleType.Threshold;
        public int Threshold { get; set; } = 10;
        public int WindowMinutes { get; set; } = 5;
        public string GroupBy { get; set; } = "";                     // e.g. source.ip (GroupThreshold)
        public SiemSeverity Severity { get; set; } = SiemSeverity.High;
        public string MitreId { get; set; } = "";                     // e.g. T1110
        public string MitreName { get; set; } = "";                   // e.g. Brute Force
        public string MitreTactic { get; set; } = "";                 // e.g. Credential Access
        public string WebhookUrl { get; set; } = "";                  // optional: POST the alert here when it fires
        public string EmailTo { get; set; } = "";                     // optional: email the alert here (needs SMTP configured)
        public int RiskScore { get; set; } = 0;                       // 0-100 base risk; 0 = derive from severity
        public int SuppressMinutes { get; set; } = 0;                 // dedupe/suppression by group; 0 = use the window
        public int BaselineWindows { get; set; } = 12;                // Anomaly: how many prior windows form the baseline
        public int MaxSpanMinutes { get; set; } = 0;                  // Sequence: max minutes from step-A to step-B; 0 = anywhere in the window

        /// <summary>Effective base risk (0-100): explicit if set, else mapped from severity.</summary>
        public int EffectiveRisk => RiskScore > 0 ? Math.Clamp(RiskScore, 0, 100) : Severity switch
        {
            SiemSeverity.Critical => 95,
            SiemSeverity.High     => 73,
            SiemSeverity.Medium   => 50,
            SiemSeverity.Low      => 25,
            _                     => 10,
        };

        public string MitreText => string.IsNullOrEmpty(MitreId) ? "" :
            (string.IsNullOrEmpty(MitreName) ? MitreId : $"{MitreId} · {MitreName}");

        public string Summary()
        {
            string q = string.IsNullOrWhiteSpace(Query) ? "any event" : Query;
            return Type switch
            {
                SiemRuleType.Anomaly => $"[{q}] rate >{Math.Max(2, Threshold)}σ above the {BaselineWindows}×{WindowMinutes}m baseline{(string.IsNullOrWhiteSpace(GroupBy) ? "" : $" per {GroupBy}")}",
                SiemRuleType.IndicatorMatch => $"[{q}] {(string.IsNullOrWhiteSpace(GroupBy) ? "observables" : GroupBy)} hit a threat-intel indicator (≥{Math.Max(1, Threshold)} in {WindowMinutes}m)",
                SiemRuleType.NewTerms => $"new {GroupBy} value for [{q}] (last {WindowMinutes}m vs history)",
                SiemRuleType.Sequence => $"≥{Threshold} [{q}] then [{(string.IsNullOrWhiteSpace(SecondQuery) ? "any" : SecondQuery)}] from one {(string.IsNullOrWhiteSpace(GroupBy) ? "(any)" : GroupBy)}{(MaxSpanMinutes > 0 ? $" within {MaxSpanMinutes}m" : "")} in {WindowMinutes}m",
                SiemRuleType.GroupThreshold when !string.IsNullOrWhiteSpace(GroupBy) => $"≥{Threshold} [{q}] from one {GroupBy} in {WindowMinutes}m",
                _ => $"≥{Threshold} [{q}] in {WindowMinutes}m",
            };
        }

        public string SeverityColor => Severity switch
        {
            SiemSeverity.Critical => "#F85149",
            SiemSeverity.High     => "#FF7B72",
            SiemSeverity.Medium   => "#E3B341",
            SiemSeverity.Low      => "#58A6FF",
            _                     => "#8B949E",
        };
    }
}
