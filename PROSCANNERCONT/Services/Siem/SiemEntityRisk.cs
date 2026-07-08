using System;
using System.Collections.Generic;
using System.Linq;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Services.Siem
{
    public enum SiemEntityKind { Host, User }

    /// <summary>
    /// Entity analytics (Elastic "host/user risk"): per-host and per-user roll-ups with a
    /// severity-weighted risk score, used by the Entities investigation view.
    /// </summary>
    public sealed class SiemEntityStat
    {
        public string Name { get; set; } = "";
        public SiemEntityKind Kind { get; set; }
        public int Events { get; set; }
        public int Critical { get; set; }
        public int High { get; set; }
        public int Medium { get; set; }
        public int Low { get; set; }
        public DateTime LastSeen { get; set; }
        public int RiskScore { get; set; }   // 0–100

        public string KindText => Kind == SiemEntityKind.Host ? "host" : "user";
        public string EventsText => Events.ToString("N0");
        public string CriticalText => Critical.ToString("N0");
        public string HighText => High.ToString("N0");
        public string RiskText => RiskScore.ToString();

        public string RiskLevel => RiskScore switch
        {
            >= 75 => "Critical",
            >= 50 => "High",
            >= 25 => "Medium",
            >= 10 => "Low",
            _ => "Minimal",
        };

        public string RiskColor => RiskScore switch
        {
            >= 75 => "#F85149",
            >= 50 => "#FF7B72",
            >= 25 => "#E3B341",
            >= 10 => "#58A6FF",
            _ => "#8B949E",
        };

        public string LastSeenText
        {
            get
            {
                var ago = DateTime.Now - LastSeen;
                if (ago.TotalSeconds < 60) return $"{(int)ago.TotalSeconds}s ago";
                if (ago.TotalMinutes < 60) return $"{(int)ago.TotalMinutes}m ago";
                if (ago.TotalHours < 24) return $"{(int)ago.TotalHours}h ago";
                return LastSeen.ToString("MM-dd HH:mm");
            }
        }
    }

    /// <summary>Computes per-entity risk from the event store (severity-weighted).</summary>
    public static class SiemEntityRisk
    {
        // severity weights — escalate sharply with severity (Elastic-style risk contribution)
        private static int Weight(SiemSeverity s) => s switch
        {
            SiemSeverity.Critical => 30,
            SiemSeverity.High => 12,
            SiemSeverity.Medium => 4,
            SiemSeverity.Low => 1,
            _ => 0,
        };

        public static List<SiemEntityStat> Entities(SiemEntityKind kind, SiemRange? range, int top = 250)
        {
            var snap = SiemStoreProvider.Current.Snapshot();
            var map = new Dictionary<string, SiemEntityStat>(StringComparer.OrdinalIgnoreCase);
            var raw = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);

            foreach (var e in snap)
            {
                if (!(range?.Contains(e.Timestamp) ?? true)) continue;
                // skip synthetic alert events so a "SIEM" pseudo-entity isn't created
                if (e.Fields.TryGetValue("event.kind", out var k) && k == "alert") continue;

                string name = kind == SiemEntityKind.Host ? e.Host : (e.Get("user.name") ?? "");
                if (string.IsNullOrWhiteSpace(name)) continue;

                if (!map.TryGetValue(name, out var st))
                { map[name] = st = new SiemEntityStat { Name = name, Kind = kind }; raw[name] = 0; }

                st.Events++;
                switch (e.Severity)
                {
                    case SiemSeverity.Critical: st.Critical++; break;
                    case SiemSeverity.High: st.High++; break;
                    case SiemSeverity.Medium: st.Medium++; break;
                    case SiemSeverity.Low: st.Low++; break;
                }
                raw[name] += Weight(e.Severity);
                if (e.Timestamp > st.LastSeen) st.LastSeen = e.Timestamp;
            }

            foreach (var st in map.Values)
                st.RiskScore = (int)Math.Min(100, raw[st.Name]);

            return map.Values
                .OrderByDescending(s => s.RiskScore)
                .ThenByDescending(s => s.Events)
                .Take(top)
                .ToList();
        }

        public static List<SiemEntityStat> Hosts(SiemRange? range) => Entities(SiemEntityKind.Host, range);
        public static List<SiemEntityStat> Users(SiemRange? range) => Entities(SiemEntityKind.User, range);
    }
}
