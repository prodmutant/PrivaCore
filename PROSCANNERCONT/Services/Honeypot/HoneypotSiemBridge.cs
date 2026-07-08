using System;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Services.Siem;

namespace PROSCANNERCONT.Services.Honeypot
{
    /// <summary>
    /// Forwards captured honeypot interactions into the SIEM index as normalised <see cref="SiemEvent"/>s,
    /// so decoy hits show up in Discover, drive detection rules, and enrich threat-intel — the honeypot
    /// stops being an island. Kept separate from the capture engine so the engine has no SIEM dependency.
    /// </summary>
    public static class HoneypotSiemBridge
    {
        private static Action<HoneypotHit>? _handler;
        public static bool Attached => _handler != null;

        public static void Attach(HoneypotCaptureService? svc = null)
        {
            svc ??= HoneypotCaptureService.Instance;
            if (_handler != null) return;
            _handler = hit =>
            {
                try { SiemStoreProvider.Current.Add(ToEvent(hit)); } catch { }
                // Promote the source to a threat-intel IOC only on a REAL interaction — credentials, a
                // classified technique, or an actual payload. A bare TCP connect / port scan carries none
                // of these, so it no longer floods the indicator store (and the detection rules it feeds).
                try
                {
                    if (!string.IsNullOrEmpty(hit.SourceIp) && hit.SourceIp != "?" && WorthPromoting(hit))
                        SiemIndicatorStore.Instance.Add(ToIndicator(hit));
                }
                catch { }
            };
            svc.HitRecorded += _handler;
        }

        public static void Detach(HoneypotCaptureService? svc = null)
        {
            svc ??= HoneypotCaptureService.Instance;
            if (_handler != null) { svc.HitRecorded -= _handler; _handler = null; }
        }

        public static SiemEvent ToEvent(HoneypotHit hit)
        {
            var ev = new SiemEvent
            {
                Timestamp = hit.Timestamp,
                Source = "Honeypot",
                Host = Environment.MachineName,
                Severity = ParseSeverity(hit.Severity),
                Category = "Honeypot",
                EventType = $"{hit.ServiceName} interaction",
                Message = hit.Summary,
                Raw = hit.Data ?? "",
            };
            ev.Fields["event.category"] = "intrusion_detection";
            ev.Fields["event.dataset"] = "honeypot." + hit.Service.ToString().ToLowerInvariant();
            ev.Fields["source.ip"] = hit.SourceIp;
            if (hit.SourcePort > 0) ev.Fields["source.port"] = hit.SourcePort.ToString();
            ev.Fields["honeypot.service"] = hit.ServiceName;
            ev.Fields["honeypot.port"] = hit.Port.ToString();
            if (!string.IsNullOrEmpty(hit.Username)) ev.Fields["user.name"] = hit.Username!;
            if (!string.IsNullOrEmpty(hit.Password)) ev.Fields["honeypot.password"] = hit.Password!;
            return ev;
        }

        /// <summary>
        /// True when a hit represents a real interaction worth turning into an IOC: it carried
        /// credentials, a classifier tag (an attack technique), or an actual payload. A contentless
        /// TCP connect (a scanner touching the port) returns false.
        /// </summary>
        public static bool WorthPromoting(HoneypotHit hit)
            => hit.HasCredentials
               || (hit.Tags != null && hit.Tags.Count > 0)
               || !string.IsNullOrWhiteSpace(hit.Data);

        /// <summary>Map a hit's attacker IP to a threat-intel indicator (deduped by the store).</summary>
        public static SiemIndicator ToIndicator(HoneypotHit hit) => new()
        {
            Value = hit.SourceIp,
            Type = "ip",
            Source = "honeypot",
            Note = $"Honeypot {hit.ServiceName} hit" + (hit.HasCredentials ? " (credentials)" : ""),
        };

        private static SiemSeverity ParseSeverity(string s)
            => Enum.TryParse<SiemSeverity>(s, ignoreCase: true, out var v) ? v : SiemSeverity.Medium;
    }
}
