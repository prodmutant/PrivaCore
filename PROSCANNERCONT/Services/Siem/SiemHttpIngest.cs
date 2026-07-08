using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text.Json;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Services.Siem
{
    /// <summary>
    /// Parses an HTTP ingest body (JSON) into <see cref="SiemEvent"/>s. Accepts a single object or an
    /// array of objects. Known keys map to first-class columns; everything else lands in the field bag.
    /// Static + pure so it's unit-testable independent of the HTTP listener.
    /// </summary>
    public static class SiemHttpIngest
    {
        /// <summary>
        /// Decide whether an HTTP ingest request is authorised. When <paramref name="configured"/> is
        /// empty the endpoint is open (trusted-network). Otherwise the request must present the secret
        /// via <c>X-Ingest-Token</c> or <c>Authorization: Bearer</c>, compared in constant time.
        /// </summary>
        public static bool TokenAccepted(string? configured, string? xIngestToken, string? authorization)
        {
            var token = configured ?? "";
            if (token.Length == 0) return true;

            string presented = (xIngestToken ?? "").Trim();
            if (presented.Length == 0)
            {
                var auth = authorization ?? "";
                if (auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) presented = auth["Bearer ".Length..].Trim();
            }
            var a = System.Text.Encoding.UTF8.GetBytes(presented);
            var b = System.Text.Encoding.UTF8.GetBytes(token);
            if (a.Length != b.Length) return false;
            return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(a, b);
        }

        public static List<SiemEvent> Parse(string json, string fromIp = "http")
        {
            var list = new List<SiemEvent>();
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.ValueKind == JsonValueKind.Array)
            {
                foreach (var el in root.EnumerateArray())
                    if (el.ValueKind == JsonValueKind.Object) list.Add(One(el, fromIp));
            }
            else if (root.ValueKind == JsonValueKind.Object)
            {
                list.Add(One(root, fromIp));
            }
            return list;
        }

        private static SiemEvent One(JsonElement o, string fromIp)
        {
            var e = new SiemEvent { Source = fromIp, Host = fromIp };
            foreach (var p in o.EnumerateObject())
            {
                string key = p.Name;
                string val = p.Value.ValueKind switch
                {
                    JsonValueKind.String => p.Value.GetString() ?? "",
                    JsonValueKind.Number => p.Value.ToString(),
                    JsonValueKind.True => "true",
                    JsonValueKind.False => "false",
                    JsonValueKind.Null => "",
                    _ => p.Value.GetRawText(),
                };

                switch (key.ToLowerInvariant())
                {
                    case "message" or "msg": e.Message = val; break;
                    case "host" or "host.name": e.Host = val; e.Fields["host.name"] = val; break;
                    case "source" or "observer.name": e.Source = val; break;
                    case "category" or "event.category": e.Category = val; break;
                    case "type" or "eventtype" or "event.action": e.EventType = val; break;
                    case "severity" or "log.level": e.Severity = ParseSeverity(val); break;
                    case "timestamp" or "@timestamp":
                        if (DateTime.TryParse(val, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out var ts)) e.Timestamp = ts;
                        break;
                    case "fields" when p.Value.ValueKind == JsonValueKind.Object:
                        foreach (var f in p.Value.EnumerateObject())
                            e.Fields[f.Name] = f.Value.ValueKind == JsonValueKind.String ? (f.Value.GetString() ?? "") : f.Value.ToString();
                        break;
                    default:
                        e.Fields[key] = val;   // any other top-level key becomes a field
                        break;
                }
            }
            if (string.IsNullOrEmpty(e.Category)) e.Category = "http";
            if (string.IsNullOrEmpty(e.EventType)) e.EventType = "http.ingest";
            e.Fields["event.dataset"] = "http";
            return e;
        }

        private static SiemSeverity ParseSeverity(string v)
        {
            if (Enum.TryParse<SiemSeverity>(v, true, out var s)) return s;
            // numeric (0-4) or syslog-ish
            if (int.TryParse(v, out var n)) return n switch { >= 4 => SiemSeverity.Critical, 3 => SiemSeverity.High, 2 => SiemSeverity.Medium, 1 => SiemSeverity.Low, _ => SiemSeverity.Info };
            return v.ToLowerInvariant() switch
            {
                "crit" or "critical" or "emergency" or "alert" => SiemSeverity.Critical,
                "err" or "error" or "high" => SiemSeverity.High,
                "warn" or "warning" or "medium" => SiemSeverity.Medium,
                "notice" or "low" => SiemSeverity.Low,
                _ => SiemSeverity.Info,
            };
        }
    }
}
