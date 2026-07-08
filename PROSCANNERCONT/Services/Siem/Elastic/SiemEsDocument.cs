using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text.Json;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Services.Siem.Elastic
{
    /// <summary>
    /// Maps a <see cref="SiemEvent"/> to/from an Elasticsearch <c>_source</c> document. ECS-style first-class
    /// fields are written as dotted keys alongside the open field bag, plus a numeric
    /// <c>siem.severity_level</c> (0–4) so severity range queries map onto an ES <c>range</c>.
    /// </summary>
    public static class SiemEsDocument
    {
        /// <summary>The numeric severity field used for range filters (Info=0 … Critical=4).</summary>
        public const string SeverityLevelField = "siem.severity_level";
        public const string TimestampField = "@timestamp";

        public static Dictionary<string, object?> ToSource(SiemEvent e)
        {
            var doc = new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                [TimestampField] = e.Timestamp.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture),
                ["log.level"] = e.Severity.ToString(),
                [SeverityLevelField] = (int)e.Severity,
                ["event.category"] = e.Category,
                ["event.action"] = e.EventType,
                ["host.name"] = e.Host,
                ["observer.name"] = e.Source,
                ["message"] = e.Message,
            };
            if (!string.IsNullOrEmpty(e.Raw)) doc["event.original"] = e.Raw;
            // the open field bag (dotted keys) — do not clobber the canonical fields above
            foreach (var kv in e.Fields)
                if (!doc.ContainsKey(kv.Key)) doc[kv.Key] = kv.Value;
            return doc;
        }

        public static string ToJson(SiemEvent e) => JsonSerializer.Serialize(ToSource(e));

        /// <summary>Rebuild a <see cref="SiemEvent"/> from an ES hit's <c>_source</c>.</summary>
        public static SiemEvent FromSource(JsonElement source)
        {
            var e = new SiemEvent();
            foreach (var p in source.EnumerateObject())
            {
                string val = p.Value.ValueKind switch
                {
                    JsonValueKind.String => p.Value.GetString() ?? "",
                    JsonValueKind.Number => p.Value.ToString(),
                    JsonValueKind.True => "true",
                    JsonValueKind.False => "false",
                    JsonValueKind.Null => "",
                    _ => p.Value.GetRawText(),
                };
                switch (p.Name)
                {
                    case TimestampField:
                        if (DateTime.TryParse(val, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var ts)) e.Timestamp = ts.ToLocalTime();
                        break;
                    case "log.level":
                        if (Enum.TryParse<SiemSeverity>(val, true, out var sev)) e.Severity = sev;
                        break;
                    case SeverityLevelField: break;   // derived; ignore on the way back
                    case "event.category": e.Category = val; break;
                    case "event.action": e.EventType = val; break;
                    case "host.name": e.Host = val; break;
                    case "observer.name": e.Source = val; break;
                    case "message": e.Message = val; break;
                    case "event.original": e.Raw = val; break;
                    default: e.Fields[p.Name] = val; break;
                }
            }
            return e;
        }
    }
}
