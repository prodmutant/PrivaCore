using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;

namespace PROSCANNERCONT.Models
{
    public enum SiemSeverity { Info = 0, Low = 1, Medium = 2, High = 3, Critical = 4 }

    /// <summary>
    /// A normalised security event (one document in the SIEM index). Modelled loosely on the
    /// Elastic Common Schema (ECS): a handful of first-class columns plus an open
    /// <see cref="Fields"/> bag of dotted field names (user.name, source.ip, event.action, …).
    /// The Discover view treats every event as a flat document of fields.
    /// </summary>
    public class SiemEvent
    {
        public long Id { get; set; }
        public DateTime Timestamp { get; set; } = DateTime.Now;
        public string Source { get; set; } = "";       // origin host / collector ("WinEventLog", a syslog IP, a module)
        public string Host { get; set; } = "";          // machine the event is about
        public SiemSeverity Severity { get; set; } = SiemSeverity.Info;
        public string Category { get; set; } = "";      // Authentication, Process, Network, System, Threat, ...
        public string EventType { get; set; } = "";     // "4625 Failed Logon", "ProcessCreate", ...
        public string Message { get; set; } = "";
        public Dictionary<string, string> Fields { get; set; } = new();
        public string Raw { get; set; } = "";

        // ── display helpers (bound by the dashboard) ──
        public string TimeText => Timestamp.ToString("MMM dd, HH:mm:ss.fff");
        public string SeverityText => Severity.ToString();
        public string SeverityColor => Severity switch
        {
            SiemSeverity.Critical => "#F85149",
            SiemSeverity.High     => "#FF7B72",
            SiemSeverity.Medium   => "#E3B341",
            SiemSeverity.Low      => "#58A6FF",
            _                     => "#8B949E",
        };

        public string FieldsText
        {
            get
            {
                if (Fields.Count == 0) return "";
                return string.Join("  ", Fields.Select(kv => $"{kv.Key}={kv.Value}"));
            }
        }

        // ── ECS-style flat document view (used by Discover) ──────────────────
        /// <summary>The canonical first-class fields, in display order, before the open bag.</summary>
        public static readonly string[] CoreFieldOrder =
        {
            "@timestamp", "log.level", "event.category", "event.action", "host.name", "observer.name", "message",
        };

        /// <summary>The full flat document: canonical fields followed by the open field bag (sorted).</summary>
        public IEnumerable<KeyValuePair<string, string>> AllFields()
        {
            yield return new("@timestamp", Timestamp.ToString("yyyy-MM-dd HH:mm:ss.fff"));
            yield return new("log.level", SeverityText);
            if (!string.IsNullOrEmpty(Category)) yield return new("event.category", Category);
            if (!string.IsNullOrEmpty(EventType)) yield return new("event.action", EventType);
            if (!string.IsNullOrEmpty(Host)) yield return new("host.name", Host);
            if (!string.IsNullOrEmpty(Source)) yield return new("observer.name", Source);
            if (!string.IsNullOrEmpty(Message)) yield return new("message", Message);
            foreach (var kv in Fields.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase))
                yield return kv;
            // computed runtime fields (only those that resolve to a value for this event)
            var rt = RuntimeFieldNames?.Invoke();
            if (rt != null)
                foreach (var name in rt)
                {
                    if (Fields.ContainsKey(name)) continue;   // a real field shadows a runtime field of the same name
                    var val = RuntimeFieldResolver?.Invoke(this, name);
                    if (!string.IsNullOrEmpty(val)) yield return new(name, val);
                }
            if (!string.IsNullOrEmpty(Raw)) yield return new("event.original", Raw);
        }

        /// <summary>
        /// Computes a runtime/scripted field value for an event (ECS "runtime fields"): given the event and
        /// a field name, returns the derived value or null. Assigned by the SIEM side so this model keeps no
        /// dependency on the runtime-field store. Null ⇒ no runtime fields on this host.
        /// </summary>
        public static Func<SiemEvent, string, string?>? RuntimeFieldResolver;

        /// <summary>The names of the active runtime fields (so they appear as columns / in the fields sidebar).</summary>
        public static Func<IReadOnlyCollection<string>>? RuntimeFieldNames;

        /// <summary>Read any field by its dotted name (canonical, the open bag, or a computed runtime field).</summary>
        public string? Get(string field) => field switch
        {
            "@timestamp" => Timestamp.ToString("yyyy-MM-dd HH:mm:ss.fff"),
            "log.level" or "severity" => SeverityText,
            "event.category" or "category" => Category,
            "event.action" or "event.type" => EventType,
            "host.name" or "host" => Host,
            "observer.name" or "source" => Source,
            "message" => Message,
            "event.original" or "raw" => Raw,
            _ => Fields.TryGetValue(field, out var v) ? v : RuntimeFieldResolver?.Invoke(this, field),
        };

        /// <summary>A compact one-line summary of the most useful fields (the Discover "Document" column).</summary>
        public string Summary()
        {
            var parts = new List<string>();
            foreach (var kv in AllFields())
            {
                if (kv.Key is "@timestamp" or "event.original" or "message") continue;
                parts.Add($"{kv.Key}: {kv.Value}");
                if (parts.Count >= 6) break;
            }
            if (!string.IsNullOrEmpty(Message)) parts.Insert(0, Message);
            return string.Join("   ", parts);
        }

        /// <summary>A deep copy (used for pipeline dry-run so the original is untouched).</summary>
        public SiemEvent Clone() => new()
        {
            Timestamp = Timestamp, Source = Source, Host = Host, Severity = Severity,
            Category = Category, EventType = EventType, Message = Message, Raw = Raw,
            Fields = new Dictionary<string, string>(Fields),
        };

        public string ToJson()
        {
            var doc = new Dictionary<string, object>();
            foreach (var kv in AllFields())
                doc[kv.Key] = kv.Value;
            return JsonSerializer.Serialize(doc, new JsonSerializerOptions { WriteIndented = true });
        }
    }
}
