using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;

namespace PROSCANNERCONT.Services.Siem
{
    /// <summary>The Elasticsearch-style mapping type inferred for a Discover field.</summary>
    public enum SiemFieldType { Keyword, Text, Number, Ip, Date, Boolean, Geo }

    /// <summary>
    /// Infers an Elasticsearch-like field mapping (keyword / text / number / ip / date / boolean / geo)
    /// from a field's name and a sample of its values. Drives the Discover field-type icons and the
    /// per-field Visualize shortcut. Lightweight and best-effort — never throws.
    /// </summary>
    public static class SiemFieldTypes
    {
        /// <summary>
        /// Optional explicit-mapping override (ES "mappings"): given a field name, returns a pinned type or
        /// null to fall back to inference. Assigned by <c>SiemFieldMappingStore</c> so a user-set mapping
        /// wins over the heuristics everywhere (field icons, Visualize, value formatting).
        /// </summary>
        public static Func<string, SiemFieldType?>? Override;

        /// <summary>Infer a type from the field name alone (cheap; no value sampling).</summary>
        public static SiemFieldType FromName(string field)
        {
            if (Override?.Invoke(field) is { } pinned) return pinned;
            var f = field.ToLowerInvariant();
            if (f is "@timestamp" || f.EndsWith(".time") || f.EndsWith("timestamp") || f.Contains("date") || f.EndsWith(".created") || f.EndsWith(".start") || f.EndsWith(".end")) return SiemFieldType.Date;
            if (f.EndsWith(".ip") || f == "ip" || f.Contains("address.ip")) return SiemFieldType.Ip;
            if (f.Contains(".geo.") || f.EndsWith(".location") || f.Contains("geo.location")) return SiemFieldType.Geo;
            if (f.EndsWith(".port") || f.EndsWith(".pid") || f.EndsWith(".bytes") || f.EndsWith(".count") || f.EndsWith("_count")
                || f.EndsWith(".code") || f.EndsWith(".duration") || f.EndsWith("risk_score") || f.EndsWith(".size")) return SiemFieldType.Number;
            if (f.EndsWith(".enabled") || f.Contains("is_") || f.EndsWith(".matched")) return SiemFieldType.Boolean;
            return SiemFieldType.Keyword;
        }

        /// <summary>Infer a type from the name plus a few sample values (more accurate).</summary>
        public static SiemFieldType Infer(string field, IEnumerable<string> sampleValues)
        {
            if (Override?.Invoke(field) is { } pinned) return pinned;
            var byName = FromName(field);
            if (byName is SiemFieldType.Date or SiemFieldType.Ip or SiemFieldType.Geo) return byName;

            var samples = sampleValues.Where(s => !string.IsNullOrEmpty(s)).Take(20).ToList();
            if (samples.Count == 0) return byName;

            if (samples.All(IsBool)) return SiemFieldType.Boolean;
            if (samples.All(IsNumber)) return SiemFieldType.Number;
            if (samples.All(IsIp)) return SiemFieldType.Ip;
            if (samples.All(IsDate)) return SiemFieldType.Date;
            // long / spaced values read as full-text; short tokens are keywords
            if (samples.Any(s => s.Length > 60 || s.Count(ch => ch == ' ') >= 4)) return SiemFieldType.Text;
            return SiemFieldType.Keyword;
        }

        public static string IconName(SiemFieldType t) => t switch
        {
            SiemFieldType.Date    => "Clock",
            SiemFieldType.Ip      => "NetworkWired",
            SiemFieldType.Number  => "Hashtag",
            SiemFieldType.Boolean => "ToggleOn",
            SiemFieldType.Geo     => "EarthAmericas",
            SiemFieldType.Text    => "AlignLeft",
            _                     => "Font",   // keyword
        };

        public static string Label(SiemFieldType t) => t switch
        {
            SiemFieldType.Date => "date",
            SiemFieldType.Ip => "ip",
            SiemFieldType.Number => "number",
            SiemFieldType.Boolean => "boolean",
            SiemFieldType.Geo => "geo_point",
            SiemFieldType.Text => "text",
            _ => "keyword",
        };

        private static bool IsBool(string s) => s is "true" or "false" or "True" or "False" or "0" or "1";
        private static bool IsNumber(string s) => double.TryParse(s, NumberStyles.Any, CultureInfo.InvariantCulture, out _);
        private static bool IsIp(string s) => IPAddress.TryParse(s, out _);
        private static bool IsDate(string s) => DateTime.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.None, out _);
    }
}
