using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace PROSCANNERCONT.Models
{
    /// <summary>
    /// A small grok engine (Logstash / Elastic ingest "grok" processor): expands
    /// <c>%{PATTERN:field}</c> / <c>%{PATTERN}</c> tokens into a .NET named-group regex using a
    /// built-in library of common patterns (IP, NUMBER, WORD, TIMESTAMP_ISO8601, …), then runs it
    /// over a source field to lift the captured semantics into event fields.
    ///
    /// Field names in grok (e.g. <c>source.ip</c>) aren't valid .NET regex group identifiers, so
    /// each capture is given a safe synthetic group name (<c>g0</c>, <c>g1</c>, …) mapped back to
    /// the real field name on extraction.
    /// </summary>
    public static class SiemGrok
    {
        /// <summary>Core grok pattern library. Values may reference other <c>%{NAME}</c> patterns (expanded recursively).</summary>
        public static readonly IReadOnlyDictionary<string, string> Patterns = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["WORD"] = @"\b\w+\b",
            ["NOTSPACE"] = @"\S+",
            ["SPACE"] = @"\s*",
            ["DATA"] = @".*?",
            ["GREEDYDATA"] = @".*",
            ["INT"] = @"(?:[+-]?(?:[0-9]+))",
            ["NUMBER"] = @"(?:[+-]?(?:[0-9]+(?:\.[0-9]+)?))",
            ["BASE10NUM"] = @"(?:[+-]?(?:[0-9]+(?:\.[0-9]+)?))",
            ["POSINT"] = @"\b(?:[1-9][0-9]*)\b",
            ["NONNEGINT"] = @"\b(?:[0-9]+)\b",
            ["USERNAME"] = @"[a-zA-Z0-9._-]+",
            ["USER"] = "%{USERNAME}",
            ["EMAILLOCALPART"] = @"[a-zA-Z0-9!#$%&'*+\-/=?^_`{|}~]+",
            ["HOSTNAME"] = @"\b(?:[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\.(?:[0-9A-Za-z][0-9A-Za-z-]{0,62}))*\b",
            ["EMAILADDRESS"] = "%{EMAILLOCALPART}@%{HOSTNAME}",
            ["IPV4"] = @"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)",
            // permissive: hextets separated by ':' with empty groups allowed for '::' compression
            ["IPV6"] = @"(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}",
            ["IP"] = "(?:%{IPV6}|%{IPV4})",
            ["MAC"] = @"(?:(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})",
            ["LOGLEVEL"] = @"(?:[Aa]lert|TRACE|DEBUG|NOTICE|INFO(?:RMATION)?|WARN(?:ING)?|ERR(?:OR)?|CRIT(?:ICAL)?|FATAL|SEVERE|EMERG(?:ENCY)?)",
            ["QUOTEDSTRING"] = "(?:\"(?:\\\\.|[^\\\\\"]+)*\"|'(?:\\\\.|[^\\\\']+)*')",
            ["UUID"] = @"[A-Fa-f0-9]{8}-(?:[A-Fa-f0-9]{4}-){3}[A-Fa-f0-9]{12}",
            ["URIPROTO"] = @"[A-Za-z]+(?:\+[A-Za-z+]+)?",
            ["URIHOST"] = @"%{HOSTNAME}(?::%{POSINT})?",
            ["URIPATH"] = @"(?:/[A-Za-z0-9$.+!*'(){},~:;=@#%&_\-]*)+",
            ["URIPATHPARAM"] = @"%{URIPATH}(?:\?\S+)?",
            ["MONTHNUM"] = @"(?:0?[1-9]|1[0-2])",
            ["MONTHDAY"] = @"(?:(?:0[1-9])|(?:[12][0-9])|(?:3[01])|[1-9])",
            ["YEAR"] = @"(?:\d\d){1,2}",
            ["HOUR"] = @"(?:2[0123]|[01]?[0-9])",
            ["MINUTE"] = @"(?:[0-5][0-9])",
            ["SECOND"] = @"(?:(?:[0-5]?[0-9]|60)(?:[:.,][0-9]+)?)",
            ["TIME"] = @"%{HOUR}:%{MINUTE}:%{SECOND}",
            ["TIMESTAMP_ISO8601"] = @"%{YEAR}-%{MONTHNUM}-%{MONTHDAY}[T ]%{HOUR}:%{MINUTE}(?::?%{SECOND})?(?:Z|[+-]%{HOUR}(?::?%{MINUTE})?)?",
        };

        // %{NAME}  or  %{NAME:field.name}
        private static readonly Regex TokenRx = new(@"%\{(\w+)(?::([A-Za-z0-9_.\[\]@-]+))?\}", RegexOptions.CultureInvariant);

        /// <summary>A grok expression compiled to a regex + the synthetic-group → field-name map.</summary>
        public sealed class CompiledGrok
        {
            public Regex? Regex { get; }
            public IReadOnlyDictionary<string, string> GroupToField { get; }
            public bool IsValid => Regex != null && GroupToField.Count > 0;

            internal CompiledGrok(Regex? rx, IReadOnlyDictionary<string, string> map) { Regex = rx; GroupToField = map; }

            /// <summary>Match <paramref name="input"/> and copy named captures into <paramref name="into"/>; true if matched with captures.</summary>
            public bool TryExtract(string? input, IDictionary<string, string> into)
            {
                if (Regex == null || string.IsNullOrEmpty(input) || GroupToField.Count == 0) return false;
                var m = Regex.Match(input);
                if (!m.Success) return false;
                bool any = false;
                foreach (var kv in GroupToField)
                {
                    var g = m.Groups[kv.Key];
                    if (g.Success) { into[kv.Value] = g.Value; any = true; }
                }
                return any;
            }
        }

        /// <summary>Compile a grok expression into a regex. A bad/unknown pattern degrades gracefully (never throws).</summary>
        public static CompiledGrok Compile(string? grok)
        {
            var map = new Dictionary<string, string>();
            if (string.IsNullOrWhiteSpace(grok)) return new CompiledGrok(null, map);
            int counter = 0;

            string Build(string text, int depth)
            {
                if (depth > 25) return text;   // recursion guard for self/mutually-referential patterns
                return TokenRx.Replace(text, m =>
                {
                    var name = m.Groups[1].Value;
                    string? field = m.Groups[2].Success ? m.Groups[2].Value : null;
                    if (!Patterns.TryGetValue(name, out var sub))
                        return Regex.Escape(m.Value);   // unknown %{X} → matched literally, never breaks the regex
                    var inner = Build(sub, depth + 1);
                    if (field == null) return $"(?:{inner})";
                    var g = "g" + counter++;
                    map[g] = field;
                    return $"(?<{g}>{inner})";
                });
            }

            try
            {
                var pattern = Build(grok, 0);
                var rx = new Regex(pattern, RegexOptions.CultureInvariant);
                return new CompiledGrok(rx, map);
            }
            catch
            {
                return new CompiledGrok(null, map);
            }
        }
    }
}
