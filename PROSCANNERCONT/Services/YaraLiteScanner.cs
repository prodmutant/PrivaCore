using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using PROSCANNERCONT.Utils;

namespace PROSCANNERCONT.Services
{
    /// <summary>
    /// Subset YARA rule engine. Supports the common-case grammar:
    ///   rule RULE_NAME { meta: ... strings: $a = "abc" $b = { 4D 5A } $c = /re/ condition: any of them }
    /// Including: ASCII strings ("foo"), hex strings ({ 4D 5A ?? }) with single-byte wildcards,
    /// regex strings (/pattern/), and conditions of the form "all of them", "any of them",
    /// "N of them", and "$a and $b" / "$a or $b".
    ///
    /// We intentionally don't take a native YARA dependency (libyara P/Invoke is finicky
    /// on Windows + the license model is non-trivial to bundle).  This covers ~90 %
    /// of community rule shapes seen on rules.yara.io and Florian Roth's signature-base.
    /// </summary>
    public sealed class YaraLiteScanner
    {
        public sealed class Rule
        {
            public string Name { get; set; } = "";
            public Dictionary<string, string> Meta { get; init; } = new();
            public Dictionary<string, IStringPattern> Strings { get; init; } = new();
            public string Condition { get; set; } = "any of them";
            public string Source { get; set; } = "";
        }

        public interface IStringPattern { bool Matches(ReadOnlySpan<byte> data); }

        private sealed class AsciiPattern : IStringPattern
        {
            private readonly byte[] _b;
            public AsciiPattern(string s) { _b = Encoding.UTF8.GetBytes(s); }
            public bool Matches(ReadOnlySpan<byte> data) => IndexOfBytes(data, _b) >= 0;
        }

        private sealed class HexPattern : IStringPattern
        {
            // bytes & mask: 0xFF means literal match; 0x00 means wildcard.
            private readonly byte[] _bytes;
            private readonly byte[] _mask;
            public HexPattern(byte[] bytes, byte[] mask) { _bytes = bytes; _mask = mask; }
            public bool Matches(ReadOnlySpan<byte> data)
            {
                if (data.Length < _bytes.Length) return false;
                for (int i = 0; i <= data.Length - _bytes.Length; i++)
                {
                    bool ok = true;
                    for (int j = 0; j < _bytes.Length; j++)
                    {
                        if (_mask[j] == 0) continue;
                        if (data[i + j] != _bytes[j]) { ok = false; break; }
                    }
                    if (ok) return true;
                }
                return false;
            }
        }

        private sealed class RegexPattern : IStringPattern
        {
            private readonly Regex _rx;
            public RegexPattern(string pattern) { _rx = new Regex(pattern, RegexOptions.Compiled); }
            public bool Matches(ReadOnlySpan<byte> data) => _rx.IsMatch(Encoding.Latin1.GetString(data));
        }

        public List<Rule> Rules { get; } = new();

        public void LoadFromText(string source, string yaraText)
        {
            foreach (var r in Parse(yaraText, source)) Rules.Add(r);
        }

        public void LoadDirectory(string dir, string pattern = "*.yar")
        {
            if (!Directory.Exists(dir)) return;
            foreach (var f in Directory.EnumerateFiles(dir, pattern, SearchOption.AllDirectories))
            {
                try { LoadFromText(f, File.ReadAllText(f)); }
                catch (Exception ex) { AppLogger.Log.Warning(ex, "[YARA] failed to load {File}", f); }
            }
            foreach (var f in Directory.EnumerateFiles(dir, "*.yara", SearchOption.AllDirectories))
            {
                try { LoadFromText(f, File.ReadAllText(f)); }
                catch (Exception ex) { AppLogger.Log.Warning(ex, "[YARA] failed to load {File}", f); }
            }
        }

        public List<Rule> Scan(ReadOnlySpan<byte> data)
        {
            var hits = new List<Rule>();
            foreach (var rule in Rules)
            {
                if (Evaluate(rule, data)) hits.Add(rule);
            }
            return hits;
        }

        public List<Rule> ScanFile(string path)
        {
            try { return Scan(File.ReadAllBytes(path).AsSpan()); }
            catch { return new(); }
        }

        // ── Condition evaluation ───────────────────────────────────────────
        private static bool Evaluate(Rule rule, ReadOnlySpan<byte> data)
        {
            // Pre-compute which named strings match.
            var matched = new Dictionary<string, bool>();
            foreach (var (k, p) in rule.Strings) matched[k] = p.Matches(data);

            var cond = rule.Condition.Trim().ToLowerInvariant();
            if (cond == "all of them") return matched.Values.All(v => v);
            if (cond == "any of them") return matched.Values.Any(v => v);

            var nOfThem = Regex.Match(cond, @"^(\d+)\s+of\s+them$");
            if (nOfThem.Success)
            {
                int n = int.Parse(nOfThem.Groups[1].Value);
                return matched.Values.Count(v => v) >= n;
            }

            // simple AND/OR over $vars
            var tokens = Regex.Split(cond, @"\s+(and|or)\s+");
            if (tokens.Length == 0) return matched.Values.Any(v => v);
            bool? acc = null;
            string lastOp = "or";
            foreach (var t in tokens)
            {
                if (t == "and" || t == "or") { lastOp = t; continue; }
                bool val = false;
                if (t.StartsWith('$'))
                {
                    matched.TryGetValue(t, out val);
                }
                else if (t == "true") val = true;
                else if (t == "false") val = false;
                if (acc == null) acc = val;
                else acc = lastOp == "and" ? (acc.Value && val) : (acc.Value || val);
            }
            return acc ?? matched.Values.Any(v => v);
        }

        // ── Parser ─────────────────────────────────────────────────────────
        private static readonly Regex _ruleRx = new(
            @"rule\s+([A-Za-z0-9_]+)\s*\{(?<body>(?:[^{}]|\{[^{}]*\})*)\}",
            RegexOptions.Singleline | RegexOptions.Compiled);

        private static IEnumerable<Rule> Parse(string text, string source)
        {
            foreach (Match m in _ruleRx.Matches(text))
            {
                string name = m.Groups[1].Value;
                string body = m.Groups["body"].Value;
                var rule = new Rule { Name = name, Source = source };

                // meta
                var metaM = Regex.Match(body, @"meta\s*:(.+?)(?=strings\s*:|condition\s*:|$)", RegexOptions.Singleline);
                if (metaM.Success)
                {
                    foreach (Match kv in Regex.Matches(metaM.Groups[1].Value, @"(\w+)\s*=\s*""([^""]*)"""))
                        rule.Meta[kv.Groups[1].Value] = kv.Groups[2].Value;
                }

                // strings
                var strM = Regex.Match(body, @"strings\s*:(.+?)(?=condition\s*:|$)", RegexOptions.Singleline);
                if (strM.Success)
                {
                    foreach (Match s in Regex.Matches(strM.Groups[1].Value,
                        @"(\$[A-Za-z0-9_]+)\s*=\s*(?:""([^""]*)""|\{([^}]*)\}|/([^/]*)/)"))
                    {
                        string key = s.Groups[1].Value;
                        if (s.Groups[2].Success) rule.Strings[key] = new AsciiPattern(s.Groups[2].Value);
                        else if (s.Groups[3].Success) rule.Strings[key] = ParseHex(s.Groups[3].Value);
                        else if (s.Groups[4].Success) rule.Strings[key] = new RegexPattern(s.Groups[4].Value);
                    }
                }

                // condition
                var condM = Regex.Match(body, @"condition\s*:(.+)", RegexOptions.Singleline);
                if (condM.Success)
                    rule.Condition = condM.Groups[1].Value.Trim();

                yield return rule;
            }
        }

        private static HexPattern ParseHex(string text)
        {
            var clean = Regex.Replace(text, @"\s+|//.*", "");
            var bytes = new List<byte>();
            var mask  = new List<byte>();
            for (int i = 0; i < clean.Length - 1; i += 2)
            {
                string pair = clean.Substring(i, 2);
                if (pair == "??") { bytes.Add(0); mask.Add(0); }
                else
                {
                    if (byte.TryParse(pair, System.Globalization.NumberStyles.HexNumber, null, out var b))
                    { bytes.Add(b); mask.Add(0xFF); }
                }
            }
            return new HexPattern(bytes.ToArray(), mask.ToArray());
        }

        private static int IndexOfBytes(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle)
        {
            if (needle.Length == 0 || haystack.Length < needle.Length) return -1;
            for (int i = 0; i <= haystack.Length - needle.Length; i++)
            {
                bool ok = true;
                for (int j = 0; j < needle.Length; j++)
                    if (haystack[i + j] != needle[j]) { ok = false; break; }
                if (ok) return i;
            }
            return -1;
        }
    }
}
