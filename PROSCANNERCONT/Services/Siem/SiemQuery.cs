using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Services.Siem
{
    /// <summary>
    /// A KQL-ish search language for the SIEM (Discover + detection rules). Supports:
    ///   field filters         host:DC01   source.ip:10.0.0.1   category:auth
    ///   CIDR / subnet match    source.ip:10.0.0.0/24   destination.ip:"2001:db8::/32"
    ///   range on any field     network.bytes>=1000   http.response.status_code:&gt;=500   severity:&gt;=high
    ///   wildcards              user.name:adm*   url.path:*login*   host:DC0?
    ///   negation               -host:DC01   NOT host:DC01   !category:noise
    ///   booleans + grouping    (host:DC01 OR host:WEB02) AND severity:&gt;=high
    ///   free text              "failed logon"   bruteforce
    /// Adjacent terms are AND-ed implicitly. Parsing is forgiving — a malformed query never throws.
    /// </summary>
    public sealed class SiemQuery
    {
        private readonly Func<SiemEvent, bool> _pred;
        public bool IsEmpty { get; }

        /// <summary>The original query text this was parsed from (used by alternate stores to re-translate, e.g. to ES DSL).</summary>
        public string Raw { get; }

        private SiemQuery(Func<SiemEvent, bool> pred, bool empty, string raw) { _pred = pred; IsEmpty = empty; Raw = raw; }

        public bool Matches(SiemEvent e) => _pred(e);

        public static SiemQuery Parse(string? text)
        {
            if (string.IsNullOrWhiteSpace(text)) return new SiemQuery(_ => true, true, "");
            try
            {
                var tokens = Tokenize(text);
                if (tokens.Count == 0) return new SiemQuery(_ => true, true, text);
                var p = new Parser(tokens);
                var pred = p.ParseExpr();
                return new SiemQuery(pred, false, text);
            }
            catch
            {
                // last-ditch: treat the whole thing as a free-text contains so the box never "breaks"
                var term = text.Trim().ToLowerInvariant();
                return new SiemQuery(e => FreeText(e, term), false, text);
            }
        }

        // ════════════════════════════════ tokenizer ════════════════════════════════
        private enum Kind { Term, And, Or, Not, LParen, RParen }
        private readonly record struct Tok(Kind Kind, string Text);

        private static List<Tok> Tokenize(string text)
        {
            var toks = new List<Tok>();
            var sb = new StringBuilder();
            bool inQuote = false;

            void Flush()
            {
                if (sb.Length == 0) return;
                var w = sb.ToString(); sb.Clear();
                switch (w.ToUpperInvariant())
                {
                    case "AND": toks.Add(new(Kind.And, w)); break;
                    case "OR": toks.Add(new(Kind.Or, w)); break;
                    case "NOT": toks.Add(new(Kind.Not, w)); break;
                    default: toks.Add(new(Kind.Term, w)); break;
                }
            }

            foreach (var c in text)
            {
                if (c == '"') { inQuote = !inQuote; sb.Append(c); continue; }
                if (inQuote) { sb.Append(c); continue; }
                if (c == '(') { Flush(); toks.Add(new(Kind.LParen, "(")); continue; }
                if (c == ')') { Flush(); toks.Add(new(Kind.RParen, ")")); continue; }
                if (char.IsWhiteSpace(c)) { Flush(); continue; }
                sb.Append(c);
            }
            Flush();
            return toks;
        }

        // ════════════════════════════════ parser ════════════════════════════════
        private sealed class Parser
        {
            private readonly List<Tok> _t;
            private int _i;
            public Parser(List<Tok> t) { _t = t; }

            private bool End => _i >= _t.Count;
            private Tok Peek => _t[_i];
            private Tok Next() => _t[_i++];

            // expr := orExpr
            public Func<SiemEvent, bool> ParseExpr() => ParseOr();

            // orExpr := andExpr (OR andExpr)*
            private Func<SiemEvent, bool> ParseOr()
            {
                var left = ParseAnd();
                while (!End && Peek.Kind == Kind.Or)
                {
                    Next();
                    var right = ParseAnd();
                    var l = left; left = e => l(e) || right(e);
                }
                return left;
            }

            // andExpr := notExpr ((AND)? notExpr)*   — adjacency means AND
            private Func<SiemEvent, bool> ParseAnd()
            {
                var left = ParseNot();
                while (!End)
                {
                    if (Peek.Kind == Kind.And) { Next(); }
                    else if (Peek.Kind is Kind.Or or Kind.RParen) break;
                    // otherwise it's an adjacent term/group/NOT → implicit AND
                    var right = ParseNot();
                    var l = left; left = e => l(e) && right(e);
                }
                return left;
            }

            // notExpr := (NOT) notExpr | primary
            private Func<SiemEvent, bool> ParseNot()
            {
                if (!End && Peek.Kind == Kind.Not)
                {
                    Next();
                    var inner = ParseNot();
                    return e => !inner(e);
                }
                return ParsePrimary();
            }

            // primary := '(' expr ')' | term
            private Func<SiemEvent, bool> ParsePrimary()
            {
                if (End) return _ => true;
                if (Peek.Kind == Kind.LParen)
                {
                    Next();
                    var inner = ParseExpr();
                    if (!End && Peek.Kind == Kind.RParen) Next();   // tolerate a missing ')'
                    return inner;
                }
                if (Peek.Kind == Kind.RParen) { Next(); return _ => true; }
                return BuildClause(Next().Text);
            }
        }

        // ════════════════════════════════ clause → predicate ════════════════════════════════
        private static Func<SiemEvent, bool> BuildClause(string term)
        {
            bool negate = term.Length > 1 && (term[0] == '-' || term[0] == '!');
            if (negate) term = term[1..];
            if (term.Length == 0) return _ => true;

            // find an operator: comparison (>=,<=,>,<) or ':'
            string field = "", op = "", value = "";
            for (int i = 0; i < term.Length; i++)
            {
                char c = term[i];
                if (c == '>' || c == '<')
                {
                    field = term[..i];
                    if (i + 1 < term.Length && term[i + 1] == '=') { op = c + "="; value = term[(i + 2)..]; }
                    else { op = c.ToString(); value = term[(i + 1)..]; }
                    break;
                }
                if (c == ':')
                {
                    field = term[..i]; op = ":"; value = term[(i + 1)..];
                    break;
                }
            }

            Func<SiemEvent, bool> pred;
            if (op.Length == 0 || field.Length == 0)
            {
                var ft = Unquote(term).ToLowerInvariant();
                pred = e => FreeText(e, ft);
            }
            else
            {
                var f = Alias(field.Trim().ToLowerInvariant());
                // support the KQL form  field:>=value  (colon, then a comparison operator)
                if (op == ":")
                {
                    var vt = value.TrimStart();
                    if (vt.StartsWith(">=") || vt.StartsWith("<=")) { op = vt[..2]; value = vt[2..]; }
                    else if (vt.StartsWith(">") || vt.StartsWith("<")) { op = vt[..1]; value = vt[1..]; }
                }
                var v = Unquote(value);
                pred = op == ":" ? EqualityClause(f, v) : RangeClause(f, op, v);
            }
            return negate ? (e => !pred(e)) : pred;
        }

        private static Func<SiemEvent, bool> EqualityClause(string field, string value)
        {
            bool isSeverity = field is "severity" or "log.level";
            if (isSeverity && Enum.TryParse<SiemSeverity>(value, true, out var sev))
                return e => e.Severity == sev;

            // CIDR / subnet match  (source.ip:10.0.0.0/24) — only when the value is a valid CIDR,
            // so ordinary "/"-bearing values (url.path) fall through to a normal contains.
            if (value.Contains('/') && TryParseCidr(value, out var network, out var prefix))
                return e => { var fv = FieldVal(e, field); return fv != null && IpInCidr(fv, network, prefix); };

            if (value.Contains('*') || value.Contains('?'))
            {
                var rx = WildcardRegex(value);
                return e => { var fv = FieldVal(e, field); return fv != null && rx.IsMatch(fv); };
            }
            var needle = value.ToLowerInvariant();
            return e => { var fv = FieldVal(e, field); return fv != null && fv.ToLowerInvariant().Contains(needle); };
        }

        private static Func<SiemEvent, bool> RangeClause(string field, string op, string value)
        {
            bool isSeverity = field is "severity" or "log.level";
            if (isSeverity && Enum.TryParse<SiemSeverity>(value, true, out var sev))
            {
                int target = (int)sev;
                return op switch
                {
                    ">=" => e => (int)e.Severity >= target,
                    ">" => e => (int)e.Severity > target,
                    "<=" => e => (int)e.Severity <= target,
                    "<" => e => (int)e.Severity < target,
                    _ => _ => true,
                };
            }
            if (!double.TryParse(value, NumberStyles.Any, CultureInfo.InvariantCulture, out var num))
                return _ => false;   // numeric range against a non-numeric bound matches nothing
            return e =>
            {
                var fv = FieldVal(e, field);
                if (fv == null || !double.TryParse(fv, NumberStyles.Any, CultureInfo.InvariantCulture, out var x)) return false;
                return op switch { ">=" => x >= num, ">" => x > num, "<=" => x <= num, "<" => x < num, _ => false };
            };
        }

        // ════════════════════════════════ helpers ════════════════════════════════
        private static string Alias(string f) => f switch
        {
            "sev" => "severity",
            "src" => "source",
            "cat" => "category",
            "type" or "eventtype" => "event.action",
            "msg" => "message",
            "host" => "host.name",
            _ => f,
        };

        /// <summary>Resolve a (possibly aliased) field name to the event's value, via the ECS-aware getter.</summary>
        private static string? FieldVal(SiemEvent e, string field) => e.Get(field);

        private static bool FreeText(SiemEvent e, string term)
        {
            if (term.Length == 0) return true;
            bool Has(string? s) => !string.IsNullOrEmpty(s) && s.ToLowerInvariant().Contains(term);
            return Has(e.Message) || Has(e.Raw) || Has(e.Source) || Has(e.EventType)
                || Has(e.Category) || Has(e.Host) || e.Fields.Values.Any(Has);
        }

        private static string Unquote(string s)
        {
            s = s.Trim();
            if (s.Length >= 2 && s[0] == '"' && s[^1] == '"') return s[1..^1];
            return s;
        }

        // ════════════════════════════════ CIDR / subnet matching ════════════════════════════════
        /// <summary>Parse "addr/prefix" (IPv4 or IPv6). Returns false for anything that isn't a real CIDR.</summary>
        private static bool TryParseCidr(string s, out System.Net.IPAddress network, out int prefix)
        {
            network = System.Net.IPAddress.None; prefix = 0;
            int slash = s.IndexOf('/');
            if (slash <= 0 || slash >= s.Length - 1) return false;
            if (!System.Net.IPAddress.TryParse(s[..slash].Trim(), out var addr)) return false;
            if (!int.TryParse(s[(slash + 1)..].Trim(), out prefix)) return false;
            int max = addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? 128 : 32;
            if (prefix < 0 || prefix > max) return false;
            network = addr;
            return true;
        }

        /// <summary>True if a candidate IP string falls inside the given network/prefix (same address family).</summary>
        private static bool IpInCidr(string candidate, System.Net.IPAddress network, int prefix)
        {
            var c = candidate.Trim();
            if (!System.Net.IPAddress.TryParse(c, out var ip)) return false;
            if (ip.AddressFamily != network.AddressFamily) return false;
            var ipb = ip.GetAddressBytes();
            var netb = network.GetAddressBytes();
            if (ipb.Length != netb.Length) return false;
            int fullBytes = prefix / 8, remBits = prefix % 8;
            for (int i = 0; i < fullBytes; i++) if (ipb[i] != netb[i]) return false;
            if (remBits > 0)
            {
                int mask = 0xFF << (8 - remBits) & 0xFF;
                if ((ipb[fullBytes] & mask) != (netb[fullBytes] & mask)) return false;
            }
            return true;
        }

        private static Regex WildcardRegex(string pattern)
        {
            var sb = new StringBuilder("^");
            foreach (var c in pattern)
            {
                if (c == '*') sb.Append(".*");
                else if (c == '?') sb.Append('.');
                else sb.Append(Regex.Escape(c.ToString()));
            }
            sb.Append('$');
            return new Regex(sb.ToString(), RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        }
    }
}
