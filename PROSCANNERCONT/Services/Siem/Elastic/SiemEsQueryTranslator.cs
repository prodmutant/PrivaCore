using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Services.Siem.Elastic
{
    /// <summary>
    /// Translates the SIEM's KQL-ish query language (see <see cref="SiemQuery"/>) into an
    /// Elasticsearch Query DSL tree (nested dictionaries, ready to JSON-serialise). This is the
    /// load-bearing piece of an ES-backed store: it lets the existing Discover/detection query box
    /// drive a real cluster.
    ///
    /// NOTE: the grammar is intentionally a mirror of <see cref="SiemQuery"/>'s tokenizer/parser.
    /// In production these should share a single parsed AST (one parse → both a predicate and a DSL)
    /// so they can never drift; duplicating it here keeps this a low-risk, self-contained sketch.
    ///
    /// Semantic divergence to resolve before shipping: the in-memory store does case-insensitive
    /// *substring* matching for <c>field:value</c>; here a plain <c>field:value</c> becomes an ES
    /// <c>match</c> (analysed token match). Exact parity would emit a <c>wildcard</c> <c>*value*</c>
    /// against a keyword sub-field — correct but heavier; left as a documented choice.
    /// </summary>
    public static class SiemEsQueryTranslator
    {
        private static readonly Dictionary<string, object?> MatchAll = new() { ["match_all"] = new Dictionary<string, object?>() };

        /// <summary>The query DSL node for a KQL string (match_all when empty/blank).</summary>
        public static Dictionary<string, object?> ToQueryDsl(string? query)
        {
            if (string.IsNullOrWhiteSpace(query)) return Clone(MatchAll);
            try
            {
                var toks = Tokenize(query);
                if (toks.Count == 0) return Clone(MatchAll);
                var node = new Parser(toks).ParseExpr();
                return node ?? Clone(MatchAll);
            }
            catch
            {
                // forgiving fallback: free-text across all fields (mirrors SiemQuery's last-ditch path)
                return FreeText(query.Trim());
            }
        }

        /// <summary>A full <c>_search</c> body: the query AND-ed with a @timestamp range, size + recency sort.</summary>
        public static Dictionary<string, object?> ToSearchBody(string? query, SiemRange? range, int size)
        {
            var q = ToQueryDsl(query);
            if (range != null)
            {
                q = new Dictionary<string, object?>
                {
                    ["bool"] = new Dictionary<string, object?>
                    {
                        ["must"] = new List<object?> { q },
                        ["filter"] = new List<object?> { TimestampRange(range) },
                    },
                };
            }
            return new Dictionary<string, object?>
            {
                ["size"] = size,
                ["query"] = q,
                ["sort"] = new List<object?> { new Dictionary<string, object?> { [SiemEsDocument.TimestampField] = new Dictionary<string, object?> { ["order"] = "desc" } } },
            };
        }

        public static Dictionary<string, object?> TimestampRange(SiemRange range) => new()
        {
            ["range"] = new Dictionary<string, object?>
            {
                [SiemEsDocument.TimestampField] = new Dictionary<string, object?>
                {
                    ["gte"] = range.From.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture),
                    ["lte"] = range.To.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture),
                },
            },
        };

        // ════════════════════════════════ tokenizer (mirror of SiemQuery) ════════════════════════════════
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
                toks.Add(w.ToUpperInvariant() switch
                {
                    "AND" => new(Kind.And, w),
                    "OR" => new(Kind.Or, w),
                    "NOT" => new(Kind.Not, w),
                    _ => new(Kind.Term, w),
                });
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

        // ════════════════════════════════ parser → DSL nodes ════════════════════════════════
        private sealed class Parser
        {
            private readonly List<Tok> _t; private int _i;
            public Parser(List<Tok> t) { _t = t; }
            private bool End => _i >= _t.Count;
            private Tok Peek => _t[_i];
            private Tok Next() => _t[_i++];

            public Dictionary<string, object?> ParseExpr() => ParseOr();

            private Dictionary<string, object?> ParseOr()
            {
                var clauses = new List<object?> { ParseAnd() };
                while (!End && Peek.Kind == Kind.Or) { Next(); clauses.Add(ParseAnd()); }
                if (clauses.Count == 1) return (Dictionary<string, object?>)clauses[0]!;
                return Bool("should", clauses, minimumShouldMatch: 1);
            }

            private Dictionary<string, object?> ParseAnd()
            {
                var clauses = new List<object?> { ParseNot() };
                while (!End)
                {
                    if (Peek.Kind == Kind.And) { Next(); }
                    else if (Peek.Kind is Kind.Or or Kind.RParen) break;
                    clauses.Add(ParseNot());
                }
                if (clauses.Count == 1) return (Dictionary<string, object?>)clauses[0]!;
                return Bool("must", clauses);
            }

            private Dictionary<string, object?> ParseNot()
            {
                if (!End && Peek.Kind == Kind.Not)
                {
                    Next();
                    return Bool("must_not", new List<object?> { ParseNot() });
                }
                return ParsePrimary();
            }

            private Dictionary<string, object?> ParsePrimary()
            {
                if (End) return Clone(MatchAll);
                if (Peek.Kind == Kind.LParen)
                {
                    Next();
                    var inner = ParseExpr();
                    if (!End && Peek.Kind == Kind.RParen) Next();
                    return inner;
                }
                if (Peek.Kind == Kind.RParen) { Next(); return Clone(MatchAll); }
                return BuildClause(Next().Text);
            }
        }

        private static Dictionary<string, object?> Bool(string occur, List<object?> clauses, int? minimumShouldMatch = null)
        {
            var b = new Dictionary<string, object?> { [occur] = clauses };
            if (minimumShouldMatch is int m) b["minimum_should_match"] = m;
            return new Dictionary<string, object?> { ["bool"] = b };
        }

        // ════════════════════════════════ clause → DSL ════════════════════════════════
        private static Dictionary<string, object?> BuildClause(string term)
        {
            bool negate = term.Length > 1 && (term[0] == '-' || term[0] == '!');
            if (negate) term = term[1..];
            if (term.Length == 0) return Clone(MatchAll);

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
                if (c == ':') { field = term[..i]; op = ":"; value = term[(i + 1)..]; break; }
            }

            Dictionary<string, object?> node;
            if (op.Length == 0 || field.Length == 0)
            {
                node = FreeText(Unquote(term));
            }
            else
            {
                var f = Alias(field.Trim().ToLowerInvariant());
                if (op == ":")
                {
                    var vt = value.TrimStart();
                    if (vt.StartsWith(">=") || vt.StartsWith("<=")) { op = vt[..2]; value = vt[2..]; }
                    else if (vt.StartsWith(">") || vt.StartsWith("<")) { op = vt[..1]; value = vt[1..]; }
                }
                var v = Unquote(value);
                node = op == ":" ? Equality(f, v) : Range(f, op, v);
            }
            return negate ? Bool("must_not", new List<object?> { node }) : node;
        }

        private static Dictionary<string, object?> Equality(string field, string value)
        {
            if (field is "severity" or "log.level")
                return Term("log.level", NormaliseSeverity(value));

            // CIDR / subnet — ES accepts CIDR notation directly in a term query on an `ip` field.
            if (value.Contains('/') && IsCidr(value))
                return Term(field, value);

            if (value.Contains('*') || value.Contains('?'))
                return new Dictionary<string, object?>
                {
                    ["wildcard"] = new Dictionary<string, object?>
                    {
                        [field] = new Dictionary<string, object?> { ["value"] = value.ToLowerInvariant(), ["case_insensitive"] = true },
                    },
                };

            return new Dictionary<string, object?>
            {
                ["match"] = new Dictionary<string, object?> { [field] = new Dictionary<string, object?> { ["query"] = value } },
            };
        }

        private static Dictionary<string, object?> Range(string field, string op, string value)
        {
            // severity comparisons map onto the numeric severity level
            if (field is "severity" or "log.level" && Enum.TryParse<SiemSeverity>(value, true, out var sev))
                return RangeOn(SiemEsDocument.SeverityLevelField, op, (int)sev);

            if (double.TryParse(value, NumberStyles.Any, CultureInfo.InvariantCulture, out var num))
                return RangeOn(field, op, num);

            // a numeric range against a non-numeric bound matches nothing
            return Bool("must_not", new List<object?> { Clone(MatchAll) });
        }

        private static Dictionary<string, object?> RangeOn(string field, string op, object num)
        {
            string key = op switch { ">=" => "gte", ">" => "gt", "<=" => "lte", "<" => "lt", _ => "gte" };
            return new Dictionary<string, object?>
            {
                ["range"] = new Dictionary<string, object?> { [field] = new Dictionary<string, object?> { [key] = num } },
            };
        }

        private static Dictionary<string, object?> Term(string field, string value)
            => new() { ["term"] = new Dictionary<string, object?> { [field] = value } };

        private static Dictionary<string, object?> FreeText(string text)
            => new()
            {
                ["multi_match"] = new Dictionary<string, object?>
                {
                    ["query"] = Unquote(text),
                    ["lenient"] = true,
                    ["type"] = "best_fields",
                },
            };

        // ── helpers (mirror of SiemQuery) ──
        private static string Alias(string f) => f switch
        {
            "sev" => "severity",
            "src" => "source",
            "cat" => "category",
            "type" or "eventtype" => "event.action",
            "msg" => "message",
            "host" => "host.name",
            "source" => "observer.name",
            "category" => "event.category",
            _ => f,
        };

        /// <summary>True if the value is a valid "addr/prefix" CIDR (IPv4 or IPv6) — mirrors SiemQuery.</summary>
        private static bool IsCidr(string s)
        {
            int slash = s.IndexOf('/');
            if (slash <= 0 || slash >= s.Length - 1) return false;
            if (!System.Net.IPAddress.TryParse(s[..slash].Trim(), out var addr)) return false;
            if (!int.TryParse(s[(slash + 1)..].Trim(), out var prefix)) return false;
            int max = addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? 128 : 32;
            return prefix >= 0 && prefix <= max;
        }

        /// <summary>Normalise a severity token to the stored enum name (e.g. "high" → "High").</summary>
        private static string NormaliseSeverity(string value)
            => Enum.TryParse<SiemSeverity>(value, true, out var s) ? s.ToString() : value;

        private static string Unquote(string s)
        {
            s = s.Trim();
            if (s.Length >= 2 && s[0] == '"' && s[^1] == '"') return s[1..^1];
            return s;
        }

        private static Dictionary<string, object?> Clone(Dictionary<string, object?> d) => new(d);
    }
}
