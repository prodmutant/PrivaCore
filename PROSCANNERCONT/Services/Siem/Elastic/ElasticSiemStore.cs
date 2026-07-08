using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Services.Siem.Elastic
{
    /// <summary>
    /// SKELETON — an Elasticsearch/OpenSearch-backed <see cref="ISiemStore"/>. Demonstrates how the
    /// in-memory store can be swapped for a real cluster behind the <see cref="SiemStoreProvider"/>
    /// seam, with the existing query box driving ES via <see cref="SiemEsQueryTranslator"/> and events
    /// stored through <see cref="SiemEsDocument"/>. Dependency-free (HttpClient + JSON), so it does not
    /// break the single-exe model.
    ///
    /// This is a sketch, NOT wired up by default. To try it:
    ///   <c>SiemStoreProvider.Current = new ElasticSiemStore(new SiemEsConfig { BaseUrl = "...", Index = "..." });</c>
    ///
    /// Known gaps before this is production-ready (the multi-week lift in CLAUDE.md §7.1):
    ///  • <see cref="ISiemStore"/> is synchronous but ES is async — calls here block on the HTTP task
    ///    (<c>.GetAwaiter().GetResult()</c>). The real fix is an async store interface so the WPF UI
    ///    never blocks the dispatcher.
    ///  • Retention (<see cref="Capacity"/>/<see cref="MaxAge"/>) should map to ES ILM, not be enforced here.
    ///  • A few methods (<see cref="Surrounding"/>, <see cref="FieldNames"/>) are left as TODO.
    /// </summary>
    public sealed class ElasticSiemStore : ISiemStore, IDisposable
    {
        private readonly SiemEsConfig _cfg;
        private readonly HttpClient _http;
        private long _ingested, _dropped;

        public ElasticSiemStore(SiemEsConfig cfg)
        {
            _cfg = cfg ?? throw new ArgumentNullException(nameof(cfg));
            var handler = new HttpClientHandler();
            if (cfg.AllowInvalidCertificate)
                handler.ServerCertificateCustomValidationCallback = (_, _, _, _) => true;
            _http = new HttpClient(handler) { BaseAddress = new Uri(cfg.BaseUrl.TrimEnd('/') + "/"), Timeout = cfg.Timeout };
            if (!string.IsNullOrEmpty(cfg.ApiKey))
                _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("ApiKey", cfg.ApiKey);
            else if (!string.IsNullOrEmpty(cfg.Username))
                _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic",
                    Convert.ToBase64String(Encoding.UTF8.GetBytes($"{cfg.Username}:{cfg.Password}")));
        }

        // ── retention knobs (advisory only — real enforcement is ES ILM) ──
        public int Capacity { get; set; } = 200_000;
        public TimeSpan MaxAge { get; set; } = TimeSpan.Zero;

        public SiemPipeline Pipeline { get; set; } = new();
        public event EventHandler<SiemEvent>? EventAdded;

        public long TotalIngested => System.Threading.Interlocked.Read(ref _ingested);
        public long TotalDropped => System.Threading.Interlocked.Read(ref _dropped);
        public int Count => CountMatching(SiemQuery.Parse(null), null);

        // ════════════════════════════════ ingest / lifecycle ════════════════════════════════
        public void Add(SiemEvent e, bool applyPipeline = true)
        {
            if (applyPipeline)
            {
                var processed = Pipeline.Process(e);
                if (processed == null) { System.Threading.Interlocked.Increment(ref _dropped); return; }
                e = processed;
            }
            System.Threading.Interlocked.Increment(ref _ingested);
            Post($"{_cfg.Index}/_doc?refresh=false", SiemEsDocument.ToSource(e));
            EventAdded?.Invoke(this, e);
        }

        public void LoadSnapshot(IEnumerable<SiemEvent> events)
        {
            var sb = new StringBuilder();
            foreach (var e in events)
            {
                sb.Append("{\"index\":{}}\n");
                sb.Append(SiemEsDocument.ToJson(e)).Append('\n');
            }
            if (sb.Length == 0) return;
            SendRaw(HttpMethod.Post, $"{_cfg.Index}/_bulk?refresh=true", sb.ToString(), "application/x-ndjson");
        }

        public void Clear() => Post($"{_cfg.Index}/_delete_by_query?refresh=true",
            new Dictionary<string, object?> { ["query"] = new Dictionary<string, object?> { ["match_all"] = new Dictionary<string, object?>() } });

        public int DeleteMatching(SiemQuery q, SiemRange? range)
        {
            var body = new Dictionary<string, object?> { ["query"] = QueryWithRange(RawOf(q), range) };
            using var doc = Post($"{_cfg.Index}/_delete_by_query?refresh=true", body);
            return doc.RootElement.TryGetProperty("deleted", out var d) ? d.GetInt32() : 0;
        }

        /// <summary>Advisory only — ES retention is handled by ILM, not client-side purging.</summary>
        public int PurgeExpired() => 0;

        // ════════════════════════════════ search ════════════════════════════════
        public List<SiemEvent> Query(SiemQuery q, SiemRange? range, int limit)
            => SearchHits(SiemEsQueryTranslator.ToSearchBody(RawOf(q), range, Math.Min(limit, 10_000)));

        public List<SiemEvent> Snapshot() => Query(SiemQuery.Parse(null), null, Math.Min(Capacity, 10_000));

        public int CountMatching(SiemQuery q, SiemRange? range)
        {
            var body = new Dictionary<string, object?> { ["query"] = QueryWithRange(RawOf(q), range) };
            using var doc = Post($"{_cfg.Index}/_count", body);
            return doc.RootElement.TryGetProperty("count", out var c) ? c.GetInt32() : 0;
        }

        // ════════════════════════════════ aggregations ════════════════════════════════
        public Dictionary<SiemSeverity, int> CountBySeverity(SiemQuery q, SiemRange? range)
        {
            var dict = new Dictionary<SiemSeverity, int>();
            foreach (SiemSeverity s in Enum.GetValues(typeof(SiemSeverity))) dict[s] = 0;
            var agg = new Dictionary<string, object?> { ["terms"] = new Dictionary<string, object?> { ["field"] = "log.level", ["size"] = 10 } };
            foreach (var (key, count) in TermsAgg(q, range, agg))
                if (Enum.TryParse<SiemSeverity>(key, true, out var sev)) dict[sev] = count;
            return dict;
        }

        public List<(string key, int count)> TopByField(string field, SiemQuery q, SiemRange? range, int n)
        {
            var agg = new Dictionary<string, object?> { ["terms"] = new Dictionary<string, object?> { ["field"] = field, ["size"] = n } };
            return TermsAgg(q, range, agg);
        }

        /// <summary>A delegate selector can't be pushed to ES — group a sampled page client-side (documented divergence).</summary>
        public List<(string key, int count)> TopBy(Func<SiemEvent, string> selector, SiemQuery q, SiemRange? range, int n)
            => Query(q, range, 5_000).GroupBy(selector).Select(g => (g.Key ?? "", g.Count()))
               .OrderByDescending(t => t.Item2).Take(n).ToList();

        /// <summary>Heat map over a sampled page client-side (a date_histogram-with-terms sub-agg would be the native form).</summary>
        public (List<string> rows, int[][] matrix) HeatmapByField(string field, SiemQuery q, SiemRange range, int buckets, int topN)
        {
            buckets = Math.Max(1, buckets); topN = Math.Max(1, topN);
            var events = Query(q, range, 5_000);
            var rows = events.GroupBy(e => e.Get(field) ?? "")
                .Select(g => (key: g.Key, count: g.Count()))
                .OrderByDescending(t => t.count).Take(topN).Select(t => t.key).ToList();
            var index = new Dictionary<string, int>(StringComparer.Ordinal);
            for (int i = 0; i < rows.Count; i++) index[rows[i]] = i;
            var matrix = new int[rows.Count][];
            for (int i = 0; i < rows.Count; i++) matrix[i] = new int[buckets];
            double ms = Math.Max(1, range.Span.TotalMilliseconds) / buckets;
            foreach (var e in events)
            {
                if (!index.TryGetValue(e.Get(field) ?? "", out var r)) continue;
                int b = (int)((e.Timestamp - range.From).TotalMilliseconds / ms);
                if (b < 0) b = 0; if (b >= buckets) b = buckets - 1;
                matrix[r][b]++;
            }
            return (rows, matrix);
        }

        public double Metric(SiemAgg agg, string field, SiemQuery q, SiemRange? range)
        {
            if (agg == SiemAgg.Count) return CountMatching(q, range);
            string esAgg = agg switch
            {
                SiemAgg.UniqueCount => "cardinality",
                SiemAgg.Sum => "sum",
                SiemAgg.Average => "avg",
                SiemAgg.Min => "min",
                SiemAgg.Max => "max",
                _ => "value_count",
            };
            var body = SearchBodyWithAgg(q, range, new Dictionary<string, object?> { ["m"] = new Dictionary<string, object?> { [esAgg] = new Dictionary<string, object?> { ["field"] = field } } });
            using var doc = Post($"{_cfg.Index}/_search?size=0", body);
            return doc.RootElement.TryGetProperty("aggregations", out var a) && a.TryGetProperty("m", out var m) && m.TryGetProperty("value", out var v) && v.ValueKind == JsonValueKind.Number
                ? v.GetDouble() : 0;
        }

        public int[] Histogram(SiemQuery q, SiemRange range, int buckets)
        {
            var counts = new int[buckets];
            double ms = Math.Max(1, range.Span.TotalMilliseconds) / buckets;
            var agg = new Dictionary<string, object?>
            {
                ["h"] = new Dictionary<string, object?>
                {
                    ["date_histogram"] = new Dictionary<string, object?>
                    {
                        ["field"] = SiemEsDocument.TimestampField,
                        ["fixed_interval"] = $"{Math.Max(1, (long)ms)}ms",
                    },
                },
            };
            var body = SearchBodyWithAgg(q, range, agg);
            using var doc = Post($"{_cfg.Index}/_search?size=0", body);
            if (doc.RootElement.TryGetProperty("aggregations", out var a) && a.TryGetProperty("h", out var h) && h.TryGetProperty("buckets", out var bs))
                foreach (var b in bs.EnumerateArray())
                {
                    var when = DateTimeOffset.FromUnixTimeMilliseconds(b.GetProperty("key").GetInt64()).LocalDateTime;
                    int i = (int)((when - range.From).TotalMilliseconds / ms);
                    if (i >= 0 && i < buckets) counts[i] += b.GetProperty("doc_count").GetInt32();
                }
            return counts;
        }

        public (int total, List<(string value, int count)> top) TopValues(string field, SiemQuery q, SiemRange? range, int n, int sampleLimit = 6000)
        {
            var agg = new Dictionary<string, object?> { ["terms"] = new Dictionary<string, object?> { ["field"] = field, ["size"] = n } };
            var top = TermsAgg(q, range, agg);
            int total = top.Sum(t => t.count);
            return (total, top.Select(t => (t.key, t.count)).ToList());
        }

        public List<SiemSourceStat> SourceStats(SiemRange? range)
        {
            var stats = new List<SiemSourceStat>();
            var agg = new Dictionary<string, object?> { ["terms"] = new Dictionary<string, object?> { ["field"] = "host.name", ["size"] = 500 } };
            foreach (var (host, count) in TermsAgg(SiemQuery.Parse(null), range, agg))
                stats.Add(new SiemSourceStat { Host = host, Events = count, LastSeen = DateTime.Now });
            return stats;
        }

        // ── index metadata ──
        public long ApproxBytes()
        {
            using var doc = Get($"{_cfg.Index}/_stats/store");
            try { return doc.RootElement.GetProperty("_all").GetProperty("total").GetProperty("store").GetProperty("size_in_bytes").GetInt64(); }
            catch { return 0; }
        }

        public DateTime? Oldest() => BoundaryTime("min");
        public DateTime? Newest() => BoundaryTime("max");

        private DateTime? BoundaryTime(string which)
        {
            var body = new Dictionary<string, object?>
            {
                ["aggs"] = new Dictionary<string, object?> { ["t"] = new Dictionary<string, object?> { [which] = new Dictionary<string, object?> { ["field"] = SiemEsDocument.TimestampField } } },
            };
            using var doc = Post($"{_cfg.Index}/_search?size=0", body);
            if (doc.RootElement.TryGetProperty("aggregations", out var a) && a.TryGetProperty("t", out var t) && t.TryGetProperty("value", out var v) && v.ValueKind == JsonValueKind.Number)
                return DateTimeOffset.FromUnixTimeMilliseconds((long)v.GetDouble()).LocalDateTime;
            return null;
        }

        // ── TODO (skeleton): need bespoke searches; left unimplemented on purpose ──
        public List<SiemEvent> Surrounding(SiemEvent anchor, int before, int after, string? sameHost = null)
            => throw new NotSupportedException("ElasticSiemStore skeleton: Surrounding() — TODO: two range searches around the anchor's @timestamp.");

        public List<(string field, int docs)> FieldNames(SiemQuery q, SiemRange? range, int sampleLimit = 2500)
            => throw new NotSupportedException("ElasticSiemStore skeleton: FieldNames() — TODO: use the _field_caps API.");

        // ════════════════════════════════ HTTP + parsing helpers ════════════════════════════════
        /// <summary>The raw query text behind a compiled SiemQuery (preserved on <see cref="SiemQuery.Raw"/>), so it can be re-translated to ES DSL.</summary>
        private static string? RawOf(SiemQuery q) => q.IsEmpty ? null : q.Raw;

        private Dictionary<string, object?> QueryWithRange(string? rawQuery, SiemRange? range)
        {
            var q = SiemEsQueryTranslator.ToQueryDsl(rawQuery);
            if (range == null) return q;
            return new Dictionary<string, object?>
            {
                ["bool"] = new Dictionary<string, object?>
                {
                    ["must"] = new List<object?> { q },
                    ["filter"] = new List<object?> { SiemEsQueryTranslator.TimestampRange(range) },
                },
            };
        }

        private Dictionary<string, object?> SearchBodyWithAgg(SiemQuery q, SiemRange? range, Dictionary<string, object?> aggs)
            => new() { ["query"] = QueryWithRange(RawOf(q), range), ["aggs"] = aggs };

        private List<(string key, int count)> TermsAgg(SiemQuery q, SiemRange? range, Dictionary<string, object?> termsAgg)
        {
            var body = SearchBodyWithAgg(q, range, new Dictionary<string, object?> { ["g"] = termsAgg });
            using var doc = Post($"{_cfg.Index}/_search?size=0", body);
            var result = new List<(string, int)>();
            if (doc.RootElement.TryGetProperty("aggregations", out var a) && a.TryGetProperty("g", out var g) && g.TryGetProperty("buckets", out var bs))
                foreach (var b in bs.EnumerateArray())
                {
                    string key = b.GetProperty("key").ValueKind == JsonValueKind.String ? b.GetProperty("key").GetString() ?? "" : b.GetProperty("key").ToString();
                    result.Add((key, b.GetProperty("doc_count").GetInt32()));
                }
            return result;
        }

        private List<SiemEvent> SearchHits(Dictionary<string, object?> body)
        {
            using var doc = Post($"{_cfg.Index}/_search", body);
            var list = new List<SiemEvent>();
            if (doc.RootElement.TryGetProperty("hits", out var hits) && hits.TryGetProperty("hits", out var arr))
                foreach (var h in arr.EnumerateArray())
                    if (h.TryGetProperty("_source", out var src)) list.Add(SiemEsDocument.FromSource(src));
            return list;
        }

        private JsonDocument Post(string path, Dictionary<string, object?> body)
            => SendRaw(HttpMethod.Post, path, JsonSerializer.Serialize(body), "application/json");

        private JsonDocument Get(string path) => SendRaw(HttpMethod.Get, path, null, "application/json");

        private JsonDocument SendRaw(HttpMethod method, string path, string? body, string contentType)
        {
            var req = new HttpRequestMessage(method, path);
            if (body != null) req.Content = new StringContent(body, Encoding.UTF8, contentType);
            var resp = _http.SendAsync(req).GetAwaiter().GetResult();   // sync-over-async: see class note
            var text = resp.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            return JsonDocument.Parse(string.IsNullOrWhiteSpace(text) ? "{}" : text);
        }

        public void Dispose() => _http.Dispose();
    }
}
