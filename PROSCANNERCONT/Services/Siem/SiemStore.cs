using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Services.Siem
{
    /// <summary>
    /// The SIEM event store (the "Elasticsearch" of this stack): a thread-safe in-memory
    /// ring buffer of normalised events with query + aggregation support. Singleton so the
    /// dashboard, ingestion sources, and the module bridge all share one index.
    /// </summary>
    public sealed class SiemStore : ISiemStore
    {
        public static SiemStore Instance { get; } = new();

        private readonly object _lock = new();
        private readonly LinkedList<SiemEvent> _events = new();   // newest first
        private long _seq;
        private long _totalIngested;
        private long _totalDropped;

        public int Capacity { get; set; } = 200_000;
        /// <summary>Age-based retention: events older than this are purged. Zero = keep regardless of age.</summary>
        public TimeSpan MaxAge { get; set; } = TimeSpan.Zero;
        public int Count { get { lock (_lock) return _events.Count; } }
        public long TotalIngested => Interlocked.Read(ref _totalIngested);
        public long TotalDropped => Interlocked.Read(ref _totalDropped);

        /// <summary>The user-configurable processing pipeline applied to every ingested event.</summary>
        public SiemPipeline Pipeline { get; set; } = new();

        public event EventHandler<SiemEvent>? EventAdded;

        /// <summary>
        /// Add an event to the index. When <paramref name="applyPipeline"/> is true (local
        /// ingestion / agent intake) the event runs through the processing pipeline first and
        /// may be dropped or transformed. Events relayed from a remote collector pass false
        /// (they were already processed upstream).
        /// </summary>
        public void Add(SiemEvent e, bool applyPipeline = true)
        {
            if (applyPipeline)
            {
                var processed = Pipeline.Process(e);
                if (processed == null) { Interlocked.Increment(ref _totalDropped); return; }
                e = processed;
            }
            e.Id = Interlocked.Increment(ref _seq);
            Interlocked.Increment(ref _totalIngested);
            lock (_lock)
            {
                _events.AddFirst(e);
                if (_events.Count > Capacity) _events.RemoveLast();
            }
            EventAdded?.Invoke(this, e);
        }

        public void Clear() { lock (_lock) _events.Clear(); }

        public List<SiemEvent> Snapshot() { lock (_lock) return _events.ToList(); }

        // ── retention / index management ──
        /// <summary>Drop events older than <see cref="MaxAge"/> (and trim to Capacity). Returns how many were removed.</summary>
        public int PurgeExpired()
        {
            int removed = 0;
            lock (_lock)
            {
                if (MaxAge > TimeSpan.Zero)
                {
                    var cutoff = DateTime.Now - MaxAge;
                    while (_events.Last != null && _events.Last.Value.Timestamp < cutoff) { _events.RemoveLast(); removed++; }
                }
                while (_events.Count > Capacity) { _events.RemoveLast(); removed++; }
            }
            return removed;
        }

        /// <summary>Delete events matching a query within an optional range (delete-by-query). Returns the count removed.</summary>
        public int DeleteMatching(SiemQuery q, SiemRange? range)
        {
            int removed = 0;
            lock (_lock)
            {
                var node = _events.First;
                while (node != null)
                {
                    var next = node.Next;
                    var e = node.Value;
                    if ((range?.Contains(e.Timestamp) ?? true) && q.Matches(e)) { _events.Remove(node); removed++; }
                    node = next;
                }
            }
            return removed;
        }

        /// <summary>Bulk-load events from a persisted snapshot (preserves timestamps; bypasses the pipeline).</summary>
        public void LoadSnapshot(IEnumerable<SiemEvent> events)
        {
            lock (_lock)
            {
                foreach (var e in events.OrderByDescending(x => x.Timestamp))
                {
                    e.Id = Interlocked.Increment(ref _seq);
                    _events.AddLast(e);
                    if (_events.Count >= Capacity) break;
                }
            }
        }

        /// <summary>A rough byte estimate of the index (for the index-management view).</summary>
        public long ApproxBytes()
        {
            long n = 0;
            lock (_lock)
                foreach (var e in _events)
                {
                    n += (e.Message?.Length ?? 0) + (e.Raw?.Length ?? 0) + (e.Source?.Length ?? 0) + (e.Host?.Length ?? 0) + 48;
                    foreach (var kv in e.Fields) n += kv.Key.Length + (kv.Value?.Length ?? 0) + 4;
                }
            return n * 2;   // chars → bytes (UTF-16-ish) + overhead
        }

        public DateTime? Oldest() { lock (_lock) return _events.Last?.Value.Timestamp; }
        public DateTime? Newest() { lock (_lock) return _events.First?.Value.Timestamp; }

        /// <summary>
        /// Surrounding-documents / "view in context" (Kibana): up to <paramref name="before"/> events
        /// just before and <paramref name="after"/> just after the anchor in time, oldest→newest. When
        /// <paramref name="sameHost"/> is set, only events from that host are considered.
        /// </summary>
        public List<SiemEvent> Surrounding(SiemEvent anchor, int before, int after, string? sameHost = null)
        {
            List<SiemEvent> snap; lock (_lock) snap = _events.ToList();   // newest first
            bool HostOk(SiemEvent e) => string.IsNullOrEmpty(sameHost) || string.Equals(e.Host, sameHost, StringComparison.OrdinalIgnoreCase);

            // events strictly after the anchor (closest first), then reverse to chronological
            var afterList = snap.Where(e => e.Id != anchor.Id && HostOk(e)
                                && (e.Timestamp > anchor.Timestamp || (e.Timestamp == anchor.Timestamp && e.Id > anchor.Id)))
                                .OrderBy(e => e.Timestamp).ThenBy(e => e.Id).Take(after).ToList();
            var beforeList = snap.Where(e => e.Id != anchor.Id && HostOk(e)
                                && (e.Timestamp < anchor.Timestamp || (e.Timestamp == anchor.Timestamp && e.Id < anchor.Id)))
                                .OrderByDescending(e => e.Timestamp).ThenByDescending(e => e.Id).Take(before)
                                .OrderBy(e => e.Timestamp).ThenBy(e => e.Id).ToList();

            var result = new List<SiemEvent>(before + 1 + after);
            result.AddRange(beforeList);
            result.Add(anchor);
            result.AddRange(afterList);
            return result;
        }

        // ── search ──
        public List<SiemEvent> Query(SiemQuery q, SiemRange? range, int limit)
        {
            List<SiemEvent> snap; lock (_lock) snap = _events.ToList();
            var res = new List<SiemEvent>(Math.Min(limit, 4096));
            foreach (var e in snap)
            {
                if (!(range?.Contains(e.Timestamp) ?? true)) continue;
                if (q.Matches(e)) { res.Add(e); if (res.Count >= limit) break; }
            }
            return res;
        }

        public int CountMatching(SiemQuery q, SiemRange? range)
        {
            List<SiemEvent> snap; lock (_lock) snap = _events.ToList();
            int n = 0;
            foreach (var e in snap) if ((range?.Contains(e.Timestamp) ?? true) && q.Matches(e)) n++;
            return n;
        }

        // ── aggregations (Kibana-style) ──
        public Dictionary<SiemSeverity, int> CountBySeverity(SiemQuery q, SiemRange? range)
        {
            var dict = new Dictionary<SiemSeverity, int>();
            foreach (SiemSeverity s in Enum.GetValues(typeof(SiemSeverity))) dict[s] = 0;
            foreach (var e in Filter(q, range)) dict[e.Severity]++;
            return dict;
        }

        public List<(string key, int count)> TopBy(Func<SiemEvent, string> selector, SiemQuery q, SiemRange? range, int n)
            => Filter(q, range).GroupBy(selector)
                .Select(g => (g.Key ?? "", g.Count()))
                .OrderByDescending(t => t.Item2).Take(n).ToList();

        /// <summary>Events per time bucket across the range (oldest → newest), for the histogram.</summary>
        public int[] Histogram(SiemQuery q, SiemRange range, int buckets)
        {
            var counts = new int[buckets];
            var start = range.From;
            double ms = Math.Max(1, range.Span.TotalMilliseconds) / buckets;
            foreach (var e in Filter(q, range))
            {
                int i = (int)((e.Timestamp - start).TotalMilliseconds / ms);
                if (i < 0) i = 0; if (i >= buckets) i = buckets - 1;
                counts[i]++;
            }
            return counts;
        }

        /// <summary>Field-over-time heat map: top-N field values (rows) × time buckets, matrix[row][bucket] = count.</summary>
        public (List<string> rows, int[][] matrix) HeatmapByField(string field, SiemQuery q, SiemRange range, int buckets, int topN)
        {
            buckets = Math.Max(1, buckets); topN = Math.Max(1, topN);
            var events = Filter(q, range).ToList();
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

        // ── config-driven (Lens-style) aggregations ──
        /// <summary>Top values of an arbitrary field (count grouped by the field).</summary>
        public List<(string key, int count)> TopByField(string field, SiemQuery q, SiemRange? range, int n)
            => TopBy(e => e.Get(field) ?? "", q, range, n);

        /// <summary>A single metric over the matching documents (count / unique-count / numeric agg).</summary>
        public double Metric(SiemAgg agg, string field, SiemQuery q, SiemRange? range)
        {
            if (agg == SiemAgg.Count) return CountMatching(q, range);

            if (agg == SiemAgg.UniqueCount)
            {
                var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var e in Filter(q, range)) { var v = e.Get(field); if (!string.IsNullOrEmpty(v)) set.Add(v); }
                return set.Count;
            }

            // numeric aggregations
            double sum = 0, min = double.MaxValue, max = double.MinValue; long count = 0;
            foreach (var e in Filter(q, range))
            {
                var v = e.Get(field);
                if (v == null || !double.TryParse(v, System.Globalization.NumberStyles.Any, System.Globalization.CultureInfo.InvariantCulture, out var x)) continue;
                sum += x; if (x < min) min = x; if (x > max) max = x; count++;
            }
            if (count == 0) return 0;
            return agg switch
            {
                SiemAgg.Sum => sum,
                SiemAgg.Average => sum / count,
                SiemAgg.Min => min,
                SiemAgg.Max => max,
                _ => 0,
            };
        }

        private IEnumerable<SiemEvent> Filter(SiemQuery q, SiemRange? range)
        {
            List<SiemEvent> snap; lock (_lock) snap = _events.ToList();
            foreach (var e in snap) if ((range?.Contains(e.Timestamp) ?? true) && q.Matches(e)) yield return e;
        }

        // ── Discover field aggregations (Kibana-style) ──
        /// <summary>All distinct field names present across the matching documents (sampled), with how many docs have each.</summary>
        public List<(string field, int docs)> FieldNames(SiemQuery q, SiemRange? range, int sampleLimit = 2500)
        {
            var counts = new Dictionary<string, int>();
            int seen = 0;
            foreach (var e in Filter(q, range))
            {
                foreach (var kv in e.AllFields())
                    counts[kv.Key] = counts.TryGetValue(kv.Key, out var c) ? c + 1 : 1;
                if (++seen >= sampleLimit) break;
            }
            return counts.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key)
                         .Select(kv => (kv.Key, kv.Value)).ToList();
        }

        /// <summary>Top values for one field across the matching documents (sampled) — value, count, and % of docs that have the field.</summary>
        public (int total, List<(string value, int count)> top) TopValues(string field, SiemQuery q, SiemRange? range, int n, int sampleLimit = 6000)
        {
            var counts = new Dictionary<string, int>();
            int withField = 0, seen = 0;
            foreach (var e in Filter(q, range))
            {
                var v = e.Get(field);
                if (!string.IsNullOrEmpty(v)) { counts[v] = counts.TryGetValue(v, out var c) ? c + 1 : 1; withField++; }
                if (++seen >= sampleLimit) break;
            }
            var top = counts.OrderByDescending(kv => kv.Value).Take(n).Select(kv => (kv.Key, kv.Value)).ToList();
            return (withField, top);
        }

        // ── multi-machine view: which hosts/agents are reporting in ──
        /// <summary>Per-reporting-machine roll-up for the Sources / Agents view.</summary>
        public List<SiemSourceStat> SourceStats(SiemRange? range)
        {
            List<SiemEvent> snap; lock (_lock) snap = _events.ToList();
            var map = new Dictionary<string, SiemSourceStat>(StringComparer.OrdinalIgnoreCase);
            foreach (var e in snap)
            {
                if (!(range?.Contains(e.Timestamp) ?? true)) continue;
                var key = string.IsNullOrEmpty(e.Host) ? (string.IsNullOrEmpty(e.Source) ? "(unknown)" : e.Source) : e.Host;
                if (!map.TryGetValue(key, out var st))
                    map[key] = st = new SiemSourceStat { Host = key, Source = e.Source };
                st.Events++;
                if (e.Severity == SiemSeverity.Critical) st.Critical++;
                else if (e.Severity == SiemSeverity.High) st.High++;
                if (e.Timestamp > st.LastSeen) { st.LastSeen = e.Timestamp; st.Source = e.Source; }
            }
            return map.Values.OrderByDescending(s => s.Events).ToList();
        }
    }

    /// <summary>One reporting machine / agent / source, rolled up for the Sources view.</summary>
    public sealed class SiemSourceStat
    {
        public string Host { get; set; } = "";
        public string Source { get; set; } = "";
        public int Events { get; set; }
        public int High { get; set; }
        public int Critical { get; set; }
        public DateTime LastSeen { get; set; }

        public string EventsText => Events.ToString("N0");
        public string HighText => High.ToString("N0");
        public string CriticalText => Critical.ToString("N0");
        public string LastSeenText
        {
            get
            {
                var ago = DateTime.Now - LastSeen;
                if (ago.TotalSeconds < 5) return "just now";
                if (ago.TotalSeconds < 60) return $"{(int)ago.TotalSeconds}s ago";
                if (ago.TotalMinutes < 60) return $"{(int)ago.TotalMinutes}m ago";
                if (ago.TotalHours < 24) return $"{(int)ago.TotalHours}h ago";
                return LastSeen.ToString("MM-dd HH:mm");
            }
        }
        public bool IsLive => (DateTime.Now - LastSeen).TotalSeconds < 90;
        public string LiveColor => IsLive ? "#56D364" : "#6E7681";
        public string StatusText => IsLive ? "LIVE" : "IDLE";
    }
}
