using System;
using System.Collections.Generic;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Services.Siem
{
    /// <summary>
    /// The SIEM index abstraction (the "Elasticsearch" seam). Captures the full surface the UI and
    /// engine use — ingest, retention, search, and aggregations — so the concrete in-memory
    /// <see cref="SiemStore"/> can later be swapped for an Elasticsearch/OpenSearch-backed store
    /// without touching consumers. Resolve the active store via <see cref="SiemStoreProvider.Current"/>;
    /// do not reference the concrete singleton directly outside the store/provider themselves.
    /// </summary>
    public interface ISiemStore
    {
        // ── capacity / retention knobs ──
        int Capacity { get; set; }
        /// <summary>Age-based retention: events older than this are purged. Zero = keep regardless of age.</summary>
        TimeSpan MaxAge { get; set; }

        // ── counters ──
        int Count { get; }
        long TotalIngested { get; }
        long TotalDropped { get; }

        /// <summary>The user-configurable processing pipeline applied to every ingested event.</summary>
        SiemPipeline Pipeline { get; set; }

        /// <summary>Raised after an event is added to the index.</summary>
        event EventHandler<SiemEvent>? EventAdded;

        // ── ingest / lifecycle ──
        void Add(SiemEvent e, bool applyPipeline = true);
        void Clear();
        List<SiemEvent> Snapshot();
        int PurgeExpired();
        int DeleteMatching(SiemQuery q, SiemRange? range);
        void LoadSnapshot(IEnumerable<SiemEvent> events);

        // ── index metadata ──
        long ApproxBytes();
        DateTime? Oldest();
        DateTime? Newest();
        List<SiemEvent> Surrounding(SiemEvent anchor, int before, int after, string? sameHost = null);

        // ── search ──
        List<SiemEvent> Query(SiemQuery q, SiemRange? range, int limit);
        int CountMatching(SiemQuery q, SiemRange? range);

        // ── aggregations ──
        Dictionary<SiemSeverity, int> CountBySeverity(SiemQuery q, SiemRange? range);
        List<(string key, int count)> TopBy(Func<SiemEvent, string> selector, SiemQuery q, SiemRange? range, int n);
        int[] Histogram(SiemQuery q, SiemRange range, int buckets);
        /// <summary>Field-over-time heat map: the top-N values of a field (rows) × time buckets (cols); matrix[row][bucket] = count.</summary>
        (List<string> rows, int[][] matrix) HeatmapByField(string field, SiemQuery q, SiemRange range, int buckets, int topN);
        List<(string key, int count)> TopByField(string field, SiemQuery q, SiemRange? range, int n);
        double Metric(SiemAgg agg, string field, SiemQuery q, SiemRange? range);

        // ── Discover field aggregations ──
        List<(string field, int docs)> FieldNames(SiemQuery q, SiemRange? range, int sampleLimit = 2500);
        (int total, List<(string value, int count)> top) TopValues(string field, SiemQuery q, SiemRange? range, int n, int sampleLimit = 6000);

        // ── multi-machine roll-up ──
        List<SiemSourceStat> SourceStats(SiemRange? range);
    }

    /// <summary>
    /// Resolves the active <see cref="ISiemStore"/>. Defaults to the in-memory <see cref="SiemStore"/>
    /// singleton; assign <see cref="Current"/> at startup to swap in an alternative backend (e.g. an
    /// Elasticsearch-backed store) without changing any consumer.
    /// </summary>
    public static class SiemStoreProvider
    {
        private static ISiemStore? _current;

        public static ISiemStore Current
        {
            get => _current ??= SiemStore.Instance;
            set => _current = value ?? throw new ArgumentNullException(nameof(value));
        }
    }
}
