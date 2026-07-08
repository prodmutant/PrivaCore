using System;
using System.Collections.Generic;
using FluentAssertions;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Services.Siem;
using Xunit;

namespace PROSCANNERCONT.Tests;

/// <summary>The ISiemStore abstraction + provider seam (de-risking a future Elasticsearch backend).</summary>
[Collection("Siem singleton")]
public class SiemStoreProviderTests
{
    [Fact]
    public void Concrete_store_implements_the_interface()
        => SiemStore.Instance.Should().BeAssignableTo<ISiemStore>();

    [Fact]
    public void Provider_defaults_to_the_in_memory_singleton()
        => SiemStoreProvider.Current.Should().BeSameAs(SiemStore.Instance);

    [Fact]
    public void Provider_can_be_swapped_and_consumers_see_the_replacement()
    {
        var fake = new CountingStore();
        var original = SiemStoreProvider.Current;
        try
        {
            SiemStoreProvider.Current = fake;
            SiemStoreProvider.Current.Should().BeSameAs(fake);

            // a consumer resolving via the provider hits the replacement
            SiemStoreProvider.Current.Add(new SiemEvent());
            fake.Added.Should().Be(1);
        }
        finally { SiemStoreProvider.Current = original; }
    }

    [Fact]
    public void Provider_rejects_null()
    {
        Action act = () => SiemStoreProvider.Current = null!;
        act.Should().Throw<ArgumentNullException>();
    }

    /// <summary>A minimal alternate ISiemStore implementation — proves the seam is swappable.</summary>
    private sealed class CountingStore : ISiemStore
    {
        public int Added;
        public int Capacity { get; set; }
        public TimeSpan MaxAge { get; set; }
        public int Count => Added;
        public long TotalIngested => Added;
        public long TotalDropped => 0;
        public SiemPipeline Pipeline { get; set; } = new();
        public event EventHandler<SiemEvent>? EventAdded;
        public void Add(SiemEvent e, bool applyPipeline = true) { Added++; EventAdded?.Invoke(this, e); }
        public void Clear() => Added = 0;
        public List<SiemEvent> Snapshot() => new();
        public int PurgeExpired() => 0;
        public int DeleteMatching(SiemQuery q, SiemRange? range) => 0;
        public void LoadSnapshot(IEnumerable<SiemEvent> events) { }
        public long ApproxBytes() => 0;
        public DateTime? Oldest() => null;
        public DateTime? Newest() => null;
        public List<SiemEvent> Surrounding(SiemEvent anchor, int before, int after, string? sameHost = null) => new();
        public List<SiemEvent> Query(SiemQuery q, SiemRange? range, int limit) => new();
        public int CountMatching(SiemQuery q, SiemRange? range) => 0;
        public Dictionary<SiemSeverity, int> CountBySeverity(SiemQuery q, SiemRange? range) => new();
        public List<(string key, int count)> TopBy(Func<SiemEvent, string> selector, SiemQuery q, SiemRange? range, int n) => new();
        public int[] Histogram(SiemQuery q, SiemRange range, int buckets) => new int[buckets];
        public (List<string> rows, int[][] matrix) HeatmapByField(string field, SiemQuery q, SiemRange range, int buckets, int topN) => (new(), Array.Empty<int[]>());
        public List<(string key, int count)> TopByField(string field, SiemQuery q, SiemRange? range, int n) => new();
        public double Metric(SiemAgg agg, string field, SiemQuery q, SiemRange? range) => 0;
        public List<(string field, int docs)> FieldNames(SiemQuery q, SiemRange? range, int sampleLimit = 2500) => new();
        public (int total, List<(string value, int count)> top) TopValues(string field, SiemQuery q, SiemRange? range, int n, int sampleLimit = 6000) => (0, new());
        public List<SiemSourceStat> SourceStats(SiemRange? range) => new();
    }
}
