using System;
using FluentAssertions;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Services.Siem;
using Xunit;

namespace PROSCANNERCONT.Tests;

/// <summary>SiemRange: rolling / absolute / all-time semantics + store filtering by absolute range.</summary>
[Collection("Siem singleton")]
public class SiemRangeTests : IDisposable
{
    private readonly SiemStore _store = SiemStore.Instance;
    public SiemRangeTests() { _store.Clear(); _store.Pipeline = new SiemPipeline(); }
    public void Dispose() { _store.Clear(); _store.Pipeline = new SiemPipeline(); }

    [Fact]
    public void Rolling_contains_recent_excludes_old()
    {
        var r = SiemRange.Rolling(TimeSpan.FromMinutes(10))!;
        r.Contains(DateTime.Now).Should().BeTrue();
        r.Contains(DateTime.Now.AddMinutes(-30)).Should().BeFalse();
    }

    [Fact]
    public void Null_range_is_all_time()
    {
        SiemRange.Rolling(null).Should().BeNull();   // null = all time by convention
    }

    [Fact]
    public void Absolute_contains_within_bounds_only()
    {
        var from = new DateTime(2026, 1, 1, 9, 0, 0);
        var to = new DateTime(2026, 1, 1, 12, 0, 0);
        var r = SiemRange.Absolute(from, to);
        r.Contains(new DateTime(2026, 1, 1, 10, 0, 0)).Should().BeTrue();
        r.Contains(new DateTime(2026, 1, 1, 8, 0, 0)).Should().BeFalse();
        r.Contains(new DateTime(2026, 1, 1, 13, 0, 0)).Should().BeFalse();
    }

    [Fact]
    public void Absolute_swaps_reversed_bounds()
    {
        var r = SiemRange.Absolute(new DateTime(2026, 1, 2), new DateTime(2026, 1, 1));
        r.From.Should().Be(new DateTime(2026, 1, 1));
        r.To.Should().Be(new DateTime(2026, 1, 2));
    }

    [Fact]
    public void TimeSpan_implicitly_becomes_rolling_range()
    {
        SiemRange r = TimeSpan.FromMinutes(5);
        r.Contains(DateTime.Now).Should().BeTrue();
    }

    [Fact]
    public void Store_query_honours_absolute_range()
    {
        var inRange = new SiemEvent { Timestamp = new DateTime(2026, 1, 1, 10, 0, 0), Host = "a", Category = "x", EventType = "x" };
        var outRange = new SiemEvent { Timestamp = new DateTime(2026, 1, 1, 20, 0, 0), Host = "b", Category = "x", EventType = "x" };
        _store.Add(inRange); _store.Add(outRange);

        var r = SiemRange.Absolute(new DateTime(2026, 1, 1, 9, 0, 0), new DateTime(2026, 1, 1, 11, 0, 0));
        var hits = _store.Query(SiemQuery.Parse(null), r, 100);
        hits.Should().ContainSingle().Which.Host.Should().Be("a");
    }
}
