using System;
using System.Linq;
using FluentAssertions;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Services.Siem;
using Xunit;

namespace PROSCANNERCONT.Tests;

/// <summary>Index management: capacity, age-based purge, delete-by-query, snapshot load.</summary>
[Collection("Siem singleton")]
public class SiemIndexTests : IDisposable
{
    private readonly SiemStore _store = SiemStore.Instance;

    public SiemIndexTests() { _store.Clear(); _store.Pipeline = new SiemPipeline(); _store.MaxAge = TimeSpan.Zero; _store.Capacity = 200_000; }
    public void Dispose() { _store.Clear(); _store.Pipeline = new SiemPipeline(); _store.MaxAge = TimeSpan.Zero; _store.Capacity = 200_000; }

    private SiemEvent At(DateTime ts, string host = "a")
        => new() { Timestamp = ts, Host = host, Source = host, Category = "x", EventType = "x", Severity = SiemSeverity.Info };

    [Fact]
    public void Capacity_trims_oldest_via_purge()
    {
        _store.Capacity = 3;
        for (int i = 0; i < 6; i++) _store.Add(At(DateTime.Now));
        _store.PurgeExpired();
        _store.Count.Should().BeLessThanOrEqualTo(3);
    }

    [Fact]
    public void Surrounding_returns_neighbours_in_time_order_with_anchor_in_place()
    {
        var baseTime = new DateTime(2026, 6, 21, 12, 0, 0);
        // 10 events 1s apart on host "a", plus some noise on host "b"
        var anchors = new System.Collections.Generic.List<SiemEvent>();
        for (int i = 0; i < 10; i++) { var e = At(baseTime.AddSeconds(i), "a"); _store.Add(e); anchors.Add(e); }
        for (int i = 0; i < 5; i++) _store.Add(At(baseTime.AddSeconds(i), "b"));

        var anchor = anchors[5];   // the 6th event on host a
        var ctx = _store.Surrounding(anchor, 3, 3, sameHost: "a");

        ctx.Should().HaveCount(7);                       // 3 before + anchor + 3 after
        ctx[3].Id.Should().Be(anchor.Id);               // anchor centred
        ctx.Should().OnlyContain(e => e.Host == "a");   // host filter respected
        ctx.Select(e => e.Timestamp).Should().BeInAscendingOrder();
    }

    [Fact]
    public void Snapshot_to_file_round_trips_through_restore()
    {
        for (int i = 0; i < 25; i++) _store.Add(At(DateTime.Now.AddSeconds(-i), host: "h" + (i % 3)));
        var path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"siem-snap-{Guid.NewGuid():N}.ndjson.gz");
        try
        {
            int written = SiemPersistence.SnapshotTo(path);
            written.Should().Be(25);

            _store.Clear();
            _store.Count.Should().Be(0);

            int loaded = SiemPersistence.RestoreFrom(path);
            loaded.Should().Be(25);
            _store.Count.Should().Be(25);
        }
        finally { try { System.IO.File.Delete(path); } catch { } }
    }

    [Fact]
    public void Age_based_purge_drops_old_events()
    {
        _store.MaxAge = TimeSpan.FromMinutes(10);
        _store.Add(At(DateTime.Now.AddMinutes(-30)));   // expired
        _store.Add(At(DateTime.Now));                   // fresh
        _store.PurgeExpired();
        _store.Count.Should().Be(1);
        _store.Newest().Should().NotBeNull();
    }

    [Fact]
    public void Delete_by_query_removes_matching()
    {
        _store.Add(At(DateTime.Now, "DC01"));
        _store.Add(At(DateTime.Now, "WEB02"));
        int removed = _store.DeleteMatching(SiemQuery.Parse("host:DC01"), null);
        removed.Should().Be(1);
        _store.Snapshot().Should().ContainSingle(e => e.Host == "WEB02");
    }

    [Fact]
    public void Load_snapshot_restores_events_newest_first()
    {
        var older = At(DateTime.Now.AddMinutes(-5), "old");
        var newer = At(DateTime.Now, "new");
        _store.LoadSnapshot(new[] { older, newer });
        var snap = _store.Snapshot();
        snap.Should().HaveCount(2);
        snap[0].Host.Should().Be("new");   // newest first
    }

    [Fact]
    public void Approx_bytes_grows_with_documents()
    {
        long empty = _store.ApproxBytes();
        _store.Add(At(DateTime.Now));
        _store.ApproxBytes().Should().BeGreaterThan(empty);
    }
}
