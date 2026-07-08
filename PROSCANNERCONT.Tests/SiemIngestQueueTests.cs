using System.Collections.Generic;
using FluentAssertions;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Services.Siem;
using Xunit;

namespace PROSCANNERCONT.Tests;

/// <summary>The bounded collector-side ingest queue: drain to sink, capacity back-pressure, counters.</summary>
public class SiemIngestQueueTests
{
    private static SiemEvent Ev(string host = "h") => new() { Host = host, Category = "auth", Message = "x" };

    [Fact]
    public void Enqueued_events_drain_to_the_sink_with_their_pipeline_flag()
    {
        var sink = new List<(string host, bool pipeline)>();
        var q = new SiemIngestQueue((e, p) => sink.Add((e.Host, p)), autoStart: false);

        q.Enqueue(Ev("a")).Should().BeTrue();
        q.Enqueue(Ev("b"), applyPipeline: false).Should().BeTrue();
        q.DrainOnce().Should().Be(2);

        sink.Should().Equal(("a", true), ("b", false));
        q.TotalEnqueued.Should().Be(2);
        q.TotalProcessed.Should().Be(2);
        q.Depth.Should().Be(0);
    }

    [Fact]
    public void Full_queue_drops_and_counts_without_blocking()
    {
        var q = new SiemIngestQueue((_, _) => { }, autoStart: false) { Capacity = 3 };
        q.Enqueue(Ev()).Should().BeTrue();
        q.Enqueue(Ev()).Should().BeTrue();
        q.Enqueue(Ev()).Should().BeTrue();
        q.Enqueue(Ev()).Should().BeFalse();   // 4th over capacity → dropped
        q.Enqueue(Ev()).Should().BeFalse();

        q.Depth.Should().Be(3);
        q.TotalDropped.Should().Be(2);
        q.TotalEnqueued.Should().Be(3);

        // draining frees capacity so new events are accepted again
        q.DrainOnce().Should().Be(3);
        q.Enqueue(Ev()).Should().BeTrue();
        q.TotalDropped.Should().Be(2);
    }

    [Fact]
    public void Peak_depth_tracks_the_high_water_mark()
    {
        var q = new SiemIngestQueue((_, _) => { }, autoStart: false) { Capacity = 100 };
        for (int i = 0; i < 5; i++) q.Enqueue(Ev());
        q.PeakDepth.Should().Be(5);
        q.DrainOnce();
        q.Depth.Should().Be(0);
        q.PeakDepth.Should().Be(5);   // peak is sticky after draining
    }

    [Fact]
    public void A_throwing_sink_does_not_stop_the_drain()
    {
        int seen = 0;
        var q = new SiemIngestQueue((e, _) => { seen++; if (e.Host == "boom") throw new System.Exception(); }, autoStart: false);
        q.Enqueue(Ev("ok"));
        q.Enqueue(Ev("boom"));
        q.Enqueue(Ev("ok2"));
        q.DrainOnce().Should().Be(3);
        seen.Should().Be(3);          // all three were attempted; the exception was swallowed
        q.TotalProcessed.Should().Be(3);
    }
}
