using System;
using FluentAssertions;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Services.Siem;
using Xunit;

namespace PROSCANNERCONT.Tests;

/// <summary>Config-driven (Lens-style) aggregations used by custom dashboard tiles.</summary>
[Collection("Siem singleton")]
public class SiemVizTests : IDisposable
{
    private readonly SiemStore _store = SiemStore.Instance;
    public SiemVizTests() { _store.Clear(); _store.Pipeline = new SiemPipeline(); }
    public void Dispose() { _store.Clear(); _store.Pipeline = new SiemPipeline(); }

    private SiemEvent Ev(string host, int bytes)
    {
        var e = new SiemEvent { Host = host, Source = host, Category = "network", EventType = "flow", Severity = SiemSeverity.Info };
        e.Fields["network.bytes"] = bytes.ToString();
        return e;
    }

    private SiemQuery Q => SiemQuery.Parse(null);

    [Fact]
    public void Count_metric()
    {
        _store.Add(Ev("a", 10)); _store.Add(Ev("b", 20));
        _store.Metric(SiemAgg.Count, "", Q, null).Should().Be(2);
    }

    [Fact]
    public void Unique_count_metric()
    {
        _store.Add(Ev("a", 10)); _store.Add(Ev("a", 11)); _store.Add(Ev("b", 12));
        _store.Metric(SiemAgg.UniqueCount, "host.name", Q, null).Should().Be(2);
    }

    [Fact]
    public void Sum_avg_min_max_over_numeric_field()
    {
        _store.Add(Ev("a", 100)); _store.Add(Ev("b", 300));
        _store.Metric(SiemAgg.Sum, "network.bytes", Q, null).Should().Be(400);
        _store.Metric(SiemAgg.Average, "network.bytes", Q, null).Should().Be(200);
        _store.Metric(SiemAgg.Min, "network.bytes", Q, null).Should().Be(100);
        _store.Metric(SiemAgg.Max, "network.bytes", Q, null).Should().Be(300);
    }

    [Fact]
    public void TopByField_groups_and_counts()
    {
        _store.Add(Ev("a", 1)); _store.Add(Ev("a", 2)); _store.Add(Ev("b", 3));
        var top = _store.TopByField("host.name", Q, null, 5);
        top.Should().HaveCount(2);
        top[0].key.Should().Be("a");
        top[0].count.Should().Be(2);
    }

    [Fact]
    public void Custom_widget_title_derives_from_config()
    {
        var w = new SiemWidget { Type = SiemWidgetType.Custom, Chart = SiemChart.Metric, Agg = SiemAgg.UniqueCount, Field = "source.ip" };
        w.DisplayTitle().Should().Contain("source.ip");
        var bar = new SiemWidget { Type = SiemWidgetType.Custom, Chart = SiemChart.Bar, Field = "host.name" };
        bar.DisplayTitle().Should().Be("Top host.name");
    }

    [Fact]
    public void Dashboard_doc_resolves_current_and_falls_back()
    {
        var doc = new SiemDashboardDoc { Current = "Threats" };
        doc.Dashboards.Add(new SiemDashboard { Name = "Default" });
        doc.Dashboards.Add(new SiemDashboard { Name = "Threats" });
        doc.CurrentDashboard().Name.Should().Be("Threats");

        doc.Current = "Missing";   // unknown → first dashboard
        doc.CurrentDashboard().Name.Should().Be("Default");
    }
}
