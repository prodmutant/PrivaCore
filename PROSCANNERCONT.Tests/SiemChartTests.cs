using System;
using System.Linq;
using FluentAssertions;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Services.Siem;
using Xunit;

namespace PROSCANNERCONT.Tests;

/// <summary>The new viz building blocks: squarified treemap layout + field-over-time heat map aggregation.</summary>
[Collection("Siem singleton")]
public class SiemChartTests
{
    // ── treemap layout (pure) ──
    [Fact]
    public void Treemap_tiles_are_area_proportional_and_in_bounds()
    {
        var values = new double[] { 4, 2, 1, 1 };
        var tiles = SiemTreemap.Layout(values, 100, 100);
        tiles.Should().HaveCount(4);

        double total = values.Sum();
        foreach (var t in tiles)
        {
            t.X.Should().BeGreaterThanOrEqualTo(-0.001);
            t.Y.Should().BeGreaterThanOrEqualTo(-0.001);
            (t.X + t.W).Should().BeLessThanOrEqualTo(100.001);
            (t.Y + t.H).Should().BeLessThanOrEqualTo(100.001);
            // area ≈ value / total * canvasArea
            (t.W * t.H).Should().BeApproximately(values[t.Index] / total * 100 * 100, 1.0);
        }
    }

    [Fact]
    public void Treemap_ignores_non_positive_values_and_empty_input()
    {
        SiemTreemap.Layout(new double[] { 0, -3 }, 100, 100).Should().BeEmpty();
        SiemTreemap.Layout(Array.Empty<double>(), 100, 100).Should().BeEmpty();
        SiemTreemap.Layout(new double[] { 1 }, 0, 100).Should().BeEmpty();   // zero area
    }

    [Fact]
    public void Treemap_preserves_original_indices()
    {
        // value 9 is at input index 1 — its tile must carry Index 1 and the largest area
        var tiles = SiemTreemap.Layout(new double[] { 1, 9, 2 }, 200, 100);
        var biggest = tiles.OrderByDescending(t => t.W * t.H).First();
        biggest.Index.Should().Be(1);
    }

    // ── heat map aggregation ──
    [Fact]
    public void Heatmap_rows_are_top_values_with_correct_totals()
    {
        var s = SiemStore.Instance; s.Clear(); s.Pipeline = new SiemPipeline();
        for (int i = 0; i < 3; i++) s.Add(new SiemEvent { Host = "A", Category = "auth" });
        for (int i = 0; i < 2; i++) s.Add(new SiemEvent { Host = "B", Category = "auth" });
        s.Add(new SiemEvent { Host = "C", Category = "auth" });

        var range = SiemRange.Rolling(TimeSpan.FromMinutes(60));
        var (rows, matrix) = s.HeatmapByField("host.name", SiemQuery.Parse(""), range, 6, topN: 2);

        rows.Should().Equal("A", "B");                 // top-2 by total, descending
        matrix[0].Sum().Should().Be(3);                // A
        matrix[1].Sum().Should().Be(2);                // B
        matrix[0].Length.Should().Be(6);               // one column per bucket

        s.Clear();
    }
}
