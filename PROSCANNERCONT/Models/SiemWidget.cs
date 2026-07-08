using System;
using System.Collections.Generic;

namespace PROSCANNERCONT.Models
{
    public enum SiemWidgetType
    {
        Stats, Histogram, SeverityDonut, TopSources, TopCategories, TopEventTypes, Feed, Watchlist,
        Custom,   // config-driven (Lens-style): Field + Agg + Chart
    }

    /// <summary>Aggregation applied by a custom visualization (Kibana Lens-style).</summary>
    public enum SiemAgg { Count, UniqueCount, Sum, Average, Min, Max }

    /// <summary>How a custom visualization renders its data.</summary>
    public enum SiemChart { Metric, Bar, Donut, Table, Line, Heatmap, Gauge, Treemap }

    /// <summary>A draggable/resizable panel on the SIEM dashboard canvas (Kibana-style).</summary>
    public class SiemWidget
    {
        public string Id { get; set; } = Guid.NewGuid().ToString("N");
        public SiemWidgetType Type { get; set; }
        public double X { get; set; }
        public double Y { get; set; }
        public double W { get; set; } = 360;
        public double H { get; set; } = 240;

        // ── custom (Lens-style) config — used when Type == Custom ──
        public string Field { get; set; } = "";          // field to aggregate / group by
        public SiemAgg Agg { get; set; } = SiemAgg.Count;
        public SiemChart Chart { get; set; } = SiemChart.Bar;
        public int TopN { get; set; } = 8;
        public string CustomTitle { get; set; } = "";

        /// <summary>The display title for any widget (custom titles derive from their config).</summary>
        public string DisplayTitle()
        {
            if (Type != SiemWidgetType.Custom) return Title(Type);
            if (!string.IsNullOrWhiteSpace(CustomTitle)) return CustomTitle;
            string agg = Agg switch
            {
                SiemAgg.Count => "Count",
                SiemAgg.UniqueCount => "Unique",
                SiemAgg.Sum => "Sum",
                SiemAgg.Average => "Avg",
                SiemAgg.Min => "Min",
                SiemAgg.Max => "Max",
                _ => Agg.ToString(),
            };
            return Chart switch
            {
                SiemChart.Metric or SiemChart.Gauge => $"{agg} {Field}".Trim(),
                SiemChart.Line => $"{Field} over time",
                SiemChart.Heatmap => $"{Field} over time (heat)",
                _ => $"Top {Field}".Trim(),
            };
        }

        public string DisplayIcon() => Type == SiemWidgetType.Custom
            ? Chart switch
            {
                SiemChart.Metric => "Hashtag",
                SiemChart.Bar => "ChartColumn",
                SiemChart.Donut => "ChartPie",
                SiemChart.Table => "TableList",
                SiemChart.Line => "ChartLine",
                SiemChart.Heatmap => "TableCells",
                SiemChart.Gauge => "GaugeHigh",
                SiemChart.Treemap => "TableCellsLarge",
                _ => "ChartBar",
            }
            : Icon(Type);

        public static string Title(SiemWidgetType t) => t switch
        {
            SiemWidgetType.Stats => "Overview",
            SiemWidgetType.Histogram => "Events Over Time",
            SiemWidgetType.SeverityDonut => "By Severity",
            SiemWidgetType.TopSources => "Top Sources",
            SiemWidgetType.TopCategories => "Top Categories",
            SiemWidgetType.TopEventTypes => "Top Event Types",
            SiemWidgetType.Feed => "Live Events",
            SiemWidgetType.Watchlist => "Watchlist (High / Critical)",
            _ => t.ToString(),
        };

        public static string Icon(SiemWidgetType t) => t switch
        {
            SiemWidgetType.Stats => "GaugeHigh",
            SiemWidgetType.Histogram => "ChartColumn",
            SiemWidgetType.SeverityDonut => "ChartPie",
            SiemWidgetType.TopSources => "Server",
            SiemWidgetType.TopCategories => "LayerGroup",
            SiemWidgetType.TopEventTypes => "ListUl",
            SiemWidgetType.Feed => "Stream",
            SiemWidgetType.Watchlist => "TriangleExclamation",
            _ => "ChartBar",
        };

        /// <summary>Default Overview tiles (positions/size are no longer used — tiles flow in a
        /// responsive grid; KPI Stats render in the strip and the Feed lives on the Search tab).</summary>
        public static List<SiemWidget> Default() => new()
        {
            new() { Type = SiemWidgetType.Histogram },
            new() { Type = SiemWidgetType.SeverityDonut },
            new() { Type = SiemWidgetType.TopSources },
            new() { Type = SiemWidgetType.TopCategories },
            new() { Type = SiemWidgetType.TopEventTypes },
            new() { Type = SiemWidgetType.Watchlist },
        };
    }
}
