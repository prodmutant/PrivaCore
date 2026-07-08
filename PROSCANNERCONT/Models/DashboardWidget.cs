using System;
using System.Collections.Generic;

namespace PROSCANNERCONT.Models
{
    public enum WidgetType
    {
        ModuleStatus,
        RecentFindings,
        IDSAlerts,
        TrafficStats,
        TopThreats,
        SecurityScore,
        NetworkSpeed,
        HostsList,
        ActivityChart,
        VulnSummary,
        QuickActions,
        SystemResources,
        OpenPorts,
        AlertTrend,
        HoneypotActivity,
        CVEExploit,
        AssetChanges,
        IdsRuleStats,
        LiveTraffic
    }

    public enum WidgetSize { Small, Medium, Large }

    public class DashboardWidget
    {
        public string     Id           { get; set; } = Guid.NewGuid().ToString();
        public WidgetType Type         { get; set; }
        public bool       Visible      { get; set; } = true;
        public int        Order        { get; set; }
        public WidgetSize Size         { get; set; } = WidgetSize.Medium;
        public double?    CustomWidth  { get; set; }
        public double?    CustomHeight { get; set; }
        public double?    X            { get; set; }
        public double?    Y            { get; set; }

        public static double WidthFor(WidgetSize size) => size switch
        {
            WidgetSize.Small  => 240,
            WidgetSize.Large  => 540,
            _                 => 360
        };

        public static string DisplayName(WidgetType t) => t switch
        {
            WidgetType.ModuleStatus      => "Module Status",
            WidgetType.RecentFindings    => "Recent Findings",
            WidgetType.IDSAlerts         => "IDS Live Alerts",
            WidgetType.TrafficStats      => "Traffic Stats",
            WidgetType.TopThreats        => "Top Threats",
            WidgetType.SecurityScore     => "Security Score",
            WidgetType.NetworkSpeed      => "Network Speed",
            WidgetType.HostsList         => "Discovered Hosts",
            WidgetType.ActivityChart     => "Activity (7 days)",
            WidgetType.VulnSummary       => "Vulnerability Summary",
            WidgetType.QuickActions      => "Quick Actions",
            WidgetType.SystemResources   => "System Resources",
            WidgetType.OpenPorts         => "Open Ports",
            WidgetType.AlertTrend        => "Alert Trend (24h)",
            WidgetType.HoneypotActivity  => "Honeypot Activity",
            WidgetType.CVEExploit        => "CVE Exploits",
            WidgetType.AssetChanges      => "Asset Changes",
            WidgetType.IdsRuleStats      => "IDS Rule Stats",
            WidgetType.LiveTraffic       => "Live Traffic",
            _                            => t.ToString()
        };

        public static string Description(WidgetType t) => t switch
        {
            WidgetType.ModuleStatus      => "Status of all PrivaCore modules at a glance",
            WidgetType.RecentFindings    => "Latest scan results from all modules",
            WidgetType.IDSAlerts         => "Live IDS alerts with severity breakdown",
            WidgetType.TrafficStats      => "Packet counts, data rate, and protocol mix",
            WidgetType.TopThreats        => "Top threat categories detected by IDS",
            WidgetType.SecurityScore     => "Last security check score and risk level",
            WidgetType.NetworkSpeed      => "Download speed test result",
            WidgetType.HostsList         => "Network devices discovered by scanner",
            WidgetType.ActivityChart     => "Scan activity over the last 7 days",
            WidgetType.VulnSummary       => "Vulnerability counts grouped by severity",
            WidgetType.QuickActions      => "One-click shortcuts to common operations",
            WidgetType.SystemResources   => "App memory usage and disk free space",
            WidgetType.OpenPorts         => "Most common open ports found by port scanner",
            WidgetType.AlertTrend        => "IDS alert counts over the last 24 hours",
            WidgetType.HoneypotActivity  => "Honeypot traps triggered, grouped by trap name",
            WidgetType.CVEExploit        => "Open ports with known CVEs ranked by CVSS score",
            WidgetType.AssetChanges      => "New, offline, and changed devices since last scan",
            WidgetType.IdsRuleStats      => "Top-triggered IDS rules with hit counts",
            WidgetType.LiveTraffic       => "Live packet capture: rates, bytes, and threats",
            _                            => ""
        };

        public static List<DashboardWidget> Defaults() => new()
        {
            new() { Type = WidgetType.ModuleStatus,     Visible = true,  Order = 0,  Size = WidgetSize.Medium },
            new() { Type = WidgetType.RecentFindings,   Visible = true,  Order = 1,  Size = WidgetSize.Large  },
            new() { Type = WidgetType.IDSAlerts,        Visible = true,  Order = 2,  Size = WidgetSize.Medium },
            new() { Type = WidgetType.SecurityScore,    Visible = true,  Order = 3,  Size = WidgetSize.Small  },
            new() { Type = WidgetType.TrafficStats,     Visible = false, Order = 4,  Size = WidgetSize.Medium },
            new() { Type = WidgetType.TopThreats,       Visible = false, Order = 5,  Size = WidgetSize.Medium },
            new() { Type = WidgetType.NetworkSpeed,     Visible = false, Order = 6,  Size = WidgetSize.Small  },
            new() { Type = WidgetType.HostsList,        Visible = false, Order = 7,  Size = WidgetSize.Medium },
            new() { Type = WidgetType.ActivityChart,    Visible = false, Order = 8,  Size = WidgetSize.Medium },
            new() { Type = WidgetType.VulnSummary,      Visible = false, Order = 9,  Size = WidgetSize.Small  },
            new() { Type = WidgetType.QuickActions,     Visible = false, Order = 10, Size = WidgetSize.Medium },
            new() { Type = WidgetType.SystemResources,  Visible = false, Order = 11, Size = WidgetSize.Small  },
            new() { Type = WidgetType.OpenPorts,        Visible = false, Order = 12, Size = WidgetSize.Medium },
            new() { Type = WidgetType.AlertTrend,       Visible = false, Order = 13, Size = WidgetSize.Medium },
            new() { Type = WidgetType.HoneypotActivity, Visible = false, Order = 14, Size = WidgetSize.Medium },
            new() { Type = WidgetType.CVEExploit,       Visible = false, Order = 15, Size = WidgetSize.Medium },
            new() { Type = WidgetType.AssetChanges,     Visible = false, Order = 16, Size = WidgetSize.Medium },
            new() { Type = WidgetType.IdsRuleStats,     Visible = false, Order = 17, Size = WidgetSize.Medium },
            new() { Type = WidgetType.LiveTraffic,      Visible = false, Order = 18, Size = WidgetSize.Medium },
        };
    }
}
