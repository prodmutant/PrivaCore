using System.Collections.Generic;
using System.ComponentModel;
using System.Text.Json.Serialization;
using FontAwesome.Sharp;
using PrivaCore.ModuleSdk;

namespace PROSCANNERCONT.Models
{
    /// <summary>A module type available in the Add Module catalog.</summary>
    public class ModuleDescriptor
    {
        public string Key { get; set; } = "";
        public string DisplayName { get; set; } = "";
        public string Description { get; set; } = "";
        public IconChar Icon { get; set; } = IconChar.PuzzlePiece;
        public string Category { get; set; } = "";
        public string? PageName { get; set; }
        public bool IsPlaceholder { get; set; }
        public int DefaultPort { get; set; } = 9700;
    }

    /// <summary>A remote module the user added to their nav. Connection state is transient.</summary>
    public class ManagedModule : INotifyPropertyChanged
    {
        /// <summary>Unique per added instance (so the same module type can be added several times).</summary>
        public Guid InstanceId { get; set; } = Guid.NewGuid();
        public string Key { get; set; } = "";
        public string DisplayName { get; set; } = "";
        public IconChar Icon { get; set; } = IconChar.PuzzlePiece;
        public string? PageName { get; set; }
        public string Host { get; set; } = "127.0.0.1";
        public int Port { get; set; } = 9700;
        public string? Username { get; set; }

        private bool _isConnected;
        [JsonIgnore]
        public bool IsConnected
        {
            get => _isConnected;
            set { _isConnected = value; OnPropertyChanged(nameof(IsConnected)); OnPropertyChanged(nameof(StatusText)); }
        }

        [JsonIgnore] public string? SessionToken { get; set; }
        /// <summary>Live connection to the remote module (kept while connected).</summary>
        [JsonIgnore] public ModuleClient? LiveClient { get; set; }

        [JsonIgnore] public string StatusText => IsConnected ? $"● {Host}" : "○ not connected";

        public event PropertyChangedEventHandler? PropertyChanged;
        private void OnPropertyChanged(string n) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(n));
    }

    /// <summary>
    /// The Add Module catalog. Only modules that genuinely run on another machine
    /// are modular (IDS, Honeypot); built-in local tools (Port/Vuln scanner, etc.)
    /// stay in the main nav. Everything else is a "coming soon" placeholder.
    /// </summary>
    public static class ModuleCatalog
    {
        public static IReadOnlyList<ModuleDescriptor> All { get; } = new List<ModuleDescriptor>
        {
            // ── Available modular modules (run as a standalone app on a machine) ──
            new() { Key = "IDS", DisplayName = "Intrusion Detection (IDS)", Category = "Detection",
                    Icon = IconChar.Shield, DefaultPort = 9700,
                    Description = "Deploy on a sensor host. Streams live detections back to the console." },
            new() { Key = "Honeypot", DisplayName = "Honeypot Manager", Category = "Deception",
                    Icon = IconChar.Eye, DefaultPort = 9710,
                    Description = "Run on a honeypot host. Reports captured attacker activity in real time." },
            new() { Key = "SIEM", DisplayName = "SIEM / Log Analytics", Category = "Analytics",
                    Icon = IconChar.ChartBar, DefaultPort = 9720,
                    Description = "Central log collector. Many machines ship logs via the PrivaCore agent; live search, dashboards & a custom pipeline (ELK-style)." },

            // ── Coming soon (planned modular modules) ──
            new() { Key = "EDR",         DisplayName = "Endpoint / EDR",       Category = "Coming soon", Icon = IconChar.Laptop,       IsPlaceholder = true, Description = "Fleet endpoint telemetry and response agent." },
            new() { Key = "CloudSec",    DisplayName = "Cloud Security",       Category = "Coming soon", Icon = IconChar.Cloud,        IsPlaceholder = true, Description = "AWS / Azure / GCP posture and misconfig scanning." },
            new() { Key = "ThreatIntel", DisplayName = "Threat Intel Feed",    Category = "Coming soon", Icon = IconChar.Brain,        IsPlaceholder = true, Description = "IOC feeds and enrichment for alerts." },
            new() { Key = "EmailSec",    DisplayName = "Email / Phishing",     Category = "Coming soon", Icon = IconChar.Envelope,     IsPlaceholder = true, Description = "Mail-flow inspection and phishing detection." },
            new() { Key = "DLP",         DisplayName = "Data Loss Prevention", Category = "Coming soon", Icon = IconChar.UserSecret,   IsPlaceholder = true, Description = "Detect and block sensitive-data exfiltration." },
            new() { Key = "SOAR",        DisplayName = "SOAR / Playbooks",     Category = "Coming soon", Icon = IconChar.Robot,        IsPlaceholder = true, Description = "Automated response playbooks and case workflow." },
            new() { Key = "Firewall",    DisplayName = "Firewall Manager",     Category = "Coming soon", Icon = IconChar.Fire, IsPlaceholder = true, Description = "Central rule management for edge/host firewalls." },
            new() { Key = "Compliance",  DisplayName = "Compliance / GRC",     Category = "Coming soon", Icon = IconChar.Clipboard, IsPlaceholder = true, Description = "Framework mapping, evidence and audit reporting." },
            new() { Key = "AssetInv",    DisplayName = "Asset Inventory",      Category = "Coming soon", Icon = IconChar.Sitemap,      IsPlaceholder = true, Description = "Continuous asset discovery and CMDB sync." },
            new() { Key = "Deception",   DisplayName = "Deception Grid",       Category = "Coming soon", Icon = IconChar.Ghost,    IsPlaceholder = true, Description = "Distributed decoys and breadcrumbs across the network." },
        };
    }
}
