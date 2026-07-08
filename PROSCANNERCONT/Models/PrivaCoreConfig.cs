using System;
using System.Collections.Generic;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Models
{
    /// <summary>
    /// Root configuration object. Import/export one file to configure everything.
    /// </summary>
    public class PrivaCoreConfig
    {
        public string ConfigVersion { get; set; } = "2.0";
        public string Name        { get; set; } = "";
        public string Description { get; set; } = "";
        public string Author      { get; set; } = "";
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        /// <summary>"Host" or "Network" — which IDS dashboard was selected in the wizard.</summary>
        public string? IdsMode { get; set; }

        public NidsConfigBlock? Nids { get; set; }
        public HidsConfigBlock? Hids { get; set; }
    }

    public class NidsConfigBlock
    {
        /// <summary>true = wipe existing rules then add these; false = add new only (skip duplicates)</summary>
        public bool ReplaceRules { get; set; } = false;

        public BehavioralSettingsConfig? BehavioralThresholds { get; set; }
        public bool? IpsMode { get; set; }

        /// <summary>Allowlist entries to add. Existing entries are kept.</summary>
        public List<AllowlistEntryConfig>? Allowlist { get; set; }

        /// <summary>Rules to add (or replace if ReplaceRules=true). null = leave current rules alone.</summary>
        public List<IDSRuleConfig>? Rules { get; set; }
    }

    public class HidsConfigBlock
    {
        public int PollIntervalSeconds { get; set; } = 5;

        /// <summary>Extra paths to watch in addition to Windows/System32.</summary>
        public List<string> CustomWatchPaths { get; set; } = new();

        /// <summary>Additional process names to flag (beyond the built-in list).</summary>
        public List<string> AdditionalProcessBlacklist { get; set; } = new();

        /// <summary>Additional TCP/UDP ports to flag as suspicious in connections.</summary>
        public List<int> AdditionalSuspiciousPorts { get; set; } = new();

        /// <summary>Additional registry keys to watch (hive\subKey format).</summary>
        public List<string> AdditionalRegistryKeys { get; set; } = new();

        public bool EnableFileHashing           { get; set; } = true;
        public bool EnableScheduledTaskMonitor  { get; set; } = true;
        public bool EnableServiceMonitor        { get; set; } = true;
        public bool EnableDnsMonitor            { get; set; } = true;
        public bool EnableSessionMonitor        { get; set; } = true;
        public bool EnableParentChildDetection  { get; set; } = true;
    }

    // ── Serializable versions of engine types ─────────────────────────────
    // (Using separate classes avoids pulling in computed properties / JsonIgnore issues)

    public class BehavioralSettingsConfig
    {
        public int SynFloodThreshold   { get; set; } = 200; public int SynFloodWindowSec   { get; set; } = 5;
        public int IcmpFloodThreshold  { get; set; } = 100; public int IcmpFloodWindowSec  { get; set; } = 10;
        public int UdpFloodThreshold   { get; set; } = 500; public int UdpFloodWindowSec   { get; set; } = 5;
        public int PortScanThreshold   { get; set; } = 25;  public int PortScanWindowSec   { get; set; } = 10;
        public int BruteForceThreshold { get; set; } = 10;  public int BruteForceWindowSec { get; set; } = 60;
    }

    public class AllowlistEntryConfig
    {
        public string IpOrCidr { get; set; } = "";
        public string? RuleId  { get; set; }
        public string Note     { get; set; } = "";
        public DateTime? ExpiresAt { get; set; }
    }

    public class IDSRuleConfig
    {
        public string RuleId         { get; set; } = "";
        public string Name           { get; set; } = "";
        public string Description    { get; set; } = "";
        public bool   IsEnabled      { get; set; } = true;
        public string Severity       { get; set; } = "Medium";
        public string Protocol       { get; set; } = "any";
        public string SourceIP       { get; set; } = "any";
        public string DestinationIP  { get; set; } = "any";
        public string SourcePort     { get; set; } = "any";
        public string DestinationPort{ get; set; } = "any";
        public string Pattern        { get; set; } = "";
        public string AttackCategory { get; set; } = "";
        public string RuleKind       { get; set; } = "Signature";
        public bool   RequireNullFlags{ get; set; }
        public bool   RequireXmasFlags{ get; set; }
        public int    MinPacketSize  { get; set; }
        public int    MaxPacketSize  { get; set; }
        public int    AlertThreshold { get; set; }
        public int    AlertWindowSec { get; set; } = 60;
    }
}
