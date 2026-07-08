using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Services
{
    /// <summary>
    /// Central config manager. Holds live HIDS runtime settings (since HostIDSDashboardPage is
    /// recreated on navigation). Call Apply() after importing a config file.
    /// </summary>
    public static class ConfigManager
    {
        private static readonly string _dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PrivaCore", "Config");

        private static readonly JsonSerializerOptions _opts = new()
        {
            WriteIndented = true,
            PropertyNameCaseInsensitive = true,
            Converters = { new JsonStringEnumConverter() },
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        // ── Live HIDS settings (persist across page navigations) ─────────
        public static HidsRuntimeSettings Hids { get; private set; } = new();

        // ── IDS mode selected in the setup wizard ─────────────────────────
        public static string? IdsMode { get; private set; }

        /// <summary>Persist the current in-memory state to last_config.json.</summary>
        public static void Save()
        {
            Directory.CreateDirectory(_dir);
            File.WriteAllText(Path.Combine(_dir, "last_config.json"), Serialize(Export()));
        }

        /// <summary>Update the IDS mode and persist it to last_config.json.</summary>
        public static void SetIdsMode(string mode)
        {
            IdsMode = mode;
            Save();
        }

        // ── Apply a loaded config to the engine + HIDS runtime ───────────
        public static (int rulesAdded, int rulesSkipped, string summary) Apply(PrivaCoreConfig config)
        {
            int added = 0, skipped = 0;
            var log = new System.Text.StringBuilder();

            if (config.IdsMode != null)
            {
                IdsMode = config.IdsMode;
                log.AppendLine($"✔ IDS mode set to {config.IdsMode}.");
            }

            if (config.Nids != null)
            {
                var n = config.Nids;

                // Behavioral thresholds
                if (n.BehavioralThresholds != null)
                {
                    var b = n.BehavioralThresholds;
                    IDSManager.Engine.ApplyBehavioralSettings(new BehavioralSettings
                    {
                        SynFloodThreshold   = b.SynFloodThreshold,   SynFloodWindowSec   = b.SynFloodWindowSec,
                        IcmpFloodThreshold  = b.IcmpFloodThreshold,  IcmpFloodWindowSec  = b.IcmpFloodWindowSec,
                        UdpFloodThreshold   = b.UdpFloodThreshold,   UdpFloodWindowSec   = b.UdpFloodWindowSec,
                        PortScanThreshold   = b.PortScanThreshold,   PortScanWindowSec   = b.PortScanWindowSec,
                        BruteForceThreshold = b.BruteForceThreshold, BruteForceWindowSec = b.BruteForceWindowSec
                    });
                    log.AppendLine("✔ Behavioral thresholds applied.");
                }

                // IPS mode
                if (n.IpsMode.HasValue)
                {
                    IDSManager.Engine.IpsMode = n.IpsMode.Value;
                    log.AppendLine($"✔ IPS mode set to {n.IpsMode.Value}.");
                }

                // Allowlist
                if (n.Allowlist != null && n.Allowlist.Count > 0)
                {
                    foreach (var e in n.Allowlist)
                        IDSManager.Engine.AddAllowlistEntry(new AllowlistEntry
                        {
                            IpOrCidr  = e.IpOrCidr,
                            RuleId    = e.RuleId,
                            Note      = e.Note,
                            ExpiresAt = e.ExpiresAt
                        });
                    log.AppendLine($"✔ {n.Allowlist.Count} allowlist entries added.");
                }

                // Rules
                if (n.Rules != null)
                {
                    if (n.ReplaceRules) IDSManager.Engine.ResetToDefaults();
                    var ruleList = n.Rules.Select(r => MapRule(r)).ToList();
                    var json = JsonSerializer.Serialize(ruleList, _opts);
                    (added, skipped) = IDSManager.Engine.ImportRulesJson(json);
                    log.AppendLine($"✔ Rules: {added} added, {skipped} skipped (duplicate ID).");
                }
            }

            if (config.Hids != null)
            {
                var h = config.Hids;
                Hids = new HidsRuntimeSettings
                {
                    PollIntervalSeconds         = Math.Max(1, h.PollIntervalSeconds),
                    CustomWatchPaths            = h.CustomWatchPaths ?? new(),
                    AdditionalProcessBlacklist  = h.AdditionalProcessBlacklist ?? new(),
                    AdditionalSuspiciousPorts   = h.AdditionalSuspiciousPorts ?? new(),
                    AdditionalRegistryKeys      = h.AdditionalRegistryKeys ?? new(),
                    EnableFileHashing           = h.EnableFileHashing,
                    EnableScheduledTaskMonitor  = h.EnableScheduledTaskMonitor,
                    EnableServiceMonitor        = h.EnableServiceMonitor,
                    EnableDnsMonitor            = h.EnableDnsMonitor,
                    EnableSessionMonitor        = h.EnableSessionMonitor,
                    EnableParentChildDetection  = h.EnableParentChildDetection,
                };
                log.AppendLine($"✔ HIDS settings applied (poll={Hids.PollIntervalSeconds}s, paths={Hids.CustomWatchPaths.Count}, extra-procs={Hids.AdditionalProcessBlacklist.Count}).");
            }

            // Save for next launch
            Directory.CreateDirectory(_dir);
            File.WriteAllText(Path.Combine(_dir, "last_config.json"), Serialize(config));

            return (added, skipped, log.ToString().TrimEnd());
        }

        // ── Export current live state ────────────────────────────────────
        public static PrivaCoreConfig Export(IEnumerable<string>? currentCustomPaths = null)
        {
            var b = IDSManager.Engine.GetBehavioralSettings();
            return new PrivaCoreConfig
            {
                Name        = "PrivaCore Export",
                Description = $"Exported on {DateTime.Now:yyyy-MM-dd HH:mm}",
                Author      = Environment.UserName,
                CreatedAt   = DateTime.UtcNow,
                IdsMode     = IdsMode,
                Nids = new NidsConfigBlock
                {
                    ReplaceRules = true,
                    IpsMode      = IDSManager.Engine.IpsMode,
                    BehavioralThresholds = new BehavioralSettingsConfig
                    {
                        SynFloodThreshold   = b.SynFloodThreshold,   SynFloodWindowSec   = b.SynFloodWindowSec,
                        IcmpFloodThreshold  = b.IcmpFloodThreshold,  IcmpFloodWindowSec  = b.IcmpFloodWindowSec,
                        UdpFloodThreshold   = b.UdpFloodThreshold,   UdpFloodWindowSec   = b.UdpFloodWindowSec,
                        PortScanThreshold   = b.PortScanThreshold,   PortScanWindowSec   = b.PortScanWindowSec,
                        BruteForceThreshold = b.BruteForceThreshold, BruteForceWindowSec = b.BruteForceWindowSec
                    },
                    Allowlist = IDSManager.Engine.Allowlist.Select(e => new AllowlistEntryConfig
                    {
                        IpOrCidr = e.IpOrCidr, RuleId = e.RuleId, Note = e.Note, ExpiresAt = e.ExpiresAt
                    }).ToList(),
                    Rules = IDSManager.Engine.Rules.Select(MapRuleBack).ToList()
                },
                Hids = new HidsConfigBlock
                {
                    PollIntervalSeconds        = Hids.PollIntervalSeconds,
                    CustomWatchPaths           = Hids.CustomWatchPaths,
                    AdditionalProcessBlacklist = Hids.AdditionalProcessBlacklist,
                    AdditionalSuspiciousPorts  = Hids.AdditionalSuspiciousPorts,
                    AdditionalRegistryKeys     = Hids.AdditionalRegistryKeys,
                    EnableFileHashing          = Hids.EnableFileHashing,
                    EnableScheduledTaskMonitor = Hids.EnableScheduledTaskMonitor,
                    EnableServiceMonitor       = Hids.EnableServiceMonitor,
                    EnableDnsMonitor           = Hids.EnableDnsMonitor,
                    EnableSessionMonitor       = Hids.EnableSessionMonitor,
                    EnableParentChildDetection = Hids.EnableParentChildDetection,
                }
            };
        }

        public static string Serialize(PrivaCoreConfig cfg) =>
            JsonSerializer.Serialize(cfg, _opts);

        public static PrivaCoreConfig? Deserialize(string json) =>
            JsonSerializer.Deserialize<PrivaCoreConfig>(json, _opts);

        // ── Auto-load last config on startup ─────────────────────────────
        public static void TryLoadLastConfig()
        {
            try
            {
                string path = Path.Combine(_dir, "last_config.json");
                if (!File.Exists(path)) return;
                var cfg = Deserialize(File.ReadAllText(path));
                if (cfg != null) Apply(cfg);
            }
            catch { }
        }

        // ── Model mappers ─────────────────────────────────────────────────
        private static IDSRule MapRule(IDSRuleConfig r)
        {
            Enum.TryParse<IDSAlertSeverity>(r.Severity, out var sev);
            Enum.TryParse<RuleKind>(r.RuleKind, out var kind);
            return new IDSRule
            {
                Id = Guid.NewGuid(), RuleId = r.RuleId, Name = r.Name, Description = r.Description,
                IsEnabled = r.IsEnabled, Severity = sev, Protocol = r.Protocol,
                SourceIP = r.SourceIP, DestinationIP = r.DestinationIP,
                SourcePort = r.SourcePort, DestinationPort = r.DestinationPort,
                Pattern = r.Pattern, AttackCategory = r.AttackCategory, RuleKind = kind,
                RequireNullFlags = r.RequireNullFlags, RequireXmasFlags = r.RequireXmasFlags,
                MinPacketSize = r.MinPacketSize, MaxPacketSize = r.MaxPacketSize,
                AlertThreshold = r.AlertThreshold, AlertWindowSec = r.AlertWindowSec,
                CreatedDate = DateTime.Now, ModifiedDate = DateTime.Now
            };
        }

        private static IDSRuleConfig MapRuleBack(IDSRule r) => new()
        {
            RuleId = r.RuleId, Name = r.Name, Description = r.Description,
            IsEnabled = r.IsEnabled, Severity = r.Severity.ToString(), Protocol = r.Protocol,
            SourceIP = r.SourceIP, DestinationIP = r.DestinationIP,
            SourcePort = r.SourcePort, DestinationPort = r.DestinationPort,
            Pattern = r.Pattern, AttackCategory = r.AttackCategory, RuleKind = r.RuleKind.ToString(),
            RequireNullFlags = r.RequireNullFlags, RequireXmasFlags = r.RequireXmasFlags,
            MinPacketSize = r.MinPacketSize, MaxPacketSize = r.MaxPacketSize,
            AlertThreshold = r.AlertThreshold, AlertWindowSec = r.AlertWindowSec
        };
    }

    /// <summary>Live HIDS settings singleton — survives page navigation.</summary>
    public class HidsRuntimeSettings
    {
        public int PollIntervalSeconds        { get; set; } = 5;
        public List<string> CustomWatchPaths            { get; set; } = new();
        public List<string> AdditionalProcessBlacklist  { get; set; } = new();
        public List<int>    AdditionalSuspiciousPorts   { get; set; } = new();
        public List<string> AdditionalRegistryKeys      { get; set; } = new();
        public bool EnableFileHashing          { get; set; } = true;
        public bool EnableScheduledTaskMonitor { get; set; } = true;
        public bool EnableServiceMonitor       { get; set; } = true;
        public bool EnableDnsMonitor           { get; set; } = true;
        public bool EnableSessionMonitor       { get; set; } = true;
        public bool EnableParentChildDetection { get; set; } = true;
    }
}
