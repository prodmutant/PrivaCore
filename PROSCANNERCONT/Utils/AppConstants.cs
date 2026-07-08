using System;
using System.IO;

namespace PROSCANNERCONT.Utils
{
    /// <summary>
    /// Central location for all application-wide constants.
    /// Replace magic numbers throughout the codebase with references to these values.
    /// </summary>
    public static class AppConstants
    {
        public static class Scanning
        {
            public const int DefaultConnectionTimeoutMs = 2000;
            public const int MaxConcurrentScans = 50;
            public const int DefaultPortScanTimeoutMs = 1500;
            public const int VersionDetectionTimeoutMs = 3000;
            public const int BannerReadTimeoutMs = 1500;
            public const int PingTimeoutMs = 1000;
            public const int DnsResolutionTimeoutSec = 2;
            public const int ArpReadTimeoutMs = 2000;

            public static readonly int[] CommonPorts =
            {
                21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                3306, 3389, 5432, 5900, 8080, 8443
            };

            public static readonly int[] QuickScanPorts =
            {
                21, 22, 23, 80, 443, 3389, 8080
            };
        }

        public static class State
        {
            public const int MaxRecentScanResults = 50;
            public const int MaxScanHistory = 100;
            public const int MaxAlerts = 1000;
            public const int DefaultRequestTimeoutMs = 1000;
            public const int DefaultMiscPageTimeoutMs = 2000;
            public const string DefaultVulnConcurrentScans = "100";
        }

        public static class Paths
        {
            public static readonly string AppDataDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PrivaCore");

            public static readonly string ConfigDir = Path.Combine(AppDataDir, "Config");

            public static readonly string IdsDir = Path.Combine(AppDataDir, "IDS");

            // State persistence file names (relative to working directory, kept for backward compat)
            public const string NetworkScanResultsFile = "networkScanResults.json";
            public const string HostCountStateFile = "hostCountState.json";
            public const string RecentScanResultsFile = "recentScanResults.json";
            public const string VulnerabilityScanResultsFile = "vulnerabilityScanResults.json";
            public const string VulnerabilityPageStateFile = "vulnerabilityPageState.json";
            public const string VulnerabilityStateFile = "vulnerabilityState.json";
            public const string MiscellaneousPageStateFile = "miscellaneousPageState.json";
            public const string TrafficAnalysisStateFile = "trafficAnalysisState.json";
        }

        public static class IDS
        {
            public const int MaxAlertsInMemory = 5000;
            public const int AlertDedupCooldownSec = 10;
            public const int BehavioralAlertCooldownSec = 30;
            public const int BackgroundSaveIntervalMs = 5_000;
            public const int TrackerPruneIntervalSec = 60;
            public const int TrackerIdleMinutes = 5;
            public const int KillChainWindowSeconds = 300;
        }

        public static class Network
        {
            public const int MaxParallelDiscovery = 50;
            public const int SubnetBroadcastOctet1 = 1;
            public const int SubnetBroadcastOctet254 = 254;
        }
    }
}
