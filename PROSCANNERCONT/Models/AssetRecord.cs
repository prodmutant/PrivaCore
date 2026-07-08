using System;
using System.Collections.Generic;

namespace PROSCANNERCONT.Models
{
    public class AssetRecord
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string IPAddress { get; set; } = string.Empty;
        public string Hostname { get; set; } = string.Empty;
        public string MacAddress { get; set; } = string.Empty;
        public string OS { get; set; } = string.Empty;
        public string DeviceType { get; set; } = string.Empty;
        public DateTime FirstSeen { get; set; } = DateTime.Now;
        public DateTime LastSeen { get; set; } = DateTime.Now;
        public int TimesDiscovered { get; set; } = 1;
        public bool IsOnline { get; set; }
        public List<int> KnownOpenPorts { get; set; } = new();
        public List<string> KnownServices { get; set; } = new();
        public string Notes { get; set; } = string.Empty;
        public AssetRisk RiskRating { get; set; } = AssetRisk.Unknown;
        public List<AssetEvent> History { get; set; } = new();
    }

    public class AssetEvent
    {
        public DateTime Timestamp { get; set; } = DateTime.Now;
        public string EventType { get; set; } = string.Empty; // "FirstSeen", "NewPort", "PortClosed", "ServiceChanged", "Offline", "Online"
        public string Detail { get; set; } = string.Empty;
    }

    public enum AssetRisk { Unknown, Low, Medium, High, Critical }

    public class NetworkChangeSummary
    {
        public DateTime DetectedAt { get; set; } = DateTime.Now;
        public List<string> NewDevices { get; set; } = new();
        public List<string> DisappearedDevices { get; set; } = new();
        public List<string> NewOpenPorts { get; set; } = new();
        public List<string> ClosedPorts { get; set; } = new();
        public List<string> ServiceChanges { get; set; } = new();
        public bool HasChanges => NewDevices.Count > 0 || DisappearedDevices.Count > 0
            || NewOpenPorts.Count > 0 || ClosedPorts.Count > 0 || ServiceChanges.Count > 0;
        public int TotalChanges => NewDevices.Count + DisappearedDevices.Count
            + NewOpenPorts.Count + ClosedPorts.Count + ServiceChanges.Count;
    }
}
