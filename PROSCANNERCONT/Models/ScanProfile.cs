using System;
using System.Collections.Generic;

namespace PROSCANNERCONT.Models
{
    public class ScanProfile
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; } = DateTime.Now;
        public DateTime LastUsed { get; set; } = DateTime.Now;
        public int TimesUsed { get; set; }

        // Scan target settings
        public string Target { get; set; } = string.Empty;
        public int StartPort { get; set; } = 1;
        public int EndPort { get; set; } = 1024;
        public string ScanType { get; set; } = "TCP Connect";
        public int TimeoutMs { get; set; } = 2000;
        public int MaxConcurrent { get; set; } = 50;
        public bool CheckCves { get; set; } = true;
        public bool DetectVersions { get; set; } = true;
        public List<int> CustomPorts { get; set; } = new();

        // Convenience
        public string Summary => $"{Target} | Ports {StartPort}-{EndPort} | {ScanType}";
    }
}
