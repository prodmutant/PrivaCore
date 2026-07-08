using System;

namespace PROSCANNERCONT.Models
{
    public class AllowlistEntry
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string IpOrCidr { get; set; } = "";
        // null = suppress all rules; non-null = suppress only that specific rule ID
        public string? RuleId { get; set; }
        public string Note { get; set; } = "";
        public DateTime AddedDate { get; set; } = DateTime.Now;
        public DateTime? ExpiresAt { get; set; }

        [System.Text.Json.Serialization.JsonIgnore]
        public bool IsExpired => ExpiresAt.HasValue && ExpiresAt.Value < DateTime.Now;

        [System.Text.Json.Serialization.JsonIgnore]
        public string RuleDisplay => string.IsNullOrEmpty(RuleId) ? "All Rules" : RuleId;

        [System.Text.Json.Serialization.JsonIgnore]
        public string ExpiryDisplay => ExpiresAt.HasValue ? ExpiresAt.Value.ToString("yyyy-MM-dd HH:mm") : "Never";
    }

    public class BlockedIpEntry
    {
        public string IP { get; set; } = "";
        public string Reason { get; set; } = "";
        public DateTime BlockedAt { get; set; } = DateTime.Now;
        public string AlertType { get; set; } = "";

        [System.Text.Json.Serialization.JsonIgnore]
        public string BlockedAtFormatted => BlockedAt.ToString("yyyy-MM-dd HH:mm:ss");
    }

    public class CorrelationGroup
    {
        public string SourceIP { get; set; } = "";
        public int AlertCount { get; set; }
        public string Categories { get; set; } = "";
        public string MaxSeverity { get; set; } = "";
        public string MaxSeverityColor { get; set; } = "#808080";
        public DateTime FirstSeen { get; set; }
        public DateTime LastSeen { get; set; }
        public bool IsKillChain { get; set; }

        [System.Text.Json.Serialization.JsonIgnore]
        public string KillChainDisplay => IsKillChain ? "⚠ Kill Chain" : "";

        [System.Text.Json.Serialization.JsonIgnore]
        public string FirstSeenFormatted => FirstSeen.ToString("HH:mm:ss");

        [System.Text.Json.Serialization.JsonIgnore]
        public string LastSeenFormatted => LastSeen.ToString("HH:mm:ss");
    }

    public class TimelineBucket
    {
        public string Hour { get; set; } = "";
        public int Count { get; set; }
        public string Color { get; set; } = "#333333";
        public string Tooltip { get; set; } = "";
        public double BarHeight { get; set; } = 4;
    }
}
