using System;

namespace PROSCANNERCONT.Models
{
    public enum LicenseTier { Free, Pro, Enterprise }

    public class LicenseInfo
    {
        public string LicenseKey { get; set; } = string.Empty;
        public LicenseTier Tier { get; set; } = LicenseTier.Free;
        public string LicensedTo { get; set; } = string.Empty;
        public string Organization { get; set; } = string.Empty;
        public DateTime ActivatedAt { get; set; }
        public DateTime ExpiresAt { get; set; } = DateTime.MaxValue;
        public bool IsValid { get; set; }
        public bool IsExpired => ExpiresAt < DateTime.Now;

        // Feature gates
        public bool CanExportCsv => Tier >= LicenseTier.Pro;
        public bool CanExportJson => Tier >= LicenseTier.Pro;
        public bool CanUseScanProfiles => Tier >= LicenseTier.Pro;
        public bool CanUseScheduledScans => Tier >= LicenseTier.Enterprise;
        public bool CanUseAssetInventory => Tier >= LicenseTier.Pro;
        public bool HasUnlimitedScans => Tier >= LicenseTier.Pro;
        public int MaxConcurrentScans => Tier switch
        {
            LicenseTier.Free => 10,
            LicenseTier.Pro => 100,
            LicenseTier.Enterprise => 500,
            _ => 10
        };

        public string TierDisplayName => Tier switch
        {
            LicenseTier.Free => "Free",
            LicenseTier.Pro => "Pro",
            LicenseTier.Enterprise => "Enterprise",
            _ => "Free"
        };

        public static LicenseInfo CreateFree() => new()
        {
            Tier = LicenseTier.Free,
            IsValid = true,
            LicensedTo = "Trial User",
        };
    }
}
