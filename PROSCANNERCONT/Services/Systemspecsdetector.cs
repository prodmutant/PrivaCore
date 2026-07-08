using System;
using System.Diagnostics;
using System.Management;

namespace PROSCANNERCONT.Services
{
    /// <summary>
    /// Detects system hardware specifications for VM resource allocation
    /// </summary>
    public class SystemSpecsDetector
    {
        /// <summary>
        /// Get total system RAM in MB
        /// </summary>
        public static int GetTotalRAM()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT TotalVisibleMemorySize FROM Win32_OperatingSystem");
                foreach (ManagementObject obj in searcher.Get())
                {
                    // TotalVisibleMemorySize is in KB, convert to MB
                    long totalKB = Convert.ToInt64(obj["TotalVisibleMemorySize"]);
                    return (int)(totalKB / 1024);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error detecting RAM: {ex.Message}");
            }

            // Default fallback
            return 8192; // 8GB default
        }

        /// <summary>
        /// Get number of CPU cores
        /// </summary>
        public static int GetCPUCores()
        {
            try
            {
                return Environment.ProcessorCount;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error detecting CPU cores: {ex.Message}");
                return 4; // Default fallback
            }
        }

        /// <summary>
        /// Get available disk space on C: drive in GB
        /// </summary>
        public static long GetAvailableDiskSpace()
        {
            try
            {
                var driveInfo = new System.IO.DriveInfo("C");
                return driveInfo.AvailableFreeSpace / (1024 * 1024 * 1024); // Convert to GB
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error detecting disk space: {ex.Message}");
                return 100; // Default fallback
            }
        }

        /// <summary>
        /// Get recommended maximum RAM for VM (75% of total)
        /// </summary>
        public static int GetRecommendedMaxRAM()
        {
            int totalRAM = GetTotalRAM();
            return (int)(totalRAM * 0.75); // Use 75% of total RAM
        }

        /// <summary>
        /// Get recommended maximum CPU cores for VM (75% of total)
        /// </summary>
        public static int GetRecommendedMaxCores()
        {
            int totalCores = GetCPUCores();
            return Math.Max(1, (int)(totalCores * 0.75)); // At least 1 core
        }

        /// <summary>
        /// Get recommended maximum storage for VM (50% of available space, capped at 500GB)
        /// </summary>
        public static int GetRecommendedMaxStorage()
        {
            long availableGB = GetAvailableDiskSpace();
            long recommended = availableGB / 2; // 50% of available
            return (int)Math.Min(recommended, 500); // Cap at 500GB
        }

        /// <summary>
        /// Get system specs summary
        /// </summary>
        public static string GetSystemSummary()
        {
            return $"System: {GetTotalRAM()} MB RAM, {GetCPUCores()} CPU Cores, {GetAvailableDiskSpace()} GB Available";
        }
    }
}