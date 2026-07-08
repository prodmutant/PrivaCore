using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;
using System.Text.Json;
using System.IO;
using System.Linq;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Services
{
    public class TopologyMacVendorService
    {
        private static readonly HttpClient _httpClient = new HttpClient();
        private static readonly Dictionary<string, string> _cache = new Dictionary<string, string>();
        private static readonly Dictionary<string, TopologyMacVendorInfo> _localDatabase = new Dictionary<string, TopologyMacVendorInfo>();
        private const string API_URL = "https://api.macvendors.com/";
        private const int RATE_LIMIT_MS = 1100; // API rate limit: 1 req/sec
        private static DateTime _lastApiCall = DateTime.MinValue;

        static TopologyMacVendorService()
        {
            InitializeLocalDatabase();
        }

        private static void InitializeLocalDatabase()
        {
            // Common MAC prefixes for popular vendors
            var vendors = new Dictionary<string, TopologyMacVendorInfo>
            {
                // Apple
                { "00:03:93", new TopologyMacVendorInfo("Apple", TopologyDeviceType.Mobile) },
                { "00:0A:95", new TopologyMacVendorInfo("Apple", TopologyDeviceType.Desktop) },
                { "00:1B:63", new TopologyMacVendorInfo("Apple", TopologyDeviceType.Desktop) },
                { "00:1C:B3", new TopologyMacVendorInfo("Apple", TopologyDeviceType.Desktop) },
                { "00:1E:C2", new TopologyMacVendorInfo("Apple", TopologyDeviceType.Desktop) },
                { "00:23:DF", new TopologyMacVendorInfo("Apple", TopologyDeviceType.Desktop) },
                { "00:25:00", new TopologyMacVendorInfo("Apple", TopologyDeviceType.Desktop) },
                { "00:26:BB", new TopologyMacVendorInfo("Apple", TopologyDeviceType.Desktop) },
                { "AC:DE:48", new TopologyMacVendorInfo("Apple", TopologyDeviceType.Mobile) },
                { "DC:2B:2A", new TopologyMacVendorInfo("Apple", TopologyDeviceType.Mobile) },
                { "F0:DB:E2", new TopologyMacVendorInfo("Apple", TopologyDeviceType.Mobile) },
                
                // Samsung
                { "00:12:47", new TopologyMacVendorInfo("Samsung Electronics", TopologyDeviceType.Mobile) },
                { "00:13:77", new TopologyMacVendorInfo("Samsung Electronics", TopologyDeviceType.Mobile) },
                { "00:15:B9", new TopologyMacVendorInfo("Samsung Electronics", TopologyDeviceType.Mobile) },
                { "00:16:32", new TopologyMacVendorInfo("Samsung Electronics", TopologyDeviceType.Mobile) },
                { "5C:0A:5B", new TopologyMacVendorInfo("Samsung Electronics", TopologyDeviceType.Mobile) },
                { "E8:50:8B", new TopologyMacVendorInfo("Samsung Electronics", TopologyDeviceType.SmartTV) },
                
                // Cisco (Routers/Switches/APs)
                { "00:01:42", new TopologyMacVendorInfo("Cisco Systems", TopologyDeviceType.Router) },
                { "00:01:43", new TopologyMacVendorInfo("Cisco Systems", TopologyDeviceType.Router) },
                { "00:01:96", new TopologyMacVendorInfo("Cisco Systems", TopologyDeviceType.Router) },
                { "00:01:C7", new TopologyMacVendorInfo("Cisco Systems", TopologyDeviceType.Switch) },
                { "00:02:FD", new TopologyMacVendorInfo("Cisco Systems", TopologyDeviceType.AccessPoint) },
                
                // TP-Link (Routers/APs)
                { "00:27:19", new TopologyMacVendorInfo("TP-Link Technologies", TopologyDeviceType.Router) },
                { "50:C7:BF", new TopologyMacVendorInfo("TP-Link Technologies", TopologyDeviceType.Router) },
                { "60:E3:27", new TopologyMacVendorInfo("TP-Link Technologies", TopologyDeviceType.AccessPoint) },
                { "C4:6E:1F", new TopologyMacVendorInfo("TP-Link Technologies", TopologyDeviceType.AccessPoint) },
                
                // Ubiquiti (APs)
                { "00:15:6D", new TopologyMacVendorInfo("Ubiquiti Networks", TopologyDeviceType.AccessPoint) },
                { "00:27:22", new TopologyMacVendorInfo("Ubiquiti Networks", TopologyDeviceType.AccessPoint) },
                { "24:A4:3C", new TopologyMacVendorInfo("Ubiquiti Networks", TopologyDeviceType.AccessPoint) },
                { "F0:9F:C2", new TopologyMacVendorInfo("Ubiquiti Networks", TopologyDeviceType.AccessPoint) },
                
                // Netgear (Routers/APs)
                { "00:09:5B", new TopologyMacVendorInfo("Netgear", TopologyDeviceType.Router) },
                { "00:0F:B5", new TopologyMacVendorInfo("Netgear", TopologyDeviceType.Router) },
                { "00:14:6C", new TopologyMacVendorInfo("Netgear", TopologyDeviceType.Router) },
                { "A0:40:A0", new TopologyMacVendorInfo("Netgear", TopologyDeviceType.AccessPoint) },
                
                // ASUS (Routers)
                { "00:15:F2", new TopologyMacVendorInfo("ASUS", TopologyDeviceType.Router) },
                { "00:1E:8C", new TopologyMacVendorInfo("ASUS", TopologyDeviceType.Router) },
                { "10:BF:48", new TopologyMacVendorInfo("ASUS", TopologyDeviceType.Router) },
                
                // D-Link (Routers/Switches)
                { "00:05:5D", new TopologyMacVendorInfo("D-Link Corporation", TopologyDeviceType.Router) },
                { "00:0D:88", new TopologyMacVendorInfo("D-Link Corporation", TopologyDeviceType.Router) },
                { "00:11:95", new TopologyMacVendorInfo("D-Link Corporation", TopologyDeviceType.Switch) },
                
                // Linksys (Routers)
                { "00:06:25", new TopologyMacVendorInfo("Linksys", TopologyDeviceType.Router) },
                { "00:13:10", new TopologyMacVendorInfo("Linksys", TopologyDeviceType.Router) },
                { "00:14:BF", new TopologyMacVendorInfo("Linksys", TopologyDeviceType.Router) },
                
                // Google
                { "00:1A:11", new TopologyMacVendorInfo("Google", TopologyDeviceType.Mobile) },
                { "3C:5A:B4", new TopologyMacVendorInfo("Google", TopologyDeviceType.IoT) },
                { "F4:F5:D8", new TopologyMacVendorInfo("Google", TopologyDeviceType.Mobile) },
                
                // Huawei
                { "00:1E:10", new TopologyMacVendorInfo("Huawei Technologies", TopologyDeviceType.Mobile) },
                { "00:25:9E", new TopologyMacVendorInfo("Huawei Technologies", TopologyDeviceType.Mobile) },
                { "A4:51:6F", new TopologyMacVendorInfo("Huawei Technologies", TopologyDeviceType.Mobile) },
                
                // Dell (Desktops/Laptops)
                { "00:06:5B", new TopologyMacVendorInfo("Dell", TopologyDeviceType.Desktop) },
                { "00:0B:DB", new TopologyMacVendorInfo("Dell", TopologyDeviceType.Desktop) },
                { "00:12:3F", new TopologyMacVendorInfo("Dell", TopologyDeviceType.Laptop) },
                { "00:14:22", new TopologyMacVendorInfo("Dell", TopologyDeviceType.Laptop) },
                
                // HP (Desktops/Laptops/Printers)
                { "00:01:E6", new TopologyMacVendorInfo("Hewlett Packard", TopologyDeviceType.Desktop) },
                { "00:08:83", new TopologyMacVendorInfo("Hewlett Packard", TopologyDeviceType.Printer) },
                { "00:1F:29", new TopologyMacVendorInfo("Hewlett Packard", TopologyDeviceType.Laptop) },
                { "00:23:7D", new TopologyMacVendorInfo("Hewlett Packard", TopologyDeviceType.Laptop) },
                
                // Lenovo
                { "00:1C:25", new TopologyMacVendorInfo("Lenovo", TopologyDeviceType.Laptop) },
                { "00:21:CC", new TopologyMacVendorInfo("Lenovo", TopologyDeviceType.Laptop) },
                { "50:7B:9D", new TopologyMacVendorInfo("Lenovo", TopologyDeviceType.Laptop) },
                
                // Microsoft
                { "00:03:FF", new TopologyMacVendorInfo("Microsoft Corporation", TopologyDeviceType.Desktop) },
                { "00:50:F2", new TopologyMacVendorInfo("Microsoft Corporation", TopologyDeviceType.Desktop) },
                { "E0:D5:5E", new TopologyMacVendorInfo("Microsoft Corporation", TopologyDeviceType.Desktop) },
                
                // Raspberry Pi
                { "B8:27:EB", new TopologyMacVendorInfo("Raspberry Pi Foundation", TopologyDeviceType.IoT) },
                { "DC:A6:32", new TopologyMacVendorInfo("Raspberry Pi Foundation", TopologyDeviceType.IoT) },
                { "E4:5F:01", new TopologyMacVendorInfo("Raspberry Pi Foundation", TopologyDeviceType.IoT) },
                
                // Amazon (Echo/IoT)
                { "00:71:47", new TopologyMacVendorInfo("Amazon Technologies", TopologyDeviceType.IoT) },
                { "74:C2:46", new TopologyMacVendorInfo("Amazon Technologies", TopologyDeviceType.IoT) },
                
                // Sony
                { "00:13:15", new TopologyMacVendorInfo("Sony", TopologyDeviceType.SmartTV) },
                { "00:1D:BA", new TopologyMacVendorInfo("Sony Mobile", TopologyDeviceType.Mobile) },
                { "AC:9B:0A", new TopologyMacVendorInfo("Sony", TopologyDeviceType.SmartTV) },
                
                // LG Electronics
                { "00:1C:62", new TopologyMacVendorInfo("LG Electronics", TopologyDeviceType.SmartTV) },
                { "00:1E:75", new TopologyMacVendorInfo("LG Electronics", TopologyDeviceType.Mobile) },
                { "64:BC:0C", new TopologyMacVendorInfo("LG Electronics", TopologyDeviceType.SmartTV) },
                
                // Xiaomi
                { "34:CE:00", new TopologyMacVendorInfo("Xiaomi Communications", TopologyDeviceType.Mobile) },
                { "64:09:80", new TopologyMacVendorInfo("Xiaomi Communications", TopologyDeviceType.Mobile) },
                { "F0:B4:29", new TopologyMacVendorInfo("Xiaomi Communications", TopologyDeviceType.IoT) }
            };

            foreach (var kvp in vendors)
            {
                _localDatabase[kvp.Key.Replace(":", "").ToUpper()] = kvp.Value;
            }
        }

        public static async Task<TopologyMacVendorInfo> LookupVendorAsync(string macAddress)
        {
            if (string.IsNullOrWhiteSpace(macAddress))
                return new TopologyMacVendorInfo("Unknown", TopologyDeviceType.Unknown);

            // Normalize MAC address
            string normalizedMac = macAddress.Replace(":", "").Replace("-", "").ToUpper();

            if (normalizedMac.Length < 6)
                return new TopologyMacVendorInfo("Unknown", TopologyDeviceType.Unknown);

            // Check cache first
            if (_cache.TryGetValue(normalizedMac, out string cachedVendor))
            {
                return new TopologyMacVendorInfo(cachedVendor, GuessDeviceTypeFromVendor(cachedVendor));
            }

            // Check local database
            string prefix6 = normalizedMac.Substring(0, 6);
            string prefix8 = normalizedMac.Length >= 8 ? normalizedMac.Substring(0, 8) : "";

            // Try 8-char prefix first (more specific)
            if (!string.IsNullOrEmpty(prefix8) && _localDatabase.TryGetValue(FormatMacPrefix(prefix8), out var info8))
            {
                _cache[normalizedMac] = info8.Vendor;
                return info8;
            }

            // Try 6-char prefix
            if (_localDatabase.TryGetValue(FormatMacPrefix(prefix6), out var info6))
            {
                _cache[normalizedMac] = info6.Vendor;
                return info6;
            }

            // Try API lookup with rate limiting
            try
            {
                var timeSinceLastCall = DateTime.Now - _lastApiCall;
                if (timeSinceLastCall.TotalMilliseconds < RATE_LIMIT_MS)
                {
                    await Task.Delay(RATE_LIMIT_MS - (int)timeSinceLastCall.TotalMilliseconds);
                }

                _lastApiCall = DateTime.Now;

                var response = await _httpClient.GetAsync($"{API_URL}{macAddress}");

                if (response.IsSuccessStatusCode)
                {
                    var vendor = await response.Content.ReadAsStringAsync();
                    vendor = vendor.Trim();

                    if (!string.IsNullOrWhiteSpace(vendor) && !vendor.Contains("error", StringComparison.OrdinalIgnoreCase))
                    {
                        _cache[normalizedMac] = vendor;
                        return new TopologyMacVendorInfo(vendor, GuessDeviceTypeFromVendor(vendor));
                    }
                }
            }
            catch
            {
                // API call failed, continue with fallback
            }

            // Fallback
            return new TopologyMacVendorInfo("Unknown", TopologyDeviceType.Unknown);
        }

        private static string FormatMacPrefix(string prefix)
        {
            if (prefix.Length >= 6)
            {
                return $"{prefix.Substring(0, 2)}:{prefix.Substring(2, 2)}:{prefix.Substring(4, 2)}";
            }
            return prefix;
        }

        private static TopologyDeviceType GuessDeviceTypeFromVendor(string vendor)
        {
            if (string.IsNullOrWhiteSpace(vendor))
                return TopologyDeviceType.Unknown;

            vendor = vendor.ToLower();

            // Mobile devices
            if (vendor.Contains("apple") || vendor.Contains("samsung") || vendor.Contains("huawei") ||
                vendor.Contains("xiaomi") || vendor.Contains("oneplus") || vendor.Contains("google") ||
                vendor.Contains("motorola") || vendor.Contains("sony mobile") || vendor.Contains("lg electronics"))
            {
                if (vendor.Contains("mobile") || vendor.Contains("phone"))
                    return TopologyDeviceType.Mobile;
            }

            // Routers
            if (vendor.Contains("asus") || vendor.Contains("netgear") || vendor.Contains("linksys") ||
                vendor.Contains("d-link") && vendor.Contains("router"))
            {
                return TopologyDeviceType.Router;
            }

            // Access Points
            if (vendor.Contains("ubiquiti") || vendor.Contains("unifi") || vendor.Contains("aruba") ||
                vendor.Contains("ruckus") || vendor.Contains("meraki"))
            {
                return TopologyDeviceType.AccessPoint;
            }

            // Network equipment
            if (vendor.Contains("cisco"))
            {
                return TopologyDeviceType.Switch; // Generic network device
            }

            // Smart TVs
            if (vendor.Contains("sony") || vendor.Contains("lg") || vendor.Contains("samsung"))
            {
                if (!vendor.Contains("mobile"))
                    return TopologyDeviceType.SmartTV;
            }

            // IoT devices
            if (vendor.Contains("raspberry") || vendor.Contains("amazon") || vendor.Contains("google home") ||
                vendor.Contains("nest"))
            {
                return TopologyDeviceType.IoT;
            }

            // Printers
            if (vendor.Contains("hp") || vendor.Contains("hewlett") || vendor.Contains("canon") ||
                vendor.Contains("epson") || vendor.Contains("brother"))
            {
                return TopologyDeviceType.Printer;
            }

            // Desktops/Laptops
            if (vendor.Contains("dell") || vendor.Contains("lenovo") || vendor.Contains("asus") ||
                vendor.Contains("microsoft") || vendor.Contains("acer"))
            {
                return TopologyDeviceType.Desktop;
            }

            return TopologyDeviceType.Unknown;
        }

        public static void ClearCache()
        {
            _cache.Clear();
        }
    }

    public class TopologyMacVendorInfo
    {
        public string Vendor { get; set; }
        public TopologyDeviceType SuggestedType { get; set; }

        public TopologyMacVendorInfo(string vendor, TopologyDeviceType type)
        {
            Vendor = vendor;
            SuggestedType = type;
        }
    }
}