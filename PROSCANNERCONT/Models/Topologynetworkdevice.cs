using System;
using System.Collections.Generic;
using System.Net;

namespace PROSCANNERCONT.Models
{
    public enum TopologyDeviceType
    {
        Unknown,
        Router,
        AccessPoint,
        Switch,
        Desktop,
        Laptop,
        Mobile,
        Server,
        Printer,
        IoT,
        Camera,
        SmartTV
    }

    public enum TopologyConnectionType
    {
        Unknown,
        Wired,
        Wireless
    }

    public class TopologyNetworkDevice
    {
        public string Id { get; set; }
        public string IPAddress { get; set; }
        public string MACAddress { get; set; }
        public string Hostname { get; set; }
        public string Vendor { get; set; }
        public TopologyDeviceType DeviceType { get; set; }
        public TopologyConnectionType ConnectionType { get; set; }
        public string ParentDeviceId { get; set; }
        public List<string> ChildDeviceIds { get; set; }
        public List<int> OpenPorts { get; set; }
        public Dictionary<int, string> PortServices { get; set; }
        public int NetworkLayer { get; set; } // 0 = Gateway, 1 = First hop, 2 = Second hop, etc.
        public bool IsGateway { get; set; }
        public bool IsOnline { get; set; }
        public DateTime LastSeen { get; set; }
        public int TTL { get; set; }
        public string SubnetMask { get; set; }
        public double ResponseTime { get; set; } // ms

        // Visual properties
        public double X { get; set; }
        public double Y { get; set; }

        // Additional metadata
        public string OSType { get; set; }
        public string Model { get; set; }
        public Dictionary<string, string> AdditionalInfo { get; set; }

        public TopologyNetworkDevice()
        {
            Id = Guid.NewGuid().ToString();
            ChildDeviceIds = new List<string>();
            OpenPorts = new List<int>();
            PortServices = new Dictionary<int, string>();
            AdditionalInfo = new Dictionary<string, string>();
            IsOnline = true;
            LastSeen = DateTime.Now;
            NetworkLayer = -1;
        }

        public string GetDeviceIcon()
        {
            return DeviceType switch
            {
                TopologyDeviceType.Router => "🌐",
                TopologyDeviceType.AccessPoint => "📡",
                TopologyDeviceType.Switch => "🔀",
                TopologyDeviceType.Desktop => "🖥️",
                TopologyDeviceType.Laptop => "💻",
                TopologyDeviceType.Mobile => "📱",
                TopologyDeviceType.Server => "🖧",
                TopologyDeviceType.Printer => "🖨️",
                TopologyDeviceType.IoT => "💡",
                TopologyDeviceType.Camera => "📷",
                TopologyDeviceType.SmartTV => "📺",
                _ => "❓"
            };
        }

        public string GetDeviceColor()
        {
            return DeviceType switch
            {
                TopologyDeviceType.Router => "#FF00BCD4", // Cyan
                TopologyDeviceType.AccessPoint => "#FFFF9800", // Orange
                TopologyDeviceType.Switch => "#FFFF5722", // Deep Orange
                TopologyDeviceType.Desktop => "#FF4CAF50", // Green
                TopologyDeviceType.Laptop => "#FF4CAF50", // Green
                TopologyDeviceType.Mobile => "#FF9C27B0", // Purple
                TopologyDeviceType.Server => "#FF2196F3", // Blue
                TopologyDeviceType.Printer => "#FF795548", // Brown
                TopologyDeviceType.IoT => "#FFCDDC39", // Lime
                TopologyDeviceType.Camera => "#FFFF4081", // Pink
                TopologyDeviceType.SmartTV => "#FF3F51B5", // Indigo
                _ => "#FF757575" // Grey
            };
        }

        public string GetDisplayName()
        {
            if (!string.IsNullOrWhiteSpace(Hostname) && Hostname != "Unknown")
                return Hostname;

            if (!string.IsNullOrWhiteSpace(Vendor) && Vendor != "Unknown")
                return $"{Vendor} Device";

            return IPAddress ?? "Unknown Device";
        }

        public bool IsMobileDevice()
        {
            if (DeviceType == TopologyDeviceType.Mobile)
                return true;

            var mobileVendors = new[] { "Apple", "Samsung", "Huawei", "Xiaomi", "OnePlus",
                                       "Google", "LG Electronics", "Motorola", "Sony Mobile" };

            if (!string.IsNullOrEmpty(Vendor))
            {
                foreach (var vendor in mobileVendors)
                {
                    if (Vendor.Contains(vendor, StringComparison.OrdinalIgnoreCase))
                        return true;
                }
            }

            if (!string.IsNullOrEmpty(Hostname))
            {
                var hostname = Hostname.ToLower();
                if (hostname.Contains("iphone") || hostname.Contains("ipad") ||
                    hostname.Contains("android") || hostname.Contains("mobile"))
                    return true;
            }

            return false;
        }

        public bool IsAccessPoint()
        {
            if (DeviceType == TopologyDeviceType.AccessPoint)
                return true;

            var apVendors = new[] { "Ubiquiti", "UniFi", "TP-Link", "Cisco", "Aruba",
                                   "Ruckus", "Meraki", "Netgear", "D-Link" };

            if (!string.IsNullOrEmpty(Vendor))
            {
                foreach (var vendor in apVendors)
                {
                    if (Vendor.Contains(vendor, StringComparison.OrdinalIgnoreCase))
                    {
                        // Check for common AP characteristics
                        if (OpenPorts.Contains(443) || OpenPorts.Contains(80))
                            return true;
                    }
                }
            }

            return false;
        }

        public bool IsRouter()
        {
            if (DeviceType == TopologyDeviceType.Router || IsGateway)
                return true;

            // Check if it's acting as a router
            if (NetworkLayer == 0 || ChildDeviceIds.Count > 3)
                return true;

            var routerVendors = new[] { "ASUS", "Netgear", "TP-Link", "Linksys",
                                       "D-Link", "Cisco", "Ubiquiti" };

            if (!string.IsNullOrEmpty(Vendor))
            {
                foreach (var vendor in routerVendors)
                {
                    if (Vendor.Contains(vendor, StringComparison.OrdinalIgnoreCase))
                        return true;
                }
            }

            return false;
        }
    }

    public class TopologyDeviceConnection
    {
        public string Id { get; set; }
        public string SourceDeviceId { get; set; }
        public string TargetDeviceId { get; set; }
        public TopologyConnectionType ConnectionType { get; set; }
        public int Strength { get; set; } // 0-100
        public double Latency { get; set; } // ms
        public string Label { get; set; }

        public TopologyDeviceConnection()
        {
            Id = Guid.NewGuid().ToString();
            Strength = 100;
            Latency = 0;
        }
    }

    public class TopologyPortInfo
    {
        public int Port { get; set; }
        public string Service { get; set; }
        public bool IsOpen { get; set; }

        public TopologyPortInfo(int port, string service)
        {
            Port = port;
            Service = service;
            IsOpen = true;
        }
    }
}