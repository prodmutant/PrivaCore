using System;
using System.Collections.Generic;
using System.Windows;

namespace PROSCANNERCONT.Models
{
    /// <summary>
    /// Topology Device - Complete security profile for enterprise analysis
    /// Designed for ML integration and IDS/Honeypot placement planning
    /// </summary>
    public class TopologyDevice
    {
        // Identity
        public string IPAddress { get; set; }
        public string MACAddress { get; set; }
        public string Hostname { get; set; }
        public string Vendor { get; set; }

        // Classification
        public DeviceRole Role { get; set; } = DeviceRole.EndDevice;
        public string OperatingSystem { get; set; }
        public string DeviceType { get; set; } // Computer, Phone, IoT, etc.

        // Network Position
        public string ParentRouterIP { get; set; } // ACTUAL parent router (not gateway)
        public int HopDistance { get; set; } // Hops from this device to internet
        public Point VisualPosition { get; set; }

        // Security Profile
        public List<int> OpenPorts { get; set; } = new();
        public List<ServiceInfo> RunningServices { get; set; } = new();
        public bool IsOnline { get; set; }
        public DateTime LastSeen { get; set; }
        public TimeSpan ResponseTime { get; set; }

        // Risk Assessment (for future ML)
        public int SecurityScore { get; set; } = 100; // 0-100
        public List<string> SecurityFlags { get; set; } = new(); // Vulnerabilities, misconfigurations

        // Metadata
        public DateTime DiscoveredAt { get; set; }
        public string ScanId { get; set; }
    }

    public class ServiceInfo
    {
        public int Port { get; set; }
        public string Protocol { get; set; }
        public string ServiceName { get; set; }
        public string Version { get; set; }
        public string Banner { get; set; }
    }

    public enum DeviceRole
    {
        Unknown,
        CoreRouter,        // Main gateway to internet
        DistributionRouter, // Secondary router
        AccessPoint,       // WiFi AP / Range extender
        Switch,            // Network switch
        EndDevice,         // Computer, phone, etc.
        Server,            // Server infrastructure
        SecurityDevice,    // Firewall, IDS
        IoTDevice          // Smart devices, cameras
    }

    /// <summary>
    /// Network Router - Hub device that connects other devices
    /// </summary>
    public class NetworkRouter
    {
        public string IPAddress { get; set; }
        public string MACAddress { get; set; }
        public string Hostname { get; set; }
        public DeviceRole Role { get; set; }

        // Connected devices (children)
        public List<TopologyDevice> ConnectedDevices { get; set; } = new();

        // Router relationships
        public string ParentRouterIP { get; set; } // null if core router
        public List<string> ChildRouterIPs { get; set; } = new();

        // Router capabilities
        public bool IsDHCPServer { get; set; }
        public bool IsDNSServer { get; set; }
        public bool IsFirewall { get; set; }

        // Detection confidence
        public int DetectionConfidence { get; set; } // 0-100
        public List<string> DetectionMethods { get; set; } = new();

        // Visual
        public Point VisualPosition { get; set; }

        // Enterprise planning
        public bool IsIDSCandidate { get; set; } // Good spot for IDS?
        public bool IsHoneypotZone { get; set; } // Good spot for honeypot?
        public int TrafficLoad { get; set; } // Expected traffic through this router
    }

    /// <summary>
    /// Complete Network Topology - Enterprise view
    /// </summary>
    public class NetworkTopology
    {
        public string ScanId { get; set; }
        public DateTime ScanTime { get; set; }
        public string NetworkRange { get; set; }

        // Devices
        public List<NetworkRouter> Routers { get; set; } = new();
        public List<TopologyDevice> Devices { get; set; } = new();

        // Structure
        public NetworkRouter CoreRouter { get; set; }
        public Dictionary<string, List<string>> RouterConnections { get; set; } = new(); // Router IP -> Connected Router IPs

        // Statistics
        public int TotalDevices => Devices.Count;
        public int TotalRouters => Routers.Count;
        public int TotalOpenPorts => Devices.Sum(d => d.OpenPorts.Count);

        // Enterprise Analysis (for future ML)
        public List<SecurityRecommendation> Recommendations { get; set; } = new();
        public List<NetworkSegment> Segments { get; set; } = new();
    }

    public class SecurityRecommendation
    {
        public string Title { get; set; }
        public string Description { get; set; }
        public RecommendationType Type { get; set; }
        public string AffectedDeviceIP { get; set; }
    }

    public enum RecommendationType
    {
        IDSPlacement,
        HoneypotPlacement,
        Segmentation,
        Vulnerability,
        Configuration
    }

    public class NetworkSegment
    {
        public string SegmentId { get; set; }
        public string SubnetRange { get; set; }
        public List<string> DeviceIPs { get; set; } = new();
        public string RouterIP { get; set; }
    }
}