using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Services
{
    public class TopologyNetworkDiscoveryService
    {
        private IPAddress _gatewayIP;
        private string _localSubnet;
        private AdvancedStealthReconService _stealthRecon;
        private Dictionary<string, AdvancedStealthReconService.DeviceProbeResult> _probeResults;

        public event Action<string> OnProgressUpdate;

        public TopologyNetworkDiscoveryService()
        {
            _stealthRecon = new AdvancedStealthReconService();
            _probeResults = new Dictionary<string, AdvancedStealthReconService.DeviceProbeResult>();

            // Forward stealth recon progress updates
            _stealthRecon.OnProgressUpdate += (msg) => OnProgressUpdate?.Invoke(msg);
        }

        public async Task<List<TopologyNetworkDevice>> DiscoverNetworkAsync()
        {
            var devices = new List<TopologyNetworkDevice>();

            try
            {
                OnProgressUpdate?.Invoke("Detecting gateway...");
                _gatewayIP = GetDefaultGateway();
                _localSubnet = GetLocalSubnet();

                if (_gatewayIP == null)
                {
                    OnProgressUpdate?.Invoke("No gateway found. Using local scan only.");
                }

                OnProgressUpdate?.Invoke("Scanning ARP table...");
                var arpDevices = await GetArpTableDevicesAsync();

                OnProgressUpdate?.Invoke($"Found {arpDevices.Count} devices in ARP table");

                foreach (var device in arpDevices)
                {
                    devices.Add(device);
                }

                // Perform active scanning on local subnet
                OnProgressUpdate?.Invoke("Performing active network scan on primary subnet...");
                var activeDevices = await PerformActiveScanAsync();

                // Merge with ARP devices (avoid duplicates)
                foreach (var activeDevice in activeDevices)
                {
                    if (!devices.Any(d => d.IPAddress == activeDevice.IPAddress))
                    {
                        devices.Add(activeDevice);
                    }
                }

                OnProgressUpdate?.Invoke($"Primary subnet scan complete: {devices.Count} devices");

                // CRITICAL: Filter out broadcast, multicast, and invalid addresses
                devices = FilterValidDevices(devices);

                OnProgressUpdate?.Invoke($"After filtering: {devices.Count} valid devices");

                OnProgressUpdate?.Invoke("Enriching device information...");
                OnProgressUpdate?.Invoke("Detecting routers and access points...");

                // Enrich device information
                var tasks = devices.Select(async device =>
                {
                    await EnrichDeviceInfoAsync(device);
                    return device;
                });

                await Task.WhenAll(tasks);

                // NEW: Detect additional subnets through discovered routers/APs
                OnProgressUpdate?.Invoke("🔍 Discovering additional subnets through APs/routers...");
                var additionalDevices = await DiscoverAPSubnetsAsync(devices);

                if (additionalDevices.Any())
                {
                    OnProgressUpdate?.Invoke($"Found {additionalDevices.Count} additional devices on AP subnets!");

                    // Enrich additional devices
                    var additionalTasks = additionalDevices.Select(async device =>
                    {
                        await EnrichDeviceInfoAsync(device);
                        return device;
                    });
                    await Task.WhenAll(additionalTasks);

                    devices.AddRange(additionalDevices);
                }

                OnProgressUpdate?.Invoke("Building network topology...");

                // NEW: Perform advanced stealth probing for accurate parent detection
                OnProgressUpdate?.Invoke("🔬 Performing advanced stealth reconnaissance...");
                await PerformAdvancedProbing(devices);

                // Build topology hierarchy using advanced probe data
                BuildTopologyHierarchy(devices);

                OnProgressUpdate?.Invoke($"Discovery complete! Found {devices.Count} devices");
            }
            catch (Exception ex)
            {
                OnProgressUpdate?.Invoke($"Error during discovery: {ex.Message}");
            }

            return devices;
        }

        private async Task PerformAdvancedProbing(List<TopologyNetworkDevice> devices)
        {
            var tasks = new List<Task>();

            // Probe devices in random order for stealth
            var randomOrder = devices.OrderBy(d => Guid.NewGuid()).ToList();

            foreach (var device in randomOrder)
            {
                // Limit concurrent probes for stealth
                while (tasks.Count(t => !t.IsCompleted) >= 3)
                {
                    await Task.Delay(100);
                }

                var task = ProbeDeviceAsync(device);
                tasks.Add(task);
            }

            await Task.WhenAll(tasks);

            Debug.WriteLine($"✅ Advanced probing complete: {_probeResults.Count} devices probed");
        }

        private async Task ProbeDeviceAsync(TopologyNetworkDevice device)
        {
            try
            {
                var probeResult = await _stealthRecon.StealthProbeDeviceAsync(device.IPAddress);

                if (probeResult != null && probeResult.IsAlive)
                {
                    _probeResults[device.IPAddress] = probeResult;

                    // Update device with probe data
                    if (probeResult.TTL > 0)
                        device.TTL = probeResult.TTL;

                    device.ResponseTime = probeResult.ResponseTime;  // Already double

                    Debug.WriteLine($"✅ Probed {device.IPAddress}: TTL={probeResult.TTL}, " +
                                  $"Hops={probeResult.HopCount}, Time={probeResult.ResponseTime}ms, " +
                                  $"Method={probeResult.DetectionMethod}");
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"⚠️ Probe failed for {device.IPAddress}: {ex.Message}");
            }
        }

        /// <summary>
        /// Discover devices on subnets managed by APs/routers
        /// This is critical for finding devices connected through APs!
        /// </summary>
        private async Task<List<TopologyNetworkDevice>> DiscoverAPSubnetsAsync(List<TopologyNetworkDevice> knownDevices)
        {
            var additionalDevices = new List<TopologyNetworkDevice>();

            // Identify APs and routers
            var infrastructure = knownDevices.Where(d =>
                d.DeviceType == TopologyDeviceType.Router ||
                d.DeviceType == TopologyDeviceType.AccessPoint ||
                d.IsRouter() ||
                d.IsAccessPoint())
                .ToList();

            if (!infrastructure.Any())
            {
                Debug.WriteLine("No APs/routers found for subnet discovery");
                return additionalDevices;
            }

            Debug.WriteLine($"🔍 Performing deep scan for devices behind {infrastructure.Count} APs/routers...");

            // Build list of subnets to scan based on ACTUAL EVIDENCE
            var subnetsToScan = new HashSet<string>();

            // Strategy 1: Use infrastructure device IPs as hints
            foreach (var device in infrastructure)
            {
                if (!string.IsNullOrEmpty(device.IPAddress))
                {
                    var parts = device.IPAddress.Split('.');
                    if (parts.Length == 4)
                    {
                        var subnet = $"{parts[0]}.{parts[1]}.{parts[2]}";
                        subnetsToScan.Add(subnet);
                        Debug.WriteLine($"  📡 AP/Router {device.IPAddress} → Will scan {subnet}.0/24");
                    }
                }
            }

            // Strategy 2: Add our local subnet for deep scan (in case we missed devices)
            if (!string.IsNullOrEmpty(_localSubnet))
            {
                var parts = _localSubnet.Split('.');
                if (parts.Length >= 3)
                {
                    var subnet = $"{parts[0]}.{parts[1]}.{parts[2]}";
                    if (subnetsToScan.Add(subnet))
                    {
                        Debug.WriteLine($"  🔍 Will do deep scan of primary subnet: {subnet}.0/24");
                    }
                }
            }

            Debug.WriteLine($"📡 Will perform deep scan on {subnetsToScan.Count} subnet(s) (not random guessing!)");

            // Scan each subnet
            foreach (var subnet in subnetsToScan)
            {
                OnProgressUpdate?.Invoke($"Deep scanning {subnet}.0/24 for devices behind APs...");

                var subnetDevices = await DeepScanSubnetAsync(subnet, knownDevices);

                if (subnetDevices.Any())
                {
                    Debug.WriteLine($"✅ Found {subnetDevices.Count} additional devices on {subnet}.0/24");
                    additionalDevices.AddRange(subnetDevices);
                }
            }

            Debug.WriteLine($"✅ Deep scan complete: {additionalDevices.Count} new devices found");
            return additionalDevices;
        }

        /// <summary>
        /// Deep scan a specific subnet with multiple attempts and longer timeouts
        /// This finds devices that might have been missed in the initial quick scan
        /// </summary>
        private async Task<List<TopologyNetworkDevice>> DeepScanSubnetAsync(string subnet, List<TopologyNetworkDevice> knownDevices)
        {
            var devices = new List<TopologyNetworkDevice>();
            var knownIPs = new HashSet<string>(knownDevices.Select(d => d.IPAddress));

            Debug.WriteLine($"🔬 Deep scanning {subnet}.0/24...");

            // Build list of IPs to scan (only ones we don't already know about)
            var ipsToScan = new List<string>();
            for (int i = 1; i <= 254; i++)
            {
                var ip = $"{subnet}.{i}";
                if (!knownIPs.Contains(ip))
                {
                    ipsToScan.Add(ip);
                }
            }

            if (!ipsToScan.Any())
            {
                Debug.WriteLine($"  All IPs on {subnet}.0/24 already known, skipping");
                return devices;
            }

            Debug.WriteLine($"  Scanning {ipsToScan.Count} unknown IPs on {subnet}.0/24");

            // Scan with higher concurrency for speed
            var tasks = new List<Task<TopologyNetworkDevice>>();

            foreach (var ip in ipsToScan)
            {
                // Limit concurrent scans to avoid overwhelming network
                while (tasks.Count(t => !t.IsCompleted) >= 30)
                {
                    await Task.Delay(50);
                }

                tasks.Add(DeepPingDeviceAsync(ip));
            }

            // Wait for all scans
            var results = await Task.WhenAll(tasks);

            // Filter out nulls (unreachable devices)
            devices = results.Where(d => d != null).ToList();

            Debug.WriteLine($"  ✅ Deep scan of {subnet}.0/24 found {devices.Count} devices");
            return devices;
        }

        /// <summary>
        /// Deep ping with longer timeout and multiple attempts
        /// More thorough than quick ping, better for finding hidden devices
        /// </summary>
        private async Task<TopologyNetworkDevice> DeepPingDeviceAsync(string ip)
        {
            try
            {
                using (var ping = new Ping())
                {
                    // Try twice with longer timeout for better detection
                    for (int attempt = 1; attempt <= 2; attempt++)
                    {
                        var reply = await ping.SendPingAsync(ip, 1000);  // 1 second timeout

                        if (reply.Status == IPStatus.Success)
                        {
                            var device = new TopologyNetworkDevice
                            {
                                IPAddress = ip,
                                IsOnline = true,
                                TTL = reply.Options?.Ttl ?? 0,
                                ResponseTime = reply.RoundtripTime,
                                LastSeen = DateTime.Now
                            };

                            Debug.WriteLine($"    ✅ Deep scan found: {ip} (TTL: {device.TTL}, Time: {reply.RoundtripTime}ms)");
                            return device;
                        }

                        // If first attempt failed, wait a bit before retry
                        if (attempt == 1)
                        {
                            await Task.Delay(100);
                        }
                    }
                }
            }
            catch
            {
                // Device not reachable
            }

            return null;
        }

        private List<TopologyNetworkDevice> FilterValidDevices(List<TopologyNetworkDevice> devices)
        {
            var filtered = new List<TopologyNetworkDevice>();
            var seenIPs = new HashSet<string>();

            foreach (var device in devices)
            {
                // Skip if already seen (remove duplicates)
                if (seenIPs.Contains(device.IPAddress))
                {
                    Debug.WriteLine($"Skipping duplicate IP: {device.IPAddress}");
                    continue;
                }

                // Filter out broadcast addresses
                if (IsBroadcastAddress(device.IPAddress))
                {
                    Debug.WriteLine($"Skipping broadcast address: {device.IPAddress}");
                    continue;
                }

                // Filter out multicast addresses (224.0.0.0 - 239.255.255.255)
                if (IsMulticastAddress(device.IPAddress))
                {
                    Debug.WriteLine($"Skipping multicast address: {device.IPAddress}");
                    continue;
                }

                // Filter out broadcast MAC addresses
                if (IsBroadcastMAC(device.MACAddress))
                {
                    Debug.WriteLine($"Skipping broadcast MAC: {device.MACAddress} ({device.IPAddress})");
                    continue;
                }

                // Filter out VirtualBox/VMware virtual adapters (not part of main network)
                if (IsVirtualAdapter(device.IPAddress))
                {
                    Debug.WriteLine($"Skipping virtual adapter: {device.IPAddress}");
                    continue;
                }

                // Valid device - add it
                seenIPs.Add(device.IPAddress);
                filtered.Add(device);
            }

            return filtered;
        }

        private bool IsBroadcastAddress(string ipAddress)
        {
            if (string.IsNullOrEmpty(ipAddress))
                return false;

            // Check for common broadcast addresses
            if (ipAddress == "255.255.255.255")
                return true;

            // Check for subnet broadcast (ends with .255)
            if (ipAddress.EndsWith(".255"))
                return true;

            return false;
        }

        private bool IsMulticastAddress(string ipAddress)
        {
            if (string.IsNullOrEmpty(ipAddress))
                return false;

            try
            {
                var parts = ipAddress.Split('.');
                if (parts.Length != 4)
                    return false;

                int firstOctet = int.Parse(parts[0]);

                // Multicast range: 224.0.0.0 - 239.255.255.255
                return firstOctet >= 224 && firstOctet <= 239;
            }
            catch
            {
                return false;
            }
        }

        private bool IsBroadcastMAC(string macAddress)
        {
            if (string.IsNullOrEmpty(macAddress))
                return false;

            // Normalize MAC address
            string normalized = macAddress.Replace(":", "").Replace("-", "").ToUpper();

            // Broadcast MAC
            if (normalized == "FFFFFFFFFFFF")
                return true;

            // Multicast MACs start with 01:00:5E (for IPv4 multicast)
            if (macAddress.StartsWith("01:00:5E", StringComparison.OrdinalIgnoreCase) ||
                macAddress.StartsWith("01-00-5E", StringComparison.OrdinalIgnoreCase))
                return true;

            return false;
        }

        private bool IsVirtualAdapter(string ipAddress)
        {
            if (string.IsNullOrEmpty(ipAddress))
                return false;

            // VirtualBox Host-Only adapter: 192.168.56.x
            if (ipAddress.StartsWith("192.168.56."))
                return true;

            // VMware virtual adapters: 192.168.xx.x where xx is high
            if (ipAddress.StartsWith("192.168."))
            {
                var parts = ipAddress.Split('.');
                if (parts.Length == 4)
                {
                    int thirdOctet = int.Parse(parts[2]);
                    // VMware often uses 192.168.xxx.x where xxx > 100
                    if (thirdOctet >= 56 && thirdOctet <= 200 && parts[3] == "1")
                        return true;
                }
            }

            return false;
        }

        private async Task<List<TopologyNetworkDevice>> GetArpTableDevicesAsync()
        {
            var devices = new List<TopologyNetworkDevice>();

            try
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    devices = await GetArpTableWindowsAsync();
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                {
                    devices = await GetArpTableLinuxAsync();
                }
            }
            catch (Exception ex)
            {
                OnProgressUpdate?.Invoke($"ARP table scan error: {ex.Message}");
            }

            return devices;
        }

        private async Task<List<TopologyNetworkDevice>> GetArpTableWindowsAsync()
        {
            var devices = new List<TopologyNetworkDevice>();

            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "arp",
                        Arguments = "-a",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                string output = await process.StandardOutput.ReadToEndAsync();
                await process.WaitForExitAsync();

                // Parse ARP output
                var lines = output.Split('\n');
                var ipPattern = @"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2})";

                foreach (var line in lines)
                {
                    var match = Regex.Match(line, ipPattern);
                    if (match.Success)
                    {
                        var ip = match.Groups[1].Value;
                        var mac = match.Groups[2].Value.Replace("-", ":").ToUpper();

                        var device = new TopologyNetworkDevice
                        {
                            IPAddress = ip,
                            MACAddress = mac,
                            IsOnline = true,
                            LastSeen = DateTime.Now
                        };

                        devices.Add(device);
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Windows ARP scan error: {ex.Message}");
            }

            return devices;
        }

        private async Task<List<TopologyNetworkDevice>> GetArpTableLinuxAsync()
        {
            var devices = new List<TopologyNetworkDevice>();

            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "/bin/bash",
                        Arguments = "-c \"ip neigh show\"",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                string output = await process.StandardOutput.ReadToEndAsync();
                await process.WaitForExitAsync();

                // Parse ip neigh output
                var lines = output.Split('\n');
                var pattern = @"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})";

                foreach (var line in lines)
                {
                    var match = Regex.Match(line, pattern);
                    if (match.Success)
                    {
                        var ip = match.Groups[1].Value;
                        var mac = match.Groups[2].Value.ToUpper();

                        var device = new TopologyNetworkDevice
                        {
                            IPAddress = ip,
                            MACAddress = mac,
                            IsOnline = true,
                            LastSeen = DateTime.Now
                        };

                        devices.Add(device);
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Linux ARP scan error: {ex.Message}");
            }

            return devices;
        }

        private async Task<List<TopologyNetworkDevice>> PerformActiveScanAsync()
        {
            var devices = new List<TopologyNetworkDevice>();

            if (string.IsNullOrEmpty(_localSubnet))
                return devices;

            try
            {
                var subnetParts = _localSubnet.Split('.');
                if (subnetParts.Length != 4)
                    return devices;

                var baseIP = $"{subnetParts[0]}.{subnetParts[1]}.{subnetParts[2]}";

                OnProgressUpdate?.Invoke($"Scanning subnet {baseIP}.0/24...");

                // Ping sweep on full /24 subnet (1-254)
                var pingTasks = new List<Task<TopologyNetworkDevice>>();

                // Scan in batches to avoid overwhelming the network
                for (int i = 1; i <= 254; i++)
                {
                    string ip = $"{baseIP}.{i}";
                    pingTasks.Add(PingDeviceAsync(ip));

                    // Process in batches of 50 for better performance
                    if (i % 50 == 0 || i == 254)
                    {
                        OnProgressUpdate?.Invoke($"Scanning IPs {i - 49} to {i}...");
                        var batchResults = await Task.WhenAll(pingTasks);
                        devices.AddRange(batchResults.Where(d => d != null));
                        pingTasks.Clear();
                    }
                }

                OnProgressUpdate?.Invoke($"Active scan found {devices.Count} responding devices");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Active scan error: {ex.Message}");
            }

            return devices;
        }

        private async Task<TopologyNetworkDevice> PingDeviceAsync(string ipAddress)
        {
            try
            {
                using var ping = new Ping();
                var reply = await ping.SendPingAsync(ipAddress, 1000);

                if (reply.Status == IPStatus.Success)
                {
                    return new TopologyNetworkDevice
                    {
                        IPAddress = ipAddress,
                        IsOnline = true,
                        ResponseTime = reply.RoundtripTime,
                        TTL = reply.Options?.Ttl ?? 0,
                        LastSeen = DateTime.Now
                    };
                }
            }
            catch
            {
                // Ping failed or host unreachable
            }

            return null;
        }

        private async Task EnrichDeviceInfoAsync(TopologyNetworkDevice device)
        {
            try
            {
                // Get hostname
                if (!string.IsNullOrEmpty(device.IPAddress))
                {
                    try
                    {
                        var hostEntry = await Dns.GetHostEntryAsync(device.IPAddress);
                        device.Hostname = hostEntry.HostName;
                    }
                    catch
                    {
                        device.Hostname = "Unknown";
                    }
                }

                // Get MAC vendor
                if (!string.IsNullOrEmpty(device.MACAddress))
                {
                    var vendorInfo = await TopologyMacVendorService.LookupVendorAsync(device.MACAddress);
                    device.Vendor = vendorInfo.Vendor;

                    if (device.DeviceType == TopologyDeviceType.Unknown)
                    {
                        device.DeviceType = vendorInfo.SuggestedType;
                    }
                }

                // Determine if gateway
                if (_gatewayIP != null && device.IPAddress == _gatewayIP.ToString())
                {
                    device.IsGateway = true;
                    device.DeviceType = TopologyDeviceType.Router;
                    device.NetworkLayer = 0;
                }

                // Enhanced router/AP detection using networking best practices
                await DetectRouterOrAPAsync(device);

                // Check if it's a mobile device
                if (device.IsMobileDevice())
                {
                    device.DeviceType = TopologyDeviceType.Mobile;
                }

                // Determine connection type (rough guess)
                if (device.DeviceType == TopologyDeviceType.Mobile || device.Vendor?.Contains("Wi-Fi", StringComparison.OrdinalIgnoreCase) == true)
                {
                    device.ConnectionType = TopologyConnectionType.Wireless;
                }
                else if (device.DeviceType == TopologyDeviceType.Desktop || device.DeviceType == TopologyDeviceType.Server)
                {
                    device.ConnectionType = TopologyConnectionType.Wired;
                }

                // Get TTL if not already set
                if (device.TTL == 0 && !string.IsNullOrEmpty(device.IPAddress))
                {
                    device.TTL = await GetDeviceTTLAsync(device.IPAddress);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Device enrichment error for {device.IPAddress}: {ex.Message}");
            }
        }

        private async Task DetectRouterOrAPAsync(TopologyNetworkDevice device)
        {
            if (device.IsGateway)
                return; // Already identified

            int routerScore = 0;

            // Factor 1: Check for router/AP vendor (very reliable)
            if (!string.IsNullOrEmpty(device.Vendor))
            {
                var routerVendors = new[] {
                    "Cisco", "Ubiquiti", "MikroTik", "TP-Link", "Netgear",
                    "D-Link", "ASUS", "Linksys", "Aruba", "Ruckus", "Meraki",
                    "Juniper", "Fortinet", "Huawei", "ZyXEL", "Buffalo"
                };

                foreach (var vendor in routerVendors)
                {
                    if (device.Vendor.Contains(vendor, StringComparison.OrdinalIgnoreCase))
                    {
                        routerScore += 30;
                        break;
                    }
                }
            }

            // Factor 2: Quick port scan for router/AP services
            var routerPorts = new[] {
                67,   // DHCP Server (most important indicator!)
                53,   // DNS Server
                80,   // Web Admin UI
                443,  // HTTPS Admin UI
                8080, // Alternative Web UI
                161,  // SNMP
                22,   // SSH
                23    // Telnet
            };

            int openRouterPorts = 0;
            var openPorts = new List<int>();

            foreach (var port in routerPorts)
            {
                if (await IsPortOpenAsync(device.IPAddress, port, 1000)) // 1 second timeout
                {
                    openRouterPorts++;
                    openPorts.Add(port);

                    // DHCP server is the strongest indicator
                    if (port == 67)
                        routerScore += 40;
                    // DNS and Web UI are strong indicators
                    else if (port == 53 || port == 80 || port == 443)
                        routerScore += 15;
                    // Other management ports
                    else
                        routerScore += 10;
                }
            }

            if (openPorts.Any())
            {
                Debug.WriteLine($"Device {device.IPAddress} has open ports: {string.Join(", ", openPorts)}");
            }

            // Factor 3: IP address patterns (routers often use .1, .254, .2)
            if (device.IPAddress != null)
            {
                if (device.IPAddress.EndsWith(".1") || device.IPAddress.EndsWith(".254"))
                    routerScore += 20;
                else if (device.IPAddress.EndsWith(".2") || device.IPAddress.EndsWith(".3"))
                    routerScore += 10; // Often APs
            }

            // Factor 4: Hostname patterns
            if (!string.IsNullOrEmpty(device.Hostname))
            {
                var hostname = device.Hostname.ToLower();
                if (hostname.Contains("router") || hostname.Contains("gateway") ||
                    hostname.Contains("ap") || hostname.Contains("access-point") ||
                    hostname.Contains("switch") || hostname.Contains("firewall"))
                {
                    routerScore += 25;
                }
            }

            // Factor 5: TTL patterns (routers typically have TTL 64 or 255)
            if (device.TTL == 64 || device.TTL == 255)
                routerScore += 5;

            // Decision: If score is high enough, mark as router/AP
            // Lowered threshold to 40 (from 50) to account for firewall-blocked port scans
            if (routerScore >= 40)
            {
                // Determine if it's specifically an AP
                bool isAP = device.Vendor?.Contains("Ubiquiti", StringComparison.OrdinalIgnoreCase) == true ||
                           device.Vendor?.Contains("UniFi", StringComparison.OrdinalIgnoreCase) == true ||
                           device.Vendor?.Contains("Aruba", StringComparison.OrdinalIgnoreCase) == true ||
                           device.Vendor?.Contains("Ruckus", StringComparison.OrdinalIgnoreCase) == true ||
                           device.Vendor?.Contains("WNC", StringComparison.OrdinalIgnoreCase) == true || // WNC makes APs
                           device.Hostname?.Contains("ap", StringComparison.OrdinalIgnoreCase) == true ||
                           device.Hostname?.Contains("access", StringComparison.OrdinalIgnoreCase) == true ||
                           (device.IPAddress != null && !device.IPAddress.EndsWith(".1") && !device.IPAddress.EndsWith(".254") && openRouterPorts > 0);

                device.DeviceType = isAP ? TopologyDeviceType.AccessPoint : TopologyDeviceType.Router;

                Debug.WriteLine($"✅ Detected {device.DeviceType}: {device.IPAddress} " +
                              $"(Score: {routerScore}, Vendor: {device.Vendor}, Ports: {openRouterPorts})");
            }
            else if (routerScore > 0)
            {
                Debug.WriteLine($"⚠️ Device {device.IPAddress} scored {routerScore} (below threshold, needs {40 - routerScore} more)");
            }
        }

        private async Task<bool> IsPortOpenAsync(string ipAddress, int port, int timeoutMs)
        {
            try
            {
                using var client = new System.Net.Sockets.TcpClient();
                var connectTask = client.ConnectAsync(ipAddress, port);

                // Use Task.WhenAny for timeout
                var completedTask = await Task.WhenAny(connectTask, Task.Delay(timeoutMs));

                if (completedTask == connectTask)
                {
                    // Connection attempt completed
                    await connectTask; // Await to catch any exceptions
                    bool isConnected = client.Connected;

                    if (isConnected)
                    {
                        Debug.WriteLine($"Port {port} OPEN on {ipAddress}");
                    }

                    return isConnected;
                }
                else
                {
                    // Timeout
                    return false;
                }
            }
            catch (Exception ex)
            {
                // Connection refused, host unreachable, etc.
                Debug.WriteLine($"Port {port} on {ipAddress}: {ex.Message}");
                return false;
            }
        }

        private async Task<int> GetDeviceTTLAsync(string ipAddress)
        {
            try
            {
                using var ping = new Ping();
                var reply = await ping.SendPingAsync(ipAddress, 1000);

                if (reply.Status == IPStatus.Success && reply.Options != null)
                {
                    return reply.Options.Ttl;
                }
            }
            catch
            {
                // Ignore
            }

            return 64; // Default TTL
        }

        private void BuildTopologyHierarchy(List<TopologyNetworkDevice> devices)
        {
            Debug.WriteLine("🔧 Building topology hierarchy with accurate parent detection...");

            // Step 1: Identify gateway (Layer 0)
            var gateway = devices.FirstOrDefault(d => d.IsGateway);

            if (gateway == null)
            {
                // Try to identify gateway by IP (typically .1)
                gateway = devices.FirstOrDefault(d =>
                    d.IPAddress != null &&
                    (d.IPAddress.EndsWith(".1") || d.IPAddress.EndsWith(".254")));
            }

            if (gateway == null)
            {
                // Last resort: find first router-type device
                gateway = devices.FirstOrDefault(d => d.IsRouter());
            }

            if (gateway != null)
            {
                gateway.NetworkLayer = 0;
                gateway.IsGateway = true;
                gateway.DeviceType = TopologyDeviceType.Router;
                Debug.WriteLine($"✅ Gateway identified: {gateway.IPAddress} ({gateway.Hostname})");
            }
            else
            {
                Debug.WriteLine("⚠️ No gateway found!");
            }

            // Step 2: Identify all infrastructure devices (routers/APs)
            var infrastructure = devices.Where(d =>
                (d.IsRouter() || d.IsAccessPoint() ||
                 d.DeviceType == TopologyDeviceType.Router ||
                 d.DeviceType == TopologyDeviceType.AccessPoint)
                && (gateway == null || d.IPAddress != gateway.IPAddress))
                .ToList();

            Debug.WriteLine($"📡 Found {infrastructure.Count} infrastructure devices (routers/APs)");

            // Step 3: Assign infrastructure to Layer 1 (directly connected to gateway)
            foreach (var device in infrastructure)
            {
                device.NetworkLayer = 1;
                if (gateway != null)
                {
                    device.ParentDeviceId = gateway.IPAddress;
                }
                Debug.WriteLine($"  📶 {device.DeviceType}: {device.IPAddress} → Layer 1 (parent: {device.ParentDeviceId})");
            }

            // Step 4: Use TTL-based hop detection for client devices
            var clients = devices.Where(d =>
                d.NetworkLayer < 0 &&
                (gateway == null || d.IPAddress != gateway.IPAddress) &&
                !infrastructure.Contains(d))
                .ToList();

            Debug.WriteLine($"💻 Processing {clients.Count} client devices...");

            foreach (var client in clients)
            {
                // Determine actual parent using multiple factors
                var parent = DetermineActualParent(client, gateway, infrastructure, devices);

                if (parent != null)
                {
                    client.ParentDeviceId = parent.IPAddress;
                    client.NetworkLayer = parent.NetworkLayer + 1;

                    Debug.WriteLine($"  ✅ {client.IPAddress} ({client.Vendor ?? "Unknown"}) → Parent: {parent.IPAddress} (Layer {client.NetworkLayer})");
                }
                else if (gateway != null)
                {
                    // Fallback to gateway
                    client.ParentDeviceId = gateway.IPAddress;
                    client.NetworkLayer = 1;
                    Debug.WriteLine($"  ⚠️ {client.IPAddress} → Gateway (fallback)");
                }
                else
                {
                    client.NetworkLayer = 0;
                    Debug.WriteLine($"  ❌ {client.IPAddress} → No parent found");
                }
            }

            Debug.WriteLine("✅ Topology hierarchy complete!");
        }

        private TopologyNetworkDevice DetermineActualParent(
            TopologyNetworkDevice device,
            TopologyNetworkDevice gateway,
            List<TopologyNetworkDevice> infrastructure,
            List<TopologyNetworkDevice> allDevices)
        {
            // If no infrastructure devices, connect directly to gateway
            if (!infrastructure.Any())
            {
                Debug.WriteLine($"    No infrastructure devices, using gateway for {device.IPAddress}");
                return gateway;
            }

            Debug.WriteLine($"    🔍 Determining parent for {device.IPAddress} (TTL: {device.TTL})...");

            // Check if we have advanced probe results for this device
            if (_probeResults.TryGetValue(device.IPAddress, out var probeResult))
            {
                Debug.WriteLine($"    🔬 Using advanced probe data: {probeResult.DetectionMethod}");

                // Use advanced stealth recon service to determine parent
                var advancedParent = _stealthRecon.DetermineParentAdvanced(
                    device.IPAddress, probeResult, gateway, infrastructure, allDevices);

                if (advancedParent != null)
                {
                    Debug.WriteLine($"       ✅ Advanced detection: Parent = {advancedParent.IPAddress}");
                    return advancedParent;
                }
            }

            // Fallback: Use TTL-based hop detection
            var hopBasedParent = DetermineParentByTTL(device, gateway, infrastructure);
            if (hopBasedParent != null)
            {
                Debug.WriteLine($"       ✅ TTL analysis: Parent = {hopBasedParent.IPAddress}");
                return hopBasedParent;
            }

            // Method 2: IP proximity + Connection type analysis
            var scores = new Dictionary<TopologyNetworkDevice, double>();

            foreach (var infra in infrastructure)
            {
                double score = 0;

                // Factor 1: IP Address Proximity (60 points)
                var proximity = CalculateIPProximity(device.IPAddress, infra.IPAddress);
                score += proximity * 60;

                // Factor 2: Connection Type Match (40 points)
                // Wireless devices likely connect through APs
                if (device.ConnectionType == TopologyConnectionType.Wireless &&
                    infra.DeviceType == TopologyDeviceType.AccessPoint)
                {
                    score += 40;
                    Debug.WriteLine($"       Wireless device + AP match: {infra.IPAddress} (+40)");
                }

                // Wired devices likely connect through main router
                if (device.ConnectionType == TopologyConnectionType.Wired &&
                    infra.DeviceType == TopologyDeviceType.Router)
                {
                    score += 40;
                    Debug.WriteLine($"       Wired device + Router match: {infra.IPAddress} (+40)");
                }

                // Factor 3: Vendor relationship (10 points)
                if (!string.IsNullOrEmpty(device.Vendor) && !string.IsNullOrEmpty(infra.Vendor))
                {
                    if (device.Vendor.Equals(infra.Vendor, StringComparison.OrdinalIgnoreCase))
                    {
                        score += 10;
                    }
                }

                // Factor 4: Load balancing - don't overload one infrastructure device
                int currentLoad = allDevices.Count(d => d.ParentDeviceId == infra.IPAddress);
                if (currentLoad > 8)
                {
                    score -= (currentLoad - 8) * 5;  // Penalty for overloading
                }

                scores[infra] = score;
                Debug.WriteLine($"       Score for {infra.IPAddress}: {score:F1}");
            }

            // Return infrastructure device with highest score
            var bestParent = scores.OrderByDescending(x => x.Value).FirstOrDefault();

            // If score is too low, default to gateway
            if (bestParent.Value < 30)
            {
                Debug.WriteLine($"       ⚠️ All scores too low, defaulting to gateway");
                return gateway;
            }

            Debug.WriteLine($"       ✅ Best parent: {bestParent.Key.IPAddress} (score: {bestParent.Value:F1})");
            return bestParent.Key;
        }

        private TopologyNetworkDevice DetermineParentByTTL(
            TopologyNetworkDevice device,
            TopologyNetworkDevice gateway,
            List<TopologyNetworkDevice> infrastructure)
        {
            // TTL analysis:
            // - Most devices start with TTL 64 or 128
            // - Each hop decreases TTL by 1
            // - TTL 64/128 = direct connection (Layer 1 - direct to gateway)
            // - TTL 63/127 = 1 hop (Layer 2 - through AP/router)
            // - TTL 62/126 = 2 hops (Layer 3 - through multiple devices)

            if (device.TTL <= 0)
            {
                Debug.WriteLine($"       TTL not available for {device.IPAddress}");
                return null;  // TTL not available
            }

            // Calculate hop count
            int hops = CalculateHopCount(device.TTL);

            if (hops < 0)
            {
                Debug.WriteLine($"       Cannot determine hops from TTL {device.TTL}");
                return null;
            }

            Debug.WriteLine($"       TTL {device.TTL} → {hops} hop(s)");

            // Direct connection (0 hops from gateway)
            if (hops == 0)
            {
                Debug.WriteLine($"       Direct connection to gateway");
                return gateway;
            }

            // 1 hop away - need to find which infrastructure device it's through
            if (hops == 1 && infrastructure.Any())
            {
                // Find closest infrastructure device by IP proximity
                var closest = infrastructure
                    .OrderByDescending(i => CalculateIPProximity(device.IPAddress, i.IPAddress))
                    .FirstOrDefault();

                if (closest != null)
                {
                    Debug.WriteLine($"       1 hop - closest infrastructure: {closest.IPAddress}");
                    return closest;
                }
            }

            return null;  // Can't determine from TTL
        }

        private int CalculateHopCount(int ttl)
        {
            // Most operating systems use initial TTL of 64 or 128
            // Calculate hops based on these common values

            if (ttl >= 128)
            {
                return 128 - ttl;  // Windows typically starts at 128
            }
            else if (ttl >= 64)
            {
                return 64 - ttl;   // Linux/Unix typically starts at 64
            }
            else if (ttl >= 32)
            {
                return 64 - ttl;   // Assume started at 64
            }
            else
            {
                return -1;  // Unknown/unreliable
            }
        }

        private double CalculateIPProximity(string ip1, string ip2)
        {
            if (string.IsNullOrEmpty(ip1) || string.IsNullOrEmpty(ip2))
                return 0;

            try
            {
                var parts1 = ip1.Split('.').Select(int.Parse).ToArray();
                var parts2 = ip2.Split('.').Select(int.Parse).ToArray();

                if (parts1.Length != 4 || parts2.Length != 4)
                    return 0;

                // Same /24 subnet (first 3 octets match)
                if (parts1[0] == parts2[0] && parts1[1] == parts2[1] && parts1[2] == parts2[2])
                {
                    // Very close IPs (within 10)
                    if (Math.Abs(parts1[3] - parts2[3]) <= 10)
                        return 1.0;

                    // Same subnet but farther apart
                    return 0.6;
                }

                // Same /16 subnet (first 2 octets match)
                if (parts1[0] == parts2[0] && parts1[1] == parts2[1])
                    return 0.3;

                // Same /8 subnet (first octet matches)
                if (parts1[0] == parts2[0])
                    return 0.1;

                return 0;
            }
            catch
            {
                return 0;
            }
        }

        private void BalanceTopology(List<TopologyNetworkDevice> devices, TopologyNetworkDevice gateway, List<TopologyNetworkDevice> routers)
        {
            if (gateway == null || !routers.Any())
                return;

            // Find overloaded parent devices
            var parentLoads = devices
                .Where(d => !string.IsNullOrEmpty(d.ParentDeviceId))
                .GroupBy(d => d.ParentDeviceId)
                .ToDictionary(g => g.Key, g => g.ToList());

            foreach (var load in parentLoads.Where(l => l.Value.Count > 15))
            {
                var parent = devices.FirstOrDefault(d => d.Id == load.Key);
                if (parent == null || parent.Id == gateway?.Id)
                    continue;

                // Move some devices to other routers
                var excessDevices = load.Value.Skip(10).ToList();
                var otherRouters = routers.Where(r => r.Id != parent.Id).ToList();

                if (!otherRouters.Any())
                    continue;

                int routerIndex = 0;
                foreach (var device in excessDevices)
                {
                    var newParent = otherRouters[routerIndex % otherRouters.Count];

                    // Update relationships
                    parent.ChildDeviceIds.Remove(device.Id);
                    device.ParentDeviceId = newParent.Id;
                    newParent.ChildDeviceIds.Add(device.Id);
                    device.NetworkLayer = newParent.NetworkLayer + 1;

                    routerIndex++;
                }
            }
        }

        private IPAddress GetDefaultGateway()
        {
            try
            {
                var networkInterfaces = NetworkInterface.GetAllNetworkInterfaces();

                foreach (var networkInterface in networkInterfaces)
                {
                    if (networkInterface.OperationalStatus == OperationalStatus.Up)
                    {
                        var properties = networkInterface.GetIPProperties();

                        foreach (var gateway in properties.GatewayAddresses)
                        {
                            if (gateway.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                            {
                                return gateway.Address;
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Gateway detection error: {ex.Message}");
            }

            return null;
        }

        private string GetLocalSubnet()
        {
            try
            {
                var host = Dns.GetHostEntry(Dns.GetHostName());

                foreach (var ip in host.AddressList)
                {
                    if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        // Return first local IP
                        if (ip.ToString().StartsWith("192.168.") ||
                            ip.ToString().StartsWith("10.") ||
                            ip.ToString().StartsWith("172."))
                        {
                            return ip.ToString();
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Subnet detection error: {ex.Message}");
            }

            return "192.168.1.1"; // Default fallback
        }

        public async Task<List<TopologyPortInfo>> ScanPortsAsync(string ipAddress)
        {
            var openPorts = new List<TopologyPortInfo>();
            var commonPorts = new Dictionary<int, string>
            {
                { 21, "FTP" },
                { 22, "SSH" },
                { 23, "Telnet" },
                { 25, "SMTP" },
                { 53, "DNS" },
                { 80, "HTTP" },
                { 110, "POP3" },
                { 143, "IMAP" },
                { 443, "HTTPS" },
                { 445, "SMB" },
                { 3306, "MySQL" },
                { 3389, "RDP" },
                { 5432, "PostgreSQL" },
                { 5900, "VNC" },
                { 8080, "HTTP-Alt" },
                { 8443, "HTTPS-Alt" }
            };

            var tasks = commonPorts.Select(async port =>
            {
                try
                {
                    using var client = new System.Net.Sockets.TcpClient();
                    var connectTask = client.ConnectAsync(ipAddress, port.Key);

                    if (await Task.WhenAny(connectTask, Task.Delay(1000)) == connectTask)
                    {
                        if (client.Connected)
                        {
                            return new TopologyPortInfo(port.Key, port.Value);
                        }
                    }
                }
                catch
                {
                    // Port closed or filtered
                }

                return null;
            });

            var results = await Task.WhenAll(tasks);
            openPorts.AddRange(results.Where(p => p != null));

            return openPorts;
        }
    }
}