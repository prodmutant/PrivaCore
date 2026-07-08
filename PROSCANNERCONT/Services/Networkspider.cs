using PROSCANNERCONT.Models;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace PROSCANNERCONT.Services
{
    /// <summary>
    /// Professional Multi-Layer Network Spider
    /// Uses ARP, Layer 3, WiFi, and Service Probing to build accurate topology
    /// </summary>
    public class NetworkSpider
    {
        private CancellationTokenSource? _cts;

        public event Action<string>? ProgressChanged;
        public event Action<TopologyDevice>? DeviceDiscovered;

        /// <summary>
        /// Execute complete multi-layer network discovery
        /// </summary>
        public async Task<NetworkTopology> SpiderCrawlAsync(string ipRange, CancellationToken ct = default)
        {
            _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var topology = new NetworkTopology
            {
                ScanId = Guid.NewGuid().ToString(),
                ScanTime = DateTime.Now,
                NetworkRange = ipRange
            };

            try
            {
                ReportProgress("🕷️ Starting Multi-Layer Network Spider...");

                // LAYER 1: ARP Discovery (Local Network)
                ReportProgress("📡 Layer 1: ARP Scan (Broadcast Domain)");
                var arpDevices = await PerformARPScanAsync(_cts.Token);
                Debug.WriteLine($"✓ ARP: Found {arpDevices.Count} devices");

                // LAYER 2: MAC OUI Lookup (Vendor Identification)
                ReportProgress("🏷️ Layer 2: MAC Vendor Classification");
                await ClassifyDevicesByVendorAsync(arpDevices, _cts.Token);
                Debug.WriteLine($"✓ Classified devices by vendor");

                // LAYER 3: Gateway & Traceroute (Routing Discovery)
                ReportProgress("🌐 Layer 3: Gateway & Route Discovery");
                var routers = await DiscoverRoutersLayer3Async(arpDevices, _cts.Token);
                Debug.WriteLine($"✓ Layer 3: Found {routers.Count} routers");

                // LAYER 4: WiFi Discovery (SSID/BSSID Scanning)
                ReportProgress("📶 Layer 4: WiFi AP Discovery");
                await DiscoverWiFiAccessPointsAsync(routers, _cts.Token);
                Debug.WriteLine($"✓ WiFi: Scanned for APs");

                // LAYER 5: Service Probing (SNMP, HTTP, SSH)
                ReportProgress("🔍 Layer 5: Active Service Probing");
                await ProbeRouterServicesAsync(routers, _cts.Token);
                Debug.WriteLine($"✓ Service probing complete");

                // LAYER 6: Device-to-Router Mapping (The Critical Part)
                ReportProgress("🔗 Layer 6: Building Device-Router Relationships");
                await MapDevicesToRoutersAsync(arpDevices, routers, _cts.Token);
                Debug.WriteLine($"✓ Device mapping complete");

                // Build final topology
                topology.Routers = routers;
                topology.Devices = arpDevices;
                BuildTopologyStructure(topology);

                ReportProgress($"✅ Complete: {topology.TotalRouters} routers, {topology.TotalDevices} devices");
            }
            catch (OperationCanceledException)
            {
                ReportProgress("❌ Scan cancelled");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Spider error: {ex.Message}");
                ReportProgress($"❌ Error: {ex.Message}");
            }

            return topology;
        }

        #region LAYER 1: ARP Scan

        private async Task<List<TopologyDevice>> PerformARPScanAsync(CancellationToken ct)
        {
            var devices = new List<TopologyDevice>();

            await Task.Run(async () =>
            {
                try
                {
                    // Method 1: Parse system ARP cache
                    var proc = Process.Start(new ProcessStartInfo
                    {
                        FileName = "arp",
                        Arguments = "-a",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    });

                    proc.WaitForExit(5000);
                    var output = proc.StandardOutput.ReadToEnd();

                    // Parse ARP output
                    var matches = Regex.Matches(output, @"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2})", RegexOptions.IgnoreCase);

                    foreach (Match match in matches)
                    {
                        var ip = match.Groups[1].Value;
                        var mac = match.Groups[2].Value.ToUpper().Replace('-', ':');

                        // Skip multicast/broadcast
                        if (mac.StartsWith("01:00:5E") || mac == "FF:FF:FF:FF:FF:FF")
                            continue;

                        var device = new TopologyDevice
                        {
                            IPAddress = ip,
                            MACAddress = mac,
                            IsOnline = true,
                            DiscoveredAt = DateTime.Now,
                            LastSeen = DateTime.Now
                        };

                        devices.Add(device);
                        DeviceDiscovered?.Invoke(device);
                        Debug.WriteLine($"  ARP: {ip} → {mac}");
                    }

                    // Method 2: Active ARP scan (ping sweep to populate ARP cache)
                    var localIP = GetLocalIPAddress();
                    if (localIP != null)
                    {
                        var subnet = string.Join(".", localIP.Split('.').Take(3));
                        var tasks = new List<Task>();

                        for (int i = 1; i <= 254; i++)
                        {
                            if (ct.IsCancellationRequested) break;

                            var ip = $"{subnet}.{i}";
                            tasks.Add(PingDeviceAsync(ip, devices, ct));

                            if (tasks.Count >= 50) // Batch size
                            {
                                await Task.WhenAll(tasks);
                                tasks.Clear();
                            }
                        }

                        if (tasks.Any())
                            await Task.WhenAll(tasks);
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"ARP scan error: {ex.Message}");
                }
            }, ct);

            return devices;
        }

        private async Task PingDeviceAsync(string ip, List<TopologyDevice> devices, CancellationToken ct)
        {
            try
            {
                using var ping = new Ping();
                var reply = await ping.SendPingAsync(ip, 500);

                if (reply.Status == IPStatus.Success)
                {
                    lock (devices)
                    {
                        if (!devices.Any(d => d.IPAddress == ip))
                        {
                            var device = new TopologyDevice
                            {
                                IPAddress = ip,
                                IsOnline = true,
                                ResponseTime = TimeSpan.FromMilliseconds(reply.RoundtripTime),
                                DiscoveredAt = DateTime.Now,
                                LastSeen = DateTime.Now
                            };

                            // Try to get MAC from ARP after ping
                            device.MACAddress = GetMACFromARP(ip);

                            devices.Add(device);
                            DeviceDiscovered?.Invoke(device);
                        }
                    }
                }
            }
            catch { }
        }

        private string? GetMACFromARP(string ip)
        {
            try
            {
                var proc = Process.Start(new ProcessStartInfo
                {
                    FileName = "arp",
                    Arguments = $"-a {ip}",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                });

                proc.WaitForExit(1000);
                var output = proc.StandardOutput.ReadToEnd();
                var match = Regex.Match(output, @"([0-9a-f]{2}[:-]){5}[0-9a-f]{2}", RegexOptions.IgnoreCase);
                return match.Success ? match.Value.ToUpper().Replace('-', ':') : null;
            }
            catch { return null; }
        }

        #endregion

        #region LAYER 2: MAC Vendor Classification

        private async Task ClassifyDevicesByVendorAsync(List<TopologyDevice> devices, CancellationToken ct)
        {
            var vendorHints = new Dictionary<string, DeviceRole>
            {
                // Routers
                {"00:50:56", DeviceRole.CoreRouter}, // Cisco
                {"00:1B:63", DeviceRole.CoreRouter}, // Netgear
                {"E8:1B:69", DeviceRole.CoreRouter}, // Arcadyan (ISP routers)
                {"BC:22:28", DeviceRole.CoreRouter}, // D-Link
                {"F8:1A:67", DeviceRole.CoreRouter}, // TP-Link
                
                // Access Points
                {"00:24:6C", DeviceRole.AccessPoint}, // Ubiquiti
                {"04:DA:D2", DeviceRole.AccessPoint}, // Ubiquiti
                {"B4:75:0E", DeviceRole.AccessPoint}, // Ubiquiti
                {"44:D9:E7", DeviceRole.AccessPoint}, // Ubiquiti
                {"68:D7:9A", DeviceRole.AccessPoint}, // Ubiquiti
                {"F0:9F:C2", DeviceRole.AccessPoint}, // Ubiquiti
                {"24:5A:4C", DeviceRole.AccessPoint}, // Ubiquiti
                {"E8:65:D4", DeviceRole.AccessPoint}, // Aruba AP
                {"00:1A:1E", DeviceRole.AccessPoint}, // Aruba AP
                
                // IoT
                {"B8:27:EB", DeviceRole.IoTDevice}, // Raspberry Pi
                {"DC:A6:32", DeviceRole.IoTDevice}, // Raspberry Pi
            };

            await Task.Run(() =>
            {
                foreach (var device in devices)
                {
                    if (string.IsNullOrEmpty(device.MACAddress))
                        continue;

                    var oui = device.MACAddress.Substring(0, 8); // First 3 octets

                    if (vendorHints.TryGetValue(oui, out var role))
                    {
                        device.Role = role;
                        Debug.WriteLine($"  Classified {device.IPAddress}: {role} (MAC: {oui})");
                    }

                    // Lookup full vendor name (you can expand this)
                    device.Vendor = LookupMACVendor(oui);
                }
            }, ct);
        }

        private string LookupMACVendor(string oui)
        {
            var vendors = new Dictionary<string, string>
            {
                {"00:50:56", "Cisco"},
                {"00:1B:63", "Netgear"},
                {"E8:1B:69", "Arcadyan"},
                {"BC:22:28", "D-Link"},
                {"F8:1A:67", "TP-Link"},
                {"00:24:6C", "Ubiquiti"},
                {"04:DA:D2", "Ubiquiti"},
                {"B8:27:EB", "Raspberry Pi"},
                {"DC:A6:32", "Raspberry Pi"},
            };

            return vendors.TryGetValue(oui, out var vendor) ? vendor : "Unknown";
        }

        #endregion

        #region LAYER 3: Gateway & Traceroute Discovery

        private async Task<List<NetworkRouter>> DiscoverRoutersLayer3Async(List<TopologyDevice> devices, CancellationToken ct)
        {
            var routers = new List<NetworkRouter>();

            // Step 1: Find default gateway (Core Router)
            var gatewayIP = GetDefaultGateway();
            if (gatewayIP != null)
            {
                var gatewayDevice = devices.FirstOrDefault(d => d.IPAddress == gatewayIP);
                if (gatewayDevice != null)
                {
                    var coreRouter = new NetworkRouter
                    {
                        IPAddress = gatewayIP,
                        MACAddress = gatewayDevice.MACAddress,
                        Hostname = gatewayDevice.Hostname,
                        Role = DeviceRole.CoreRouter,
                        DetectionConfidence = 100,
                        DetectionMethods = new List<string> { "Default Gateway" }
                    };
                    routers.Add(coreRouter);
                    Debug.WriteLine($"  Core Router: {gatewayIP}");
                }
            }

            // Step 2: Find devices with router characteristics
            foreach (var device in devices.Where(d => d.Role == DeviceRole.CoreRouter || d.Role == DeviceRole.AccessPoint))
            {
                if (routers.Any(r => r.IPAddress == device.IPAddress))
                    continue; // Already added

                var router = new NetworkRouter
                {
                    IPAddress = device.IPAddress,
                    MACAddress = device.MACAddress,
                    Hostname = device.Hostname,
                    Role = device.Role,
                    DetectionConfidence = 85,
                    DetectionMethods = new List<string> { "MAC Vendor Classification" }
                };

                routers.Add(router);
                Debug.WriteLine($"  Secondary Router/AP: {device.IPAddress} ({device.Role})");
            }

            // Step 3: Traceroute to internet (find upstream path)
            await PerformTracerouteAnalysisAsync(routers, ct);

            return routers;
        }

        private async Task PerformTracerouteAnalysisAsync(List<NetworkRouter> routers, CancellationToken ct)
        {
            await Task.Run(() =>
            {
                try
                {
                    var proc = Process.Start(new ProcessStartInfo
                    {
                        FileName = "tracert",
                        Arguments = "-h 5 8.8.8.8", // Max 5 hops to Google DNS
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    });

                    proc.WaitForExit(10000);
                    var output = proc.StandardOutput.ReadToEnd();

                    // Parse traceroute hops
                    var matches = Regex.Matches(output, @"(\d+\.\d+\.\d+\.\d+)");
                    var hopNumber = 0;

                    foreach (Match match in matches)
                    {
                        var hopIP = match.Value;
                        hopNumber++;

                        // Check if this hop is one of our routers
                        var router = routers.FirstOrDefault(r => r.IPAddress == hopIP);
                        if (router != null)
                        {
                            router.DetectionMethods.Add($"Traceroute Hop {hopNumber}");
                            Debug.WriteLine($"  Traceroute: Hop {hopNumber} → {hopIP}");
                        }
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Traceroute error: {ex.Message}");
                }
            }, ct);
        }

        #endregion

        #region LAYER 4: WiFi Discovery

        private async Task DiscoverWiFiAccessPointsAsync(List<NetworkRouter> routers, CancellationToken ct)
        {
            await Task.Run(() =>
            {
                try
                {
                    var proc = Process.Start(new ProcessStartInfo
                    {
                        FileName = "netsh",
                        Arguments = "wlan show networks mode=bssid",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    });

                    proc.WaitForExit(5000);
                    var output = proc.StandardOutput.ReadToEnd();

                    // Parse SSID and BSSID
                    var ssidMatches = Regex.Matches(output, @"SSID \d+ : (.+)");
                    var bssidMatches = Regex.Matches(output, @"BSSID \d+\s+: ([0-9a-f:]+)", RegexOptions.IgnoreCase);

                    for (int i = 0; i < Math.Min(ssidMatches.Count, bssidMatches.Count); i++)
                    {
                        var ssid = ssidMatches[i].Groups[1].Value.Trim();
                        var bssid = bssidMatches[i].Groups[1].Value.ToUpper();

                        // Try to match BSSID to known router
                        var router = routers.FirstOrDefault(r => r.MACAddress == bssid);
                        if (router != null)
                        {
                            router.Hostname = $"{ssid} (AP)";
                            router.DetectionMethods.Add("WiFi BSSID Match");
                            Debug.WriteLine($"  WiFi AP: {ssid} → {bssid}");
                        }
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"WiFi scan error: {ex.Message}");
                }
            }, ct);
        }

        #endregion

        #region LAYER 5: Service Probing

        private async Task ProbeRouterServicesAsync(List<NetworkRouter> routers, CancellationToken ct)
        {
            var tasks = routers.Select(router => ProbeRouterAsync(router, ct));
            await Task.WhenAll(tasks);
        }

        private async Task ProbeRouterAsync(NetworkRouter router, CancellationToken ct)
        {
            var servicePorts = new[] { 80, 443, 22, 23, 161 }; // HTTP, HTTPS, SSH, Telnet, SNMP

            foreach (var port in servicePorts)
            {
                if (ct.IsCancellationRequested) break;

                try
                {
                    using var tcp = new TcpClient();
                    await tcp.ConnectAsync(router.IPAddress, port).WaitAsync(TimeSpan.FromMilliseconds(500), ct);

                    if (tcp.Connected)
                    {
                        router.DetectionMethods.Add($"Port {port} Open");

                        if (port == 80 || port == 443)
                            router.DetectionMethods.Add("Web Management Interface");
                        if (port == 161)
                        {
                            router.DetectionMethods.Add("SNMP Enabled");
                            string sysDescr = await SnmpGetSysDescrAsync(router.IPAddress, ct);
                            if (!string.IsNullOrEmpty(sysDescr))
                            {
                                router.DetectionMethods.Add($"SNMP sysDescr: {sysDescr}");
                                // Enrich hostname from SNMP if not already known
                                var descLower = sysDescr.ToLowerInvariant();
                                if (string.IsNullOrEmpty(router.Hostname))
                                {
                                    if      (descLower.Contains("cisco"))    router.Hostname = "Cisco Router";
                                    else if (descLower.Contains("juniper"))  router.Hostname = "Juniper Router";
                                    else if (descLower.Contains("huawei"))   router.Hostname = "Huawei Router";
                                    else if (descLower.Contains("mikrotik")) router.Hostname = "MikroTik Router";
                                    else if (descLower.Contains("linux"))    router.Hostname = "Linux Router";
                                }
                            }
                        }

                        Debug.WriteLine($"  {router.IPAddress}: Port {port} open");
                    }
                }
                catch { }
            }
        }

        /// <summary>
        /// Sends an SNMPv1 GET request for sysDescr.0 (OID 1.3.6.1.2.1.1.1.0) using the
        /// "public" community string. Returns the string value on success, null on failure.
        /// </summary>
        private static async Task<string> SnmpGetSysDescrAsync(string host, CancellationToken ct)
        {
            // SNMPv1 GET-Request PDU for OID 1.3.6.1.2.1.1.1.0, community "public"
            // Pre-encoded as a fixed byte array (request ID = 1, error = 0, error-index = 0)
            byte[] request = new byte[]
            {
                0x30, 0x29,                         // SEQUENCE (41 bytes)
                  0x02, 0x01, 0x00,                 // version = 0 (SNMPv1)
                  0x04, 0x06, 0x70,0x75,0x62,0x6C,0x69,0x63, // community = "public"
                  0xA0, 0x1C,                       // GetRequest-PDU (28 bytes)
                    0x02, 0x04, 0x00,0x00,0x00,0x01, // requestId = 1
                    0x02, 0x01, 0x00,               // error-status = 0
                    0x02, 0x01, 0x00,               // error-index  = 0
                    0x30, 0x0E,                     // VarBindList
                      0x30, 0x0C,                   // VarBind
                        0x06, 0x08, 0x2B,0x06,0x01,0x02,0x01,0x01,0x01,0x00, // OID 1.3.6.1.2.1.1.1.0
                        0x05, 0x00              // NULL value
            };

            try
            {
                using var udp = new UdpClient();
                udp.Client.ReceiveTimeout = 1500;
                await udp.SendAsync(request, request.Length, host, 161);

                var receiveTask = udp.ReceiveAsync();
                if (await Task.WhenAny(receiveTask, Task.Delay(1500, ct)) != receiveTask)
                    return null;

                byte[] response = receiveTask.Result.Buffer;
                return ParseSnmpOctetString(response);
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Extracts the first OCTET STRING value from a raw SNMPv1 response packet.
        /// </summary>
        private static string ParseSnmpOctetString(byte[] data)
        {
            // Walk bytes looking for OCTET STRING tag (0x04) followed by length then value
            for (int i = 0; i < data.Length - 2; i++)
            {
                if (data[i] != 0x04) continue;
                int len = data[i + 1];
                if (i + 2 + len > data.Length) continue;
                string value = Encoding.ASCII.GetString(data, i + 2, len).Trim();
                if (value.Length > 3) // ignore tiny/empty strings
                    return value.Length > 80 ? value[..80] + "…" : value;
            }
            return null;
        }

        #endregion

        #region LAYER 6: Device-to-Router Mapping

        private async Task MapDevicesToRoutersAsync(List<TopologyDevice> devices, List<NetworkRouter> routers, CancellationToken ct)
        {
            await Task.Run(() =>
            {
                foreach (var device in devices)
                {
                    // Skip if device is itself a router
                    if (routers.Any(r => r.IPAddress == device.IPAddress))
                        continue;

                    // Find parent router
                    var parentRouter = FindParentRouter(device, routers);

                    if (parentRouter != null)
                    {
                        device.ParentRouterIP = parentRouter.IPAddress;
                        parentRouter.ConnectedDevices.Add(device);
                        Debug.WriteLine($"  {device.IPAddress} → {parentRouter.IPAddress}");
                    }
                }
            }, ct);
        }

        private NetworkRouter? FindParentRouter(TopologyDevice device, List<NetworkRouter> routers)
        {
            // Strategy: Use subnet matching + router priority
            var deviceSubnet = GetSubnet(device.IPAddress);
            var sameSubnetRouters = routers.Where(r => GetSubnet(r.IPAddress) == deviceSubnet).ToList();

            if (sameSubnetRouters.Count == 0)
                return null;

            if (sameSubnetRouters.Count == 1)
                return sameSubnetRouters[0];

            // Multiple routers on same subnet - prioritize by role
            // Prefer APs over Core routers (APs usually have direct device connections)
            var ap = sameSubnetRouters.FirstOrDefault(r => r.Role == DeviceRole.AccessPoint);
            if (ap != null) return ap;

            return sameSubnetRouters.OrderByDescending(r => r.DetectionConfidence).First();
        }

        #endregion

        #region Topology Building

        private void BuildTopologyStructure(NetworkTopology topology)
        {
            // Set core router
            topology.CoreRouter = topology.Routers.FirstOrDefault(r => r.Role == DeviceRole.CoreRouter);

            // Build router connections
            foreach (var router in topology.Routers.Where(r => r != topology.CoreRouter))
            {
                if (topology.CoreRouter != null)
                {
                    router.ParentRouterIP = topology.CoreRouter.IPAddress;
                    topology.CoreRouter.ChildRouterIPs.Add(router.IPAddress);

                    if (!topology.RouterConnections.ContainsKey(topology.CoreRouter.IPAddress))
                        topology.RouterConnections[topology.CoreRouter.IPAddress] = new List<string>();

                    topology.RouterConnections[topology.CoreRouter.IPAddress].Add(router.IPAddress);
                }
            }
        }

        #endregion

        #region Helpers

        private string? GetLocalIPAddress()
        {
            try
            {
                var host = Dns.GetHostEntry(Dns.GetHostName());
                return host.AddressList
                    .FirstOrDefault(ip => ip.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(ip))
                    ?.ToString();
            }
            catch { return null; }
        }

        private string? GetDefaultGateway()
        {
            try
            {
                return NetworkInterface.GetAllNetworkInterfaces()
                    .Where(n => n.OperationalStatus == OperationalStatus.Up)
                    .SelectMany(n => n.GetIPProperties().GatewayAddresses)
                    .FirstOrDefault(g => g.Address.AddressFamily == AddressFamily.InterNetwork)
                    ?.Address.ToString();
            }
            catch { return null; }
        }

        private string GetSubnet(string ip)
        {
            var parts = ip.Split('.');
            return parts.Length >= 3 ? $"{parts[0]}.{parts[1]}.{parts[2]}" : ip;
        }

        private void ReportProgress(string message)
        {
            Debug.WriteLine(message);
            ProgressChanged?.Invoke(message);
        }

        public void CancelScan()
        {
            _cts?.Cancel();
        }

        #endregion
    }
}