using PROSCANNERCONT.Models;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using PROSCANNERCONT.Utils;

namespace PROSCANNERCONT.Services
{
    /// <summary>
    /// Enterprise Network Scanner - Accurate, fast, intelligent
    /// </summary>
    public class NetworkScanner
    {
        private CancellationTokenSource _cts;

        public event Action<string> ProgressChanged;
        public event Action<TopologyDevice> DeviceDiscovered;

        /// <summary>
        /// Scan network and build complete topology
        /// </summary>
        public async Task<NetworkTopology> ScanNetworkAsync(string ipRange, CancellationToken ct = default)
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
                // PHASE 1: Device Discovery
                ReportProgress("Phase 1/4: Discovering devices...");
                var devices = await DiscoverDevicesAsync(ipRange, _cts.Token);
                topology.Devices = devices;
                Debug.WriteLine($"✓ Found {devices.Count} devices");

                // PHASE 2: Router Identification
                ReportProgress("Phase 2/4: Identifying routers...");
                var routers = await IdentifyRoutersAsync(devices, _cts.Token);
                topology.Routers = routers;
                Debug.WriteLine($"✓ Found {routers.Count} routers");

                // PHASE 3: Parent Router Mapping (CRITICAL)
                ReportProgress("Phase 3/4: Mapping devices to parent routers...");
                await MapDevicesToParentRoutersAsync(devices, routers, _cts.Token);
                Debug.WriteLine($"✓ Mapped devices to routers");

                // PHASE 4: Router Relationships
                ReportProgress("Phase 4/4: Analyzing router connections...");
                BuildRouterHierarchy(routers, topology);
                Debug.WriteLine($"✓ Built router hierarchy");

                ReportProgress($"Complete: {topology.TotalRouters} routers, {topology.TotalDevices} devices");
            }
            catch (OperationCanceledException)
            {
                ReportProgress("Scan cancelled");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Scan error: {ex.Message}");
                ReportProgress($"Error: {ex.Message}");
            }

            return topology;
        }

        public void CancelScan()
        {
            _cts?.Cancel();
        }

        #region PHASE 1: Device Discovery

        private async Task<List<TopologyDevice>> DiscoverDevicesAsync(string ipRange, CancellationToken ct)
        {
            var devices = new List<TopologyDevice>();
            var ips = ParseIPRange(ipRange);

            var semaphore = new SemaphoreSlim(AppConstants.Scanning.MaxConcurrentScans);
            var tasks = ips.Select(async ip =>
            {
                await semaphore.WaitAsync(ct);
                try
                {
                    var device = await ProbeDeviceAsync(ip, ct);
                    if (device != null)
                    {
                        lock (devices) devices.Add(device);
                        DeviceDiscovered?.Invoke(device);
                    }
                }
                finally
                {
                    semaphore.Release();
                }
            });

            await Task.WhenAll(tasks);
            return devices;
        }

        private async Task<TopologyDevice> ProbeDeviceAsync(string ip, CancellationToken ct)
        {
            try
            {
                // Quick ping check
                using var ping = new Ping();
                var reply = await ping.SendPingAsync(ip, AppConstants.Scanning.PingTimeoutMs);

                // Null-safe check on reply status (fix for NullReferenceException if ICMP is blocked)
                if (reply?.Status != IPStatus.Success)
                    return null;

                var device = new TopologyDevice
                {
                    IPAddress = ip,
                    IsOnline = true,
                    ResponseTime = TimeSpan.FromMilliseconds(reply.RoundtripTime),
                    LastSeen = DateTime.Now,
                    DiscoveredAt = DateTime.Now
                };

                // Get additional details (parallel)
                var tasks = new Task[]
                {
                    GetHostnameAsync(ip, ct).ContinueWith(t => device.Hostname = t.Result, ct),
                    GetMACAddressAsync(ip, ct).ContinueWith(t => device.MACAddress = t.Result, ct),
                    ScanPortsAsync(ip, ct).ContinueWith(t => device.OpenPorts = t.Result, ct)
                };

                await Task.WhenAll(tasks);

                // Identify OS from TTL and ports
                device.OperatingSystem = IdentifyOS(reply.Options?.Ttl ?? 0, device.OpenPorts);

                return device;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[NetworkScanner.ProbeDeviceAsync] {ip}: {ex.Message}");
                return null;
            }
        }

        private async Task<string> GetHostnameAsync(string ip, CancellationToken ct)
        {
            try
            {
                var host = await Dns.GetHostEntryAsync(ip)
                    .WaitAsync(TimeSpan.FromSeconds(AppConstants.Scanning.DnsResolutionTimeoutSec), ct);
                return host.HostName;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[NetworkScanner.GetHostnameAsync] {ip}: {ex.Message}");
                return null;
            }
        }

        private async Task<string> GetMACAddressAsync(string ip, CancellationToken ct)
        {
            // SECURITY FIX: use ArgumentList instead of string-interpolated Arguments
            // to prevent command injection from a hostile IP string.
            if (!ValidationUtils.IsValidIpAddress(ip)) return null;

            return await Task.Run(() =>
            {
                try
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName = "arp",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    };
                    psi.ArgumentList.Add("-a");
                    psi.ArgumentList.Add(ip); // no injection possible — each arg is isolated

                    using var proc = Process.Start(psi);
                    if (proc == null) return null;

                    proc.WaitForExit(AppConstants.Scanning.ArpReadTimeoutMs);
                    var output = proc.StandardOutput.ReadToEnd();
                    var match = Regex.Match(output, @"([0-9A-F]{2}[:-]){5}[0-9A-F]{2}",
                        RegexOptions.IgnoreCase);
                    return match.Success ? match.Value.Replace('-', ':') : null;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[NetworkScanner.GetMACAddressAsync] {ex.Message}");
                    return null;
                }
            }, ct);
        }

        private async Task<List<int>> ScanPortsAsync(string ip, CancellationToken ct)
        {
            var openPorts = new List<int>();

            var tasks = AppConstants.Scanning.QuickScanPorts.Select(async port =>
            {
                try
                {
                    using var tcp = new TcpClient();
                    await tcp.ConnectAsync(ip, port).WaitAsync(TimeSpan.FromMilliseconds(500), ct);
                    if (tcp.Connected)
                    {
                        lock (openPorts) openPorts.Add(port);
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[NetworkScanner.ScanPortsAsync] {ip}:{port}: {ex.Message}");
                }
            });

            await Task.WhenAll(tasks);
            return openPorts;
        }

        private string IdentifyOS(int ttl, List<int> openPorts)
        {
            if (ttl >= 120 && ttl <= 128) return "Windows";
            if (ttl >= 60 && ttl <= 64) return "Linux/Unix";
            if (openPorts.Contains(3389)) return "Windows";
            if (openPorts.Contains(22) && !openPorts.Contains(3389)) return "Linux";
            return "Unknown";
        }

        #endregion

        #region PHASE 2: Router Identification

        private async Task<List<NetworkRouter>> IdentifyRoutersAsync(List<TopologyDevice> devices, CancellationToken ct)
        {
            var routers = new List<NetworkRouter>();

            // Method 1: Default gateway
            var gateway = GetDefaultGateway();
            if (gateway != null && devices.Any(d => d.IPAddress == gateway))
            {
                routers.Add(CreateRouter(devices.First(d => d.IPAddress == gateway), DeviceRole.CoreRouter, 100, "Default Gateway"));
            }

            // Method 2: Common router IPs (.1, .254) with open ports 80/443
            foreach (var device in devices)
            {
                var lastOctet = device.IPAddress.Split('.').Last();
                if ((lastOctet == "1" || lastOctet == "254") &&
                    (device.OpenPorts.Contains(80) || device.OpenPorts.Contains(443)))
                {
                    if (!routers.Any(r => r.IPAddress == device.IPAddress))
                    {
                        var role = device.IPAddress == gateway ? DeviceRole.CoreRouter : DeviceRole.AccessPoint;
                        routers.Add(CreateRouter(device, role, 85, "IP Pattern + Web Interface"));
                    }
                }
            }

            return routers;
        }

        private NetworkRouter CreateRouter(TopologyDevice device, DeviceRole role, int confidence, string method)
        {
            return new NetworkRouter
            {
                IPAddress = device.IPAddress,
                MACAddress = device.MACAddress,
                Hostname = device.Hostname,
                Role = role,
                DetectionConfidence = confidence,
                DetectionMethods = new List<string> { method }
            };
        }

        #endregion

        #region PHASE 3: Parent Router Mapping (CRITICAL)

        private async Task MapDevicesToParentRoutersAsync(List<TopologyDevice> devices, List<NetworkRouter> routers, CancellationToken ct)
        {
            foreach (var device in devices)
            {
                // Skip routers themselves
                if (routers.Any(r => r.IPAddress == device.IPAddress))
                    continue;

                // Find parent router using traceroute
                var parentIP = await FindParentRouterAsync(device.IPAddress, routers, ct);

                if (parentIP != null)
                {
                    device.ParentRouterIP = parentIP;
                    var parentRouter = routers.FirstOrDefault(r => r.IPAddress == parentIP);
                    parentRouter?.ConnectedDevices.Add(device);

                    Debug.WriteLine($"  {device.IPAddress} → {parentIP}");
                }
            }
        }

        private async Task<string> FindParentRouterAsync(string deviceIP, List<NetworkRouter> routers, CancellationToken ct)
        {
            return await Task.Run(() =>
            {
                try
                {
                    // Use TTL=1 ping to find first hop
                    using var ping = new Ping();
                    var options = new PingOptions(1, true);
                    var reply = ping.Send(deviceIP, 1000, new byte[32], options);

                    if (reply.Status == IPStatus.TtlExpired && reply.Address != null)
                    {
                        var firstHop = reply.Address.ToString();
                        if (routers.Any(r => r.IPAddress == firstHop))
                            return firstHop;
                    }

                    // Fallback: Same subnet router (prefer non-core)
                    var subnet = string.Join(".", deviceIP.Split('.').Take(3));
                    var sameSubnetRouters = routers.Where(r => r.IPAddress.StartsWith(subnet)).ToList();

                    if (sameSubnetRouters.Count == 1)
                        return sameSubnetRouters[0].IPAddress;

                    if (sameSubnetRouters.Count > 1)
                    {
                        var nonCore = sameSubnetRouters.FirstOrDefault(r => r.Role != DeviceRole.CoreRouter);
                        return nonCore?.IPAddress ?? sameSubnetRouters[0].IPAddress;
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[NetworkScanner.FindParentRouterAsync] {ex.Message}");
                }

                // Last resort: core router
                return routers.FirstOrDefault(r => r.Role == DeviceRole.CoreRouter)?.IPAddress;
            }, ct);
        }

        #endregion

        #region PHASE 4: Router Hierarchy

        private void BuildRouterHierarchy(List<NetworkRouter> routers, NetworkTopology topology)
        {
            var coreRouter = routers.FirstOrDefault(r => r.Role == DeviceRole.CoreRouter);
            if (coreRouter != null)
            {
                topology.CoreRouter = coreRouter;

                // Connect all other routers to core
                foreach (var router in routers.Where(r => r != coreRouter))
                {
                    router.ParentRouterIP = coreRouter.IPAddress;
                    coreRouter.ChildRouterIPs.Add(router.IPAddress);

                    if (!topology.RouterConnections.ContainsKey(coreRouter.IPAddress))
                        topology.RouterConnections[coreRouter.IPAddress] = new List<string>();

                    topology.RouterConnections[coreRouter.IPAddress].Add(router.IPAddress);
                }
            }
        }

        #endregion

        #region Helpers

        private List<string> ParseIPRange(string range)
        {
            var ips = new List<string>();

            if (range.Contains('/')) // CIDR
            {
                var parts = range.Split('/');
                var baseIP = parts[0];
                var prefix = int.Parse(parts[1]);
                var subnet = string.Join(".", baseIP.Split('.').Take(3));

                for (int i = 1; i <= 254; i++)
                    ips.Add($"{subnet}.{i}");
            }
            else // Single IP or range
            {
                ips.Add(range);
            }

            return ips;
        }

        private string GetDefaultGateway()
        {
            try
            {
                return NetworkInterface.GetAllNetworkInterfaces()
                    .Where(n => n.OperationalStatus == OperationalStatus.Up)
                    .SelectMany(n => n.GetIPProperties().GatewayAddresses)
                    .FirstOrDefault(g => g.Address.AddressFamily == AddressFamily.InterNetwork)
                    ?.Address.ToString();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[NetworkScanner.GetDefaultGateway] {ex.Message}");
                return null;
            }
        }

        private void ReportProgress(string message)
        {
            Debug.WriteLine(message);
            ProgressChanged?.Invoke(message);
        }

        #endregion
    }
}
