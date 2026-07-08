using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using System.Text;
using System.IO;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.ServiceDetection.Utils;

namespace PROSCANNERCONT.ServiceDetection.Detectors
{
    public class RpcDetector : IServiceDetector
    {
        public string ServiceName => "RPC";

        public int[] CommonPorts => new[] { 111, 32771, 530, 2049 };

        public int Priority => 45;

        private readonly ILogger<RpcDetector> _logger;

        // RPC protocol constants
        private const int RPC_CALL = 0;
        private const int RPC_REPLY = 1;
        private const int RPC_VERSION = 2;
        private const int PORTMAP_PROGRAM = 100000;
        private const int PORTMAP_DUMP_PROC = 4;

        public RpcDetector(ILogger<RpcDetector> logger)
        {
            _logger = logger;
        }

        public bool CanDetect(int port, PortScanResult initialScan)
        {
            if (port == 111) return true;

            bool isCommonPort = Array.IndexOf(CommonPorts, port) >= 0;

            bool isRpcService = false;
            if (!string.IsNullOrEmpty(initialScan.Service))
            {
                isRpcService = initialScan.Service.Contains("rpc", StringComparison.OrdinalIgnoreCase) ||
                               initialScan.Service.Contains("portmap", StringComparison.OrdinalIgnoreCase);
            }

            return isCommonPort || isRpcService;
        }

        public async Task<PortScanResult> DetectAsync(PortScanResult result, int timeout = 5000, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation("Detecting RPC on {0}:{1}", result.IPAddress, result.Port);

                // PORT 111 - Try to extract program info
                if (result.Port == 111)
                {
                    // First, try DUMP procedure to get mapping info
                    var dumpResult = await GetRpcProgramInfo(result.IPAddress, result.Port, timeout, cancellationToken);

                    if (dumpResult.success)
                    {
                        result.Service = "rpcbind";

                        // Format version from the info we actually extracted
                        string versionRange = FormatVersionRange(dumpResult.versions);
                        result.Version = $"{versionRange} (RPC #{dumpResult.program})";
                    }
                    else
                    {
                        // Fallback for when DUMP doesn't work - try probing specific versions
                        var probeResult = await ProbeRpcVersions(result.IPAddress, result.Port, timeout, cancellationToken);

                        if (probeResult.anyVersionWorks)
                        {
                            result.Service = "rpcbind";
                            result.Version = FormatVersionRange(probeResult.workingVersions) + $" (RPC #{PORTMAP_PROGRAM})";
                        }
                    }
                }
                else
                {
                    // For other ports, use probe to identify the RPC version
                    var probeResult = await ProbeRpcVersions(result.IPAddress, result.Port, timeout, cancellationToken);

                    if (probeResult.anyVersionWorks)
                    {
                        result.Service = "RPC";
                        result.Version = "v" + FormatVersionRange(probeResult.workingVersions);
                    }
                }

                // If we still don't have a service, try banner grabbing as last resort
                if (string.IsNullOrEmpty(result.Service))
                {
                    await TryBannerGrab(result, timeout, cancellationToken);
                }

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in RPC detection");
                return result;
            }
        }

        private async Task<(bool success, int program, HashSet<int> versions)> GetRpcProgramInfo(
            string ipAddress, int port, int timeout, CancellationToken cancellationToken)
        {
            var result = (success: false, program: PORTMAP_PROGRAM, versions: new HashSet<int>());

            try
            {
                using var client = new TcpClient();

                // Set up timeout and connect
                using var cts = new CancellationTokenSource(timeout);
                using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cts.Token, cancellationToken);

                try
                {
                    await client.ConnectAsync(ipAddress, port, linkedCts.Token);
                }
                catch
                {
                    return result;
                }

                // Try DUMP with version 2 first (most widely supported)
                byte[] dumpResult = await SendRpcCallTcp(client, PORTMAP_PROGRAM, 2, PORTMAP_DUMP_PROC, null, timeout, linkedCts.Token);

                if (dumpResult != null && dumpResult.Length >= 24)
                {
                    // Successfully received DUMP response
                    result.success = true;

                    // Extract supported versions from the response
                    ExtractPortmapperVersions(dumpResult, result.versions);

                    // If we couldn't extract versions, try other methods
                    if (result.versions.Count == 0)
                    {
                        // Try DUMP with version 4 if v2 didn't return version info
                        dumpResult = await SendRpcCallTcp(client, PORTMAP_PROGRAM, 4, PORTMAP_DUMP_PROC, null, timeout, linkedCts.Token);

                        if (dumpResult != null && dumpResult.Length >= 24)
                        {
                            ExtractPortmapperVersions(dumpResult, result.versions);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Error getting RPC program info");
            }

            return result;
        }

        private void ExtractPortmapperVersions(byte[] response, HashSet<int> versions)
        {
            try
            {
                // First validate it's a proper RPC response
                if (response.Length < 24) return;

                int messageType = IPAddress.NetworkToHostOrder(BitConverter.ToInt32(response, 4));
                if (messageType != RPC_REPLY) return;

                int replyStatus = IPAddress.NetworkToHostOrder(BitConverter.ToInt32(response, 8));
                if (replyStatus != 0) return; // Not MSG_ACCEPTED

                // Skip the verifier (8 bytes)
                // Check accept status at offset 16
                int acceptStatus = IPAddress.NetworkToHostOrder(BitConverter.ToInt32(response, 16));
                if (acceptStatus != 0) return; // Not SUCCESS

                // Now we're at the DUMP response body
                // It starts with a count (4 bytes), followed by entries
                if (response.Length < 28) return;

                int count = IPAddress.NetworkToHostOrder(BitConverter.ToInt32(response, 24));

                // Sanity check
                if (count <= 0 || count > 100) return;

                int pos = 28; // Start after the count

                // Extract program/version entries
                for (int i = 0; i < count && pos + 8 <= response.Length; i++)
                {
                    uint program = (uint)IPAddress.NetworkToHostOrder(BitConverter.ToInt32(response, pos));
                    pos += 4;

                    uint version = (uint)IPAddress.NetworkToHostOrder(BitConverter.ToInt32(response, pos));
                    pos += 4;

                    // If this is the portmapper program, add the version
                    if (program == PORTMAP_PROGRAM)
                    {
                        versions.Add((int)version);
                    }

                    // Skip the rest of the entry (netid, addr, owner strings)
                    // Each string is 4 bytes length + data (aligned to 4 bytes)
                    for (int j = 0; j < 3 && pos + 4 <= response.Length; j++)
                    {
                        int strLen = IPAddress.NetworkToHostOrder(BitConverter.ToInt32(response, pos));
                        pos += 4;

                        // Skip the string data (aligned to 4 bytes)
                        int alignedLen = (strLen + 3) & ~3; // Round up to multiple of 4
                        pos += alignedLen;

                        if (pos > response.Length) break;
                    }
                }

                // If no versions found via mapping entries, try to determine from the protocol
                if (versions.Count == 0)
                {
                    // If we got a successful DUMP response with version 2, add it
                    versions.Add(2);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Error extracting portmapper versions");
            }
        }

        private async Task<(bool anyVersionWorks, HashSet<int> workingVersions)> ProbeRpcVersions(
            string ipAddress, int port, int timeout, CancellationToken cancellationToken)
        {
            var result = (anyVersionWorks: false, workingVersions: new HashSet<int>());

            try
            {
                // Test RPC versions 2, 3, and 4 explicitly via both TCP and UDP
                bool v2Works = await ProbeRpcVersion(ipAddress, port, 2, timeout, cancellationToken);
                bool v3Works = await ProbeRpcVersion(ipAddress, port, 3, timeout, cancellationToken);
                bool v4Works = await ProbeRpcVersion(ipAddress, port, 4, timeout, cancellationToken);

                if (v2Works) result.workingVersions.Add(2);
                if (v3Works) result.workingVersions.Add(3);
                if (v4Works) result.workingVersions.Add(4);

                result.anyVersionWorks = result.workingVersions.Count > 0;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Error probing RPC versions");
            }

            return result;
        }

        private async Task<bool> ProbeRpcVersion(string ipAddress, int port, int version, int timeout, CancellationToken cancellationToken)
        {
            // Try TCP first
            bool tcpWorks = await ProbeRpcVersionTcp(ipAddress, port, version, timeout, cancellationToken);
            if (tcpWorks) return true;

            // If TCP fails, try UDP
            return await ProbeRpcVersionUdp(ipAddress, port, version, timeout, cancellationToken);
        }

        private async Task<bool> ProbeRpcVersionTcp(string ipAddress, int port, int version, int timeout, CancellationToken cancellationToken)
        {
            try
            {
                using var client = new TcpClient();

                // Set up timeout and connect
                using var cts = new CancellationTokenSource(timeout);
                using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cts.Token, cancellationToken);

                try
                {
                    await client.ConnectAsync(ipAddress, port, linkedCts.Token);
                }
                catch
                {
                    return false;
                }

                // Send NULL call and get response
                byte[] response = await SendRpcCallTcp(client, PORTMAP_PROGRAM, version, 0, null, timeout, linkedCts.Token);

                // Check if we got a valid response
                return IsValidRpcResponse(response);
            }
            catch
            {
                return false;
            }
        }

        private async Task<bool> ProbeRpcVersionUdp(string ipAddress, int port, int version, int timeout, CancellationToken cancellationToken)
        {
            try
            {
                using var client = new UdpClient();
                client.Client.SendTimeout = timeout;
                client.Client.ReceiveTimeout = timeout;

                // Connect to target
                client.Connect(ipAddress, port);

                // Create and send NULL call
                byte[] rpcCall = CreateRpcCall(PORTMAP_PROGRAM, version, 0, null);
                await client.SendAsync(rpcCall, rpcCall.Length);

                // Try to receive response
                IPEndPoint remoteEp = null;
                byte[] response = null;

                try
                {
                    // Wrap the synchronous receive in a Task
                    var receiveTask = Task.Run(() => {
                        try
                        {
                            remoteEp = new IPEndPoint(IPAddress.Any, 0);
                            return client.Receive(ref remoteEp);
                        }
                        catch
                        {
                            return null;
                        }
                    });

                    // Wait with timeout
                    var timeoutTask = Task.Delay(timeout, cancellationToken);
                    var completedTask = await Task.WhenAny(receiveTask, timeoutTask);

                    if (completedTask == receiveTask && !receiveTask.IsFaulted)
                    {
                        response = await receiveTask;
                    }
                }
                catch
                {
                    return false;
                }

                // Check if we got a valid response
                return IsValidRpcResponse(response);
            }
            catch
            {
                return false;
            }
        }

        private async Task<byte[]> SendRpcCallTcp(TcpClient client, int program, int version, int procedure, byte[] params_, int timeout, CancellationToken cancellationToken)
        {
            try
            {
                // Create RPC call
                byte[] rpcCall = CreateRpcCall(program, version, procedure, params_);

                // Add record marker for TCP
                byte[] recordMarker = new byte[4];
                int length = rpcCall.Length;
                recordMarker[0] = (byte)((length >> 24) | 0x80); // Last fragment bit
                recordMarker[1] = (byte)(length >> 16);
                recordMarker[2] = (byte)(length >> 8);
                recordMarker[3] = (byte)length;

                // Send call
                using var stream = client.GetStream();
                await stream.WriteAsync(recordMarker, 0, 4, cancellationToken);
                await stream.WriteAsync(rpcCall, 0, rpcCall.Length, cancellationToken);
                await stream.FlushAsync(cancellationToken);

                // Read response marker
                byte[] responseMarker = new byte[4];
                int bytesRead = await ReadWithTimeoutAsync(stream, responseMarker, 0, 4, timeout, cancellationToken);

                if (bytesRead != 4) return null;

                // Parse response length
                int respLength = ((responseMarker[0] & 0x7F) << 24) | (responseMarker[1] << 16) |
                                 (responseMarker[2] << 8) | responseMarker[3];

                if (respLength <= 0 || respLength > 8192) return null; // Sanity check

                // Read the response
                byte[] response = new byte[respLength];
                bytesRead = await ReadWithTimeoutAsync(stream, response, 0, respLength, timeout, cancellationToken);

                if (bytesRead != respLength) return null;

                return response;
            }
            catch
            {
                return null;
            }
        }

        private byte[] CreateRpcCall(int program, int version, int procedure, byte[] params_)
        {
            using var ms = new MemoryStream();
            using var writer = new BinaryWriter(ms);

            // Generate random XID
            int xid = new Random().Next();

            // Write RPC header (all values in network byte order)
            writer.Write(IPAddress.HostToNetworkOrder(xid));                // XID
            writer.Write(IPAddress.HostToNetworkOrder(RPC_CALL));           // Message type
            writer.Write(IPAddress.HostToNetworkOrder(RPC_VERSION));        // RPC version 
            writer.Write(IPAddress.HostToNetworkOrder(program));            // Program
            writer.Write(IPAddress.HostToNetworkOrder(version));            // Version
            writer.Write(IPAddress.HostToNetworkOrder(procedure));          // Procedure

            // Authentication (none)
            writer.Write(IPAddress.HostToNetworkOrder(0));                  // Flavor
            writer.Write(IPAddress.HostToNetworkOrder(0));                  // Length

            // Verifier (none)
            writer.Write(IPAddress.HostToNetworkOrder(0));                  // Flavor
            writer.Write(IPAddress.HostToNetworkOrder(0));                  // Length

            // Add parameters if provided
            if (params_ != null && params_.Length > 0)
            {
                writer.Write(params_);
            }

            return ms.ToArray();
        }

        private bool IsValidRpcResponse(byte[] response)
        {
            if (response == null || response.Length < 24) return false;

            try
            {
                // Check message type (should be 1 for REPLY)
                int messageType = IPAddress.NetworkToHostOrder(BitConverter.ToInt32(response, 4));
                if (messageType != RPC_REPLY) return false;

                // Check reply status (should be 0 for MSG_ACCEPTED)
                int replyStatus = IPAddress.NetworkToHostOrder(BitConverter.ToInt32(response, 8));

                // Even a rejected RPC call indicates the server understands RPC
                return true;
            }
            catch
            {
                return false;
            }
        }

        private async Task<int> ReadWithTimeoutAsync(Stream stream, byte[] buffer, int offset, int count, int timeout, CancellationToken cancellationToken)
        {
            // Create a task for reading
            var readTask = stream.ReadAsync(buffer, offset, count, cancellationToken);

            // Create a timeout task
            var timeoutTask = Task.Delay(timeout, cancellationToken);

            // Wait for either completion
            var completedTask = await Task.WhenAny(readTask, timeoutTask);

            // If read completed, return result, otherwise return 0
            if (completedTask == readTask)
            {
                return await readTask;
            }

            return 0;
        }

        private string FormatVersionRange(HashSet<int> versions)
        {
            if (versions.Count == 0) return "2"; // Default to v2 if nothing detected

            List<int> versionList = new List<int>(versions);
            versionList.Sort();

            if (versionList.Count == 1)
            {
                // Single version
                return versionList[0].ToString();
            }
            else if (versionList.Count > 1)
            {
                // Check if versions are continuous
                bool isContinuous = true;
                for (int i = 1; i < versionList.Count; i++)
                {
                    if (versionList[i] != versionList[i - 1] + 1)
                    {
                        isContinuous = false;
                        break;
                    }
                }

                if (isContinuous)
                {
                    // Format as range
                    return $"{versionList[0]}-{versionList[versionList.Count - 1]}";
                }
                else
                {
                    // Format as comma-separated
                    return string.Join(",", versionList);
                }
            }

            return "2"; // Default fallback
        }

        private async Task TryBannerGrab(PortScanResult result, int timeout, CancellationToken cancellationToken)
        {
            try
            {
                string banner = await BannerGrabber.GrabBannerAsync(
                    result.IPAddress,
                    result.Port,
                    timeout,
                    cancellationToken);

                if (string.IsNullOrEmpty(banner))
                {
                    // Try with commands
                    byte[] trigger = Encoding.ASCII.GetBytes("VERSION\r\n");
                    banner = await BannerGrabber.GrabBannerWithTriggerAsync(
                        result.IPAddress,
                        result.Port,
                        trigger,
                        timeout,
                        cancellationToken);
                }

                if (!string.IsNullOrEmpty(banner))
                {
                    // For port 111
                    if (result.Port == 111)
                    {
                        result.Service = "rpcbind";

                        // Try to parse version from banner
                        if (banner.Contains("version 2") || banner.Contains("v2"))
                        {
                            result.Version = $"2 (RPC #{PORTMAP_PROGRAM})";
                        }
                        else
                        {
                            // Just use a safe default
                            result.Version = $"2 (RPC #{PORTMAP_PROGRAM})";
                        }
                    }
                    else
                    {
                        result.Service = "RPC";
                        result.Version = banner.Split('\n')[0].Trim();
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Banner grab error");
            }
        }
    }
}