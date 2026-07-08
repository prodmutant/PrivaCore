using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.ServiceDetection.Utils;
using PROSCANNERCONT.ServiceDetection.Models;
using System.IO;
using System.Net;

namespace PROSCANNERCONT.ServiceDetection.Detectors
{
    public class NfsDetector : IServiceDetector
    {
        private readonly ILogger<NfsDetector> _logger;

        public NfsDetector(ILogger<NfsDetector> logger) => _logger = logger;

        public string ServiceName => "nfs";
        public int[] CommonPorts => new[] { 2049 };

        // Increase priority to ensure it runs before RPC detector
        public int Priority => 1; // Higher priority to override RPC detectors

        public bool CanDetect(int port, PortScanResult initialScan)
        {
            // Force detection on port 2049 regardless of prior results
            if (CommonPorts.Contains(port))
                return true;

            return initialScan.Service?.Equals("nfs", StringComparison.OrdinalIgnoreCase) == true ||
                   initialScan.Service?.Equals("rpc", StringComparison.OrdinalIgnoreCase) == true;
        }

        public async Task<PortScanResult> DetectAsync(
            PortScanResult result,
            int timeout = 5000,
            CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation($"NFS detection on {result.IPAddress}:{result.Port}");

                // Always force NFS for port 2049 before any further checks
                if (CommonPorts.Contains(result.Port))
                {
                    // This should override any previously detected service
                    result.Service = "nfs";

                    // Try to get actual version, but default to a meaningful value
                    result.Version = await DetectNfsVersionAsync(result.IPAddress, result.Port, timeout, cancellationToken)
                                    ?? "v3/v4";

                    // Return immediately to prevent any other detectors from overriding
                    return result;
                }

                // For non-standard ports, proceed with detection
                string detectedVersion = await DetectNfsVersionAsync(result.IPAddress, result.Port, timeout, cancellationToken);
                if (detectedVersion != null)
                {
                    result.Service = "nfs";
                    result.Version = detectedVersion;
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogError(ex, $"NFS detection failed for {result.IPAddress}:{result.Port}");
            }

            return result;
        }

        private async Task<string> DetectNfsVersionAsync(string ipAddress, int port, int timeout, CancellationToken cancellationToken)
        {
            try
            {
                using var client = new TcpClient();
                var connectTask = client.ConnectAsync(ipAddress, port);

                if (await Task.WhenAny(connectTask, Task.Delay(timeout, cancellationToken)) != connectTask)
                    return null;

                using var stream = client.GetStream();
                stream.ReadTimeout = stream.WriteTimeout = timeout;

                // NFSv3 RPC Probe
                await stream.WriteAsync(CreateRpcCallHeader(), cancellationToken);

                try
                {
                    byte[] buffer = new byte[1024];
                    int bytesRead = await stream.ReadAsync(buffer, cancellationToken);

                    if (bytesRead < 24) return "unknown";

                    // Extract NFS version from response
                    int version = buffer.Length > 24 ? buffer[24] : 0;
                    return version switch
                    {
                        3 => "v3",
                        4 => "v4",
                        _ => "unknown"
                    };
                }
                catch (IOException)
                {
                    return "unknown";
                }
            }
            catch
            {
                return null;
            }
        }

        private byte[] CreateRpcCallHeader()
        {
            using var ms = new MemoryStream();
            using var bw = new BinaryWriter(ms);

            bw.Write(IPAddress.HostToNetworkOrder(new Random().Next())); // XID
            bw.Write(IPAddress.HostToNetworkOrder(0)); // Message Type: Call
            bw.Write(IPAddress.HostToNetworkOrder(2)); // RPC Version
            bw.Write(IPAddress.HostToNetworkOrder(100003)); // NFS Program
            bw.Write(IPAddress.HostToNetworkOrder(3)); // NFSv3
            bw.Write(IPAddress.HostToNetworkOrder(0)); // Null Procedure
            bw.Write(new byte[8]); // Auth + Verifier

            return ms.ToArray();
        }
    }
}