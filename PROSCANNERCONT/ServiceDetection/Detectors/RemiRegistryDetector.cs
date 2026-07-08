using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Logging;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.ServiceDetection.Utils;
using PROSCANNERCONT.ServiceDetection.Models;
using System.IO;
using System.Net;

namespace PROSCANNERCONT.ServiceDetection.Detectors
{
    public class RmiRegistryDetector : IServiceDetector
    {
        private readonly ILogger<RmiRegistryDetector> _logger;

        public RmiRegistryDetector(ILogger<RmiRegistryDetector> logger)
        {
            _logger = logger;
        }

        public string ServiceName => "rmiregistry";

        public int[] CommonPorts => new[] { 1099 };

        public int Priority => 50;

        public bool CanDetect(int port, PortScanResult initialScan)
        {
            // Check if it's a common RMI registry port
            bool isCommonPort = Array.IndexOf(CommonPorts, port) >= 0;

            // Check if initial scan already suggests RMI registry service
            bool isRmiService = initialScan.Service?.Contains("rmi", StringComparison.OrdinalIgnoreCase) == true ||
                              initialScan.Service?.Contains("java", StringComparison.OrdinalIgnoreCase) == true;

            return isCommonPort || isRmiService;
        }

        public async Task<PortScanResult> DetectAsync(
            PortScanResult result,
            int timeout = 5000,
            CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation($"RMI Registry service detection on {result.IPAddress}:{result.Port}");

                using (var client = new TcpClient())
                {
                    // Connect with timeout using our cancellation token
                    var connectTask = client.ConnectAsync(result.IPAddress, result.Port);
                    if (await Task.WhenAny(connectTask, Task.Delay(timeout, cancellationToken)) != connectTask)
                    {
                        result.Service = "rmiregistry";
                        result.Version = "Connection timed out";
                        return result;
                    }

                    using (var stream = client.GetStream())
                    {
                        stream.ReadTimeout = timeout;
                        stream.WriteTimeout = timeout;

                        // RMI protocol starts with JRMI header
                        // Send RMI protocol handshake byte (magic header)
                        byte[] probe = new byte[] { 0x4a, 0x52, 0x4d, 0x49 }; // "JRMI"
                        await stream.WriteAsync(probe, 0, probe.Length, cancellationToken);

                        // Add RMI protocol version (typically 0x00 0x02 for JDK 1.2+)
                        byte[] versionBytes = new byte[] { 0x00, 0x02 };
                        await stream.WriteAsync(versionBytes, 0, versionBytes.Length, cancellationToken);

                        // Try to read response
                        byte[] buffer = new byte[1024];

                        try
                        {
                            int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);

                            if (bytesRead > 0)
                            {
                                // We got a response, likely an RMI service
                                result.Service = "rmiregistry";

                                // Check for Java RMI specific bytes in response
                                if (bytesRead >= 4 && buffer[0] == 0x4E && buffer[1] == 0x00)
                                {
                                    // Response starts with N\0 - likely a Java RMI registry
                                    result.Version = "Java RMI Registry";
                                }
                                else
                                {
                                    result.Version = "Java RMI Registry (custom protocol)";
                                }

                                // Extract version info if possible
                                if (bytesRead > 6)
                                {
                                    // Try to find version bytes which commonly follow after protocol header
                                    result.Version += $" (Protocol: {buffer[4]}.{buffer[5]})";
                                }
                            }
                            else
                            {
                                // Zero bytes read, but connection succeeded
                                result.Service = "rmiregistry";
                                result.Version = "Java RMI Registry (no response)";
                            }
                        }
                        catch (IOException)
                        {
                            // Server closed connection after our probe
                            // Still likely to be RMI service
                            result.Service = "rmiregistry";
                            result.Version = "Java RMI Registry (connection reset)";
                        }
                    }
                }
            }
            catch (OperationCanceledException)
            {
                result.Service = "rmiregistry";
                result.Version = "Detection cancelled";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"RMI Registry detection error on {result.IPAddress}:{result.Port}");
                result.Service = "rmiregistry";
                result.Version = "Detection failed";

                // Try basic banner grabbing as fallback
                try
                {
                    await PerformBannerGrabbing(result, timeout, cancellationToken);
                }
                catch
                {
                    // Ignore fallback errors
                }
            }

            return result;
        }

        private async Task PerformBannerGrabbing(PortScanResult result, int timeout, CancellationToken cancellationToken)
        {
            // Try to grab banner for additional information
            string banner = await BannerGrabber.GrabBannerAsync(
                result.IPAddress,
                result.Port,
                timeout,
                cancellationToken);

            if (!string.IsNullOrEmpty(banner))
            {
                result.Service = "rmiregistry";
                result.Version = $"Java RMI Registry: {BannerGrabber.GetFirstLine(banner)}";
            }
        }
    }
}