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

namespace PROSCANNERCONT.ServiceDetection.Detectors
{
    public class IngresLockDetector : IServiceDetector
    {
        private readonly ILogger<IngresLockDetector> _logger;

        public IngresLockDetector(ILogger<IngresLockDetector> logger)
        {
            _logger = logger;
        }

        public string ServiceName => "ingreslock";

        public int[] CommonPorts => new[] { 1524 };

        public int Priority => 50;

        public bool CanDetect(int port, PortScanResult initialScan)
        {
            // Check if it's a common Ingres Lock port
            bool isCommonPort = Array.IndexOf(CommonPorts, port) >= 0;

            // Check if initial scan already suggests Ingres Lock service
            bool isIngresLockService = initialScan.Service?.Contains("ingres", StringComparison.OrdinalIgnoreCase) == true ||
                                     initialScan.Service?.Contains("lock", StringComparison.OrdinalIgnoreCase) == true;

            return isCommonPort || isIngresLockService;
        }

        public async Task<PortScanResult> DetectAsync(
            PortScanResult result,
            int timeout = 5000,
            CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation($"Ingres Lock service detection on {result.IPAddress}:{result.Port}");

                using (var client = new TcpClient())
                {
                    // Connect with timeout using our cancellation token
                    var connectTask = client.ConnectAsync(result.IPAddress, result.Port);
                    if (await Task.WhenAny(connectTask, Task.Delay(timeout, cancellationToken)) != connectTask)
                    {
                        result.Service = "ingreslock";
                        result.Version = "Connection timed out";
                        return result;
                    }

                    using (var stream = client.GetStream())
                    {
                        stream.ReadTimeout = timeout;
                        stream.WriteTimeout = timeout;

                        // Try a simple handshake probe - send a version request
                        byte[] probe = Encoding.ASCII.GetBytes("VERSION\r\n");
                        await stream.WriteAsync(probe, 0, probe.Length, cancellationToken);

                        // Try to read response
                        byte[] buffer = new byte[1024];

                        try
                        {
                            int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);

                            if (bytesRead > 0)
                            {
                                // We got a response, likely an Ingres Lock service
                                result.Service = "ingreslock";

                                // Try to extract any meaningful data from the response
                                string response = Encoding.ASCII.GetString(buffer, 0, bytesRead)
                                    .Replace("\0", "\\0")
                                    .Replace("\r", "\\r")
                                    .Replace("\n", "\\n");

                                if (!string.IsNullOrWhiteSpace(response))
                                {
                                    // See if we can find a version in the response
                                    if (response.Contains("Version", StringComparison.OrdinalIgnoreCase) ||
                                        response.Contains("Ingres", StringComparison.OrdinalIgnoreCase))
                                    {
                                        result.Version = BannerGrabber.GetFirstLine(response);
                                    }
                                    else
                                    {
                                        result.Version = $"Ingres Lock: {BannerGrabber.GetFirstLine(response)}";
                                    }
                                }
                                else
                                {
                                    result.Version = "Ingres Lock Service";
                                }
                            }
                            else
                            {
                                // Try a different approach, common with Ingres servers
                                // Some older Ingres servers wait for credentials
                                probe = Encoding.ASCII.GetBytes("CONNECT\r\n");
                                await stream.WriteAsync(probe, 0, probe.Length, cancellationToken);

                                bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);

                                if (bytesRead > 0)
                                {
                                    result.Service = "ingreslock";
                                    string response = Encoding.ASCII.GetString(buffer, 0, bytesRead);
                                    result.Version = $"Ingres Lock: {BannerGrabber.GetFirstLine(response)}";
                                }
                                else
                                {
                                    // Zero bytes read, but connection succeeded
                                    result.Service = "ingreslock";
                                    result.Version = "Ingres Lock Service (no response)";
                                }
                            }
                        }
                        catch (IOException)
                        {
                            // Server closed connection
                            // Still likely to be ingreslock service
                            result.Service = "ingreslock";
                            result.Version = "Ingres Lock Service (connection reset)";
                        }
                    }
                }
            }
            catch (OperationCanceledException)
            {
                result.Service = "ingreslock";
                result.Version = "Detection cancelled";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Ingres Lock detection error on {result.IPAddress}:{result.Port}");
                result.Service = "ingreslock";
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
                result.Service = "ingreslock";
                result.Version = $"Ingres Lock Service: {BannerGrabber.GetFirstLine(banner)}";
            }
        }
    }
}