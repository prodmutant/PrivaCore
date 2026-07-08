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
    public class ShellDetector : IServiceDetector
    {
        private readonly ILogger<ShellDetector> _logger;

        public ShellDetector(ILogger<ShellDetector> logger)
        {
            _logger = logger;
        }

        public string ServiceName => "shell";

        public int[] CommonPorts => new[] { 514 };

        public int Priority => 50;

        public bool CanDetect(int port, PortScanResult initialScan)
        {
            // Check if it's a common shell port
            bool isCommonPort = Array.IndexOf(CommonPorts, port) >= 0;

            // Check if initial scan already suggests shell service
            bool isShellService = initialScan.Service?.Contains("shell", StringComparison.OrdinalIgnoreCase) == true ||
                                 initialScan.Service?.Contains("rsh", StringComparison.OrdinalIgnoreCase) == true;

            return isCommonPort || isShellService;
        }

        public async Task<PortScanResult> DetectAsync(
            PortScanResult result,
            int timeout = 5000,
            CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation($"Shell service detection on {result.IPAddress}:{result.Port}");

                using (var client = new TcpClient())
                {
                    // Connect with timeout using our cancellation token
                    var connectTask = client.ConnectAsync(result.IPAddress, result.Port);
                    if (await Task.WhenAny(connectTask, Task.Delay(timeout, cancellationToken)) != connectTask)
                    {
                        result.Service = "shell";
                        result.Version = "Connection timed out";
                        return result;
                    }

                    using (var stream = client.GetStream())
                    {
                        stream.ReadTimeout = timeout;
                        stream.WriteTimeout = timeout;

                        // rsh protocol expects: client port, client user, server user, command
                        // a simple innocuous probe that shouldn't execute harmful commands
                        byte[] probe = Encoding.ASCII.GetBytes("0\0guest\0guest\0echo\0");
                        await stream.WriteAsync(probe, 0, probe.Length, cancellationToken);

                        // Try to read response
                        byte[] buffer = new byte[1024];

                        try
                        {
                            int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);

                            if (bytesRead > 0)
                            {
                                // We got a response, likely a shell service
                                result.Service = "shell";
                                result.Version = "Berkeley r-commands shell service";

                                // Try to extract any meaningful data from the response
                                string response = Encoding.ASCII.GetString(buffer, 0, bytesRead)
                                    .Replace("\0", "\\0")
                                    .Replace("\r", "\\r")
                                    .Replace("\n", "\\n");

                                if (!string.IsNullOrWhiteSpace(response))
                                {
                                    result.Version += $": {BannerGrabber.GetFirstLine(response)}";
                                }
                            }
                            else
                            {
                                // Zero bytes read, but connection succeeded
                                result.Service = "shell";
                                result.Version = "Berkeley r-commands shell service (no response)";
                            }
                        }
                        catch (IOException)
                        {
                            // Server closed connection after auth failure or for other reasons
                            // Still likely to be shell service
                            result.Service = "shell";
                            result.Version = "Berkeley r-commands shell service (connection reset)";
                        }
                    }
                }
            }
            catch (OperationCanceledException)
            {
                result.Service = "shell";
                result.Version = "Detection cancelled";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Shell detection error on {result.IPAddress}:{result.Port}");
                result.Service = "shell";
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
                result.Service = "shell";
                result.Version = $"Berkeley r-commands shell service: {BannerGrabber.GetFirstLine(banner)}";
            }
        }
    }
}