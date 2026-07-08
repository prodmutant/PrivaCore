using System;
using System.Collections.Generic;
using System.Linq;
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
    public class ExecDetector : IServiceDetector
    {
        private readonly ILogger<ExecDetector> _logger;

        public ExecDetector(ILogger<ExecDetector> logger)
        {
            _logger = logger;
        }

        public string ServiceName => "exec";

        public int[] CommonPorts => new[] { 512 };

        public int Priority => 50;

        public bool CanDetect(int port, PortScanResult initialScan)
        {
            // Check if it's a common exec port
            bool isCommonPort = Array.IndexOf(CommonPorts, port) >= 0;

            // Check if initial scan already suggests exec service
            bool isExecService = initialScan.Service?.Contains("exec", StringComparison.OrdinalIgnoreCase) == true ||
                                initialScan.Service?.Contains("rexec", StringComparison.OrdinalIgnoreCase) == true;

            return isCommonPort || isExecService;
        }

        public async Task<PortScanResult> DetectAsync(
            PortScanResult result,
            int timeout = 5000,
            CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation($"Exec service detection on {result.IPAddress}:{result.Port}");

                using (var client = new TcpClient())
                {
                    // Connect with timeout using our cancellation token
                    var connectTask = client.ConnectAsync(result.IPAddress, result.Port);
                    if (await Task.WhenAny(connectTask, Task.Delay(timeout, cancellationToken)) != connectTask)
                    {
                        result.Service = "exec";
                        result.Version = "Connection timed out";
                        return result;
                    }

                    using (var stream = client.GetStream())
                    {
                        stream.ReadTimeout = timeout;
                        stream.WriteTimeout = timeout;

                        // Send a null port and a null username as probe
                        // The exec protocol expects: port, username, password, command
                        byte[] probe = new byte[] { 0, 0, 0, 0, 0, 0, 0 };
                        await stream.WriteAsync(probe, 0, probe.Length, cancellationToken);

                        // Try to read response
                        byte[] buffer = new byte[1024];

                        try
                        {
                            int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);

                            if (bytesRead > 0)
                            {
                                // We got a response, likely an exec service
                                result.Service = "exec";
                                result.Version = "Berkeley r-commands exec service";

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
                                result.Service = "exec";
                                result.Version = "Berkeley r-commands exec service (no response)";
                            }
                        }
                        catch (IOException)
                        {
                            // Server closed connection, could still be exec service
                            result.Service = "exec";
                            result.Version = "Berkeley r-commands exec service (connection reset)";
                        }
                    }
                }
            }
            catch (OperationCanceledException)
            {
                result.Service = "exec";
                result.Version = "Detection cancelled";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Exec detection error on {result.IPAddress}:{result.Port}");
                result.Service = "exec";
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
                result.Service = "exec";
                result.Version = $"Berkeley r-commands exec service: {BannerGrabber.GetFirstLine(banner)}";
            }
        }
    }
}