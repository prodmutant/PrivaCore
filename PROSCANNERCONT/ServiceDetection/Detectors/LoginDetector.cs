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
    public class LoginDetector : IServiceDetector
    {
        private readonly ILogger<LoginDetector> _logger;

        public LoginDetector(ILogger<LoginDetector> logger)
        {
            _logger = logger;
        }

        public string ServiceName => "login";

        public int[] CommonPorts => new[] { 513 };

        public int Priority => 50;

        public bool CanDetect(int port, PortScanResult initialScan)
        {
            // Check if it's a common login port
            bool isCommonPort = Array.IndexOf(CommonPorts, port) >= 0;

            // Check if initial scan already suggests login service
            bool isLoginService = initialScan.Service?.Contains("login", StringComparison.OrdinalIgnoreCase) == true ||
                                initialScan.Service?.Contains("rlogin", StringComparison.OrdinalIgnoreCase) == true;

            return isCommonPort || isLoginService;
        }

        public async Task<PortScanResult> DetectAsync(
            PortScanResult result,
            int timeout = 5000,
            CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation($"Login service detection on {result.IPAddress}:{result.Port}");

                using (var client = new TcpClient())
                {
                    // Connect with timeout using our cancellation token
                    var connectTask = client.ConnectAsync(result.IPAddress, result.Port);
                    if (await Task.WhenAny(connectTask, Task.Delay(timeout, cancellationToken)) != connectTask)
                    {
                        result.Service = "login";
                        result.Version = "Connection timed out";
                        return result;
                    }

                    using (var stream = client.GetStream())
                    {
                        stream.ReadTimeout = timeout;
                        stream.WriteTimeout = timeout;

                        // rlogin protocol typically expects a null byte followed by username, 
                        // then another null byte, then the client username, then null byte, and terminal type
                        byte[] probe = Encoding.ASCII.GetBytes("\0guest\0guest\0xterm/38400\0");
                        await stream.WriteAsync(probe, 0, probe.Length, cancellationToken);

                        // Try to read response - usually login banner or prompt
                        byte[] buffer = new byte[1024];

                        try
                        {
                            int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);

                            if (bytesRead > 0)
                            {
                                // We got a response, likely a login service
                                result.Service = "login";
                                result.Version = "Berkeley r-commands login service";

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
                                result.Service = "login";
                                result.Version = "Berkeley r-commands login service (no response)";
                            }
                        }
                        catch (IOException)
                        {
                            // Server may close connection after authentication failure
                            // Still likely to be login service
                            result.Service = "login";
                            result.Version = "Berkeley r-commands login service (connection reset)";
                        }
                    }
                }
            }
            catch (OperationCanceledException)
            {
                result.Service = "login";
                result.Version = "Detection cancelled";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Login detection error on {result.IPAddress}:{result.Port}");
                result.Service = "login";
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
                result.Service = "login";
                result.Version = $"Berkeley r-commands login service: {BannerGrabber.GetFirstLine(banner)}";
            }
        }
    }
}