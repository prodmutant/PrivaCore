using System;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.ServiceDetection.Models;

namespace PROSCANNERCONT.ServiceDetection.Detectors
{
    public class VncDetector : IServiceDetector
    {
        private readonly ILogger<VncDetector> _logger;

        public VncDetector(ILogger<VncDetector> logger) => _logger = logger;

        public string ServiceName => "vnc";

        // Default VNC ports: 5900 (display 0) to 5905 (display 5)
        public int[] CommonPorts => new[] { 5900, 5901, 5902, 5903, 5904, 5905 };

        public int Priority => 1;

        public bool CanDetect(int port, PortScanResult initialScan)
        {
            if (CommonPorts.Contains(port))
                return true;

            return initialScan.Service?.Equals("vnc", StringComparison.OrdinalIgnoreCase) == true;
        }

        public async Task<PortScanResult> DetectAsync(
            PortScanResult result,
            int timeout = 5000,
            CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation($"VNC detection on {result.IPAddress}:{result.Port}");

                using var client = new TcpClient();
                var connectTask = client.ConnectAsync(result.IPAddress, result.Port);

                if (await Task.WhenAny(connectTask, Task.Delay(timeout, cancellationToken)) != connectTask)
                    return result; // Timeout

                using var stream = client.GetStream();
                stream.ReadTimeout = timeout;
                stream.WriteTimeout = timeout;

                // VNC servers send a version string immediately after connection
                byte[] buffer = new byte[12]; // e.g. "RFB 003.003\n"
                int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);

                if (bytesRead <= 0)
                    return result;

                string banner = Encoding.ASCII.GetString(buffer, 0, bytesRead).Trim('\r', '\n', '\0');

                if (banner.StartsWith("RFB"))
                {
                    result.Service = "vnc";
                    result.Version = banner; // Example: "RFB 003.003"
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogError(ex, $"VNC detection failed for {result.IPAddress}:{result.Port}");
            }

            return result;
        }
    }
}
