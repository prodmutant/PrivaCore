using System;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.ServiceDetection.Models;

namespace PROSCANNERCONT.ServiceDetection.Detectors
{
    public class X11Detector : IServiceDetector
    {
        private readonly ILogger<X11Detector> _logger;

        public X11Detector(ILogger<X11Detector> logger) => _logger = logger;

        public string ServiceName => "x11";
        public int[] CommonPorts => new[] { 6000, 6001, 6002 }; // Common X11 ports

        public int Priority => 1;

        public bool CanDetect(int port, PortScanResult initialScan)
        {
            return Array.Exists(CommonPorts, p => p == port) ||
                   initialScan.Service?.Equals("x11", StringComparison.OrdinalIgnoreCase) == true;
        }

        public async Task<PortScanResult> DetectAsync(
            PortScanResult result,
            int timeout = 5000,
            CancellationToken cancellationToken = default)
        {
            try
            {
                using var client = new TcpClient();
                var connectTask = client.ConnectAsync(result.IPAddress, result.Port);

                if (await Task.WhenAny(connectTask, Task.Delay(timeout, cancellationToken)) != connectTask)
                    return result;

                using var stream = client.GetStream();
                stream.ReadTimeout = stream.WriteTimeout = timeout;

                // X11 connection setup request:
                // [byte order (1 byte)][unused (1)][major version (2)][minor version (2)][auth proto len (2)][auth data len (2)][2 bytes padding]
                var setupRequest = new byte[12];

                // Send byte order 'B' (big endian) or 'l' (little endian)
                // 'l' (0x6C) seems to work better on most systems
                setupRequest[0] = 0x6C; // 'l'

                // Unused byte
                setupRequest[1] = 0x00;

                // Protocol major version = 11 (big endian)
                setupRequest[2] = 0x00;
                setupRequest[3] = 0x0B;

                // Protocol minor version = 0
                setupRequest[4] = 0x00;
                setupRequest[5] = 0x00;

                // Authorization protocol name length = 0 (no auth)
                setupRequest[6] = 0x00;
                setupRequest[7] = 0x00;

                // Authorization data length = 0
                setupRequest[8] = 0x00;
                setupRequest[9] = 0x00;

                // Padding bytes
                setupRequest[10] = 0x00;
                setupRequest[11] = 0x00;

                await stream.WriteAsync(setupRequest, 0, setupRequest.Length, cancellationToken);

                // The server response is at least 8 bytes long:
                // byte 0 = status (1 = success, 0 = failure)
                // bytes 2-3 = major version
                // bytes 4-5 = minor version
                var response = new byte[8];
                int bytesRead = await stream.ReadAsync(response, 0, response.Length, cancellationToken);

                if (bytesRead < 8)
                {
                    // Not enough data - assume failure
                    return result;
                }

                if (response[0] != 1)
                {
                    // 1 means success - if not, then failure
                    return result;
                }

                // Major version (big endian)
                int majorVersion = (response[2] << 8) | response[3];
                int minorVersion = (response[4] << 8) | response[5];

                result.Service = "x11";
                result.Version = $"Protocol {majorVersion}.{minorVersion}";

                return result;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogError(ex, $"X11 detection failed for {result.IPAddress}:{result.Port}");
            }

            return result;
        }
    }
}
