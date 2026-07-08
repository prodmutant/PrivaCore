using System;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.PortScanProtocols
{
    public class TcpConnectScanner : IPortScanner
    {
        public bool RequiresElevatedPrivileges => false;
        public string ScannerName => "TCP Connect Scan (-sT)";

        public async Task<PortScanResult> ScanPortAsync(string ipAddress, int port, int timeout, CancellationToken cancellationToken)
        {
            var result = new PortScanResult
            {
                IPAddress = ipAddress,
                Port = port,
                Status = "Unknown"
            };

            // Get service information using ServiceDetection
            var serviceInfo = ServiceDetection.GetService(port);
            result.Service = serviceInfo.Name;
            result.Protocol = serviceInfo.Protocol;

            try
            {
                using (var client = new TcpClient())
                {
                    var connectTask = client.ConnectAsync(ipAddress, port);
                    if (await Task.WhenAny(connectTask, Task.Delay(timeout, cancellationToken)) == connectTask)
                    {
                        result.Status = client.Connected ? "Open" : "Closed";
                        result.IsOpen = client.Connected;

                        if (client.Connected)
                        {
                            await TryGetBanner(client, result, timeout);
                        }
                    }
                    else
                    {
                        result.Status = "Filtered";
                    }
                }
            }
            catch (SocketException ex)
            {
                result.Status = HandleSocketException(ex);
            }
            catch (Exception)
            {
                result.Status = "Error";
            }

            return result;
        }

        private async Task TryGetBanner(TcpClient client, PortScanResult result, int timeout)
        {
            try
            {
                using (var stream = client.GetStream())
                {
                    stream.ReadTimeout = timeout;
                    byte[] buffer = new byte[256];
                    var readTask = stream.ReadAsync(buffer, 0, buffer.Length);
                    if (await Task.WhenAny(readTask, Task.Delay(timeout)) == readTask)
                    {
                        var bytesRead = await readTask;
                        if (bytesRead > 0)
                        {
                            result.Version = System.Text.Encoding.ASCII.GetString(buffer, 0, bytesRead)
                                .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                                .FirstOrDefault()?.Trim() ?? "";
                        }
                    }
                }
            }
            catch
            {
                // Ignore banner grab errors
            }
        }

        private string HandleSocketException(SocketException ex)
        {
            return ex.SocketErrorCode switch
            {
                SocketError.ConnectionRefused => "Closed",
                SocketError.TimedOut => "Filtered",
                SocketError.AccessDenied => "Filtered",
                _ => "Error"
            };
        }
    }
}