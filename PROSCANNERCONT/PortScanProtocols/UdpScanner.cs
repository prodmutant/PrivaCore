// PortScanProtocols/UdpScanner.cs
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using System.Linq;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.PortScanProtocols
{
    public class UdpScanner : IPortScanner
    {
        public bool RequiresElevatedPrivileges => true;
        public string ScannerName => "UDP Scan (-sU)";

        private readonly Dictionary<int, byte[]> _commonPayloads;

        public UdpScanner()
        {
            _commonPayloads = new Dictionary<int, byte[]>
            {
                { 53, Dns.GetHostName().Select(c => (byte)c).ToArray() },  // DNS
                { 161, new byte[] { 0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6C, 0x69, 0x63 } },  // SNMP
                { 137, new byte[] { 0x80, 0x94, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },  // NetBIOS
                { 67, new byte[] { 0x01, 0x01, 0x06, 0x00 } },  // DHCP
                { 123, new byte[] { 0x1B, 0x00, 0x00, 0x00 } }  // NTP
            };
        }

        public async Task<PortScanResult> ScanPortAsync(string ipAddress, int port, int timeout, CancellationToken cancellationToken)
        {
            var result = new PortScanResult
            {
                IPAddress = ipAddress,
                Port = port,
                Protocol = "UDP",
                Status = "Unknown",
                Service = "Unknown",
                Version = "",
                IsOpen = false
            };
            var serviceInfo = ServiceDetection.GetService(port);
            result.Service = serviceInfo.Name;
            result.Protocol = serviceInfo.Protocol;


            using (var udpClient = new UdpClient())
            {
                try
                {
                    udpClient.Client.ReceiveTimeout = timeout;
                    udpClient.Client.SendTimeout = timeout;

                    // Bind to a random local port
                    udpClient.Client.Bind(new IPEndPoint(IPAddress.Any, 0));

                    // Get appropriate payload for the port or use default
                    byte[] payload = _commonPayloads.ContainsKey(port)
                        ? _commonPayloads[port]
                        : new byte[] { 0x0 };

                    // Send the probe
                    await udpClient.SendAsync(payload, payload.Length, ipAddress, port);

                    try
                    {
                        // Try to receive a response
                        var receiveTask = udpClient.ReceiveAsync();

                        if (await Task.WhenAny(receiveTask, Task.Delay(timeout, cancellationToken)) == receiveTask)
                        {
                            var response = await receiveTask;
                            result.Status = "Open";
                            result.IsOpen = true;

                            // Try to determine service from response
                            if (response.Buffer.Length > 0)
                            {
                                try
                                {
                                    result.Version = System.Text.Encoding.ASCII.GetString(response.Buffer)
                                        .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                                        .FirstOrDefault()?.Trim() ?? "";
                                }
                                catch
                                {
                                    // If we can't parse the response, just ignore it
                                }
                            }
                        }
                        else
                        {
                            result.Status = "Open|Filtered";
                        }
                    }
                    catch (SocketException ex)
                    {
                        switch (ex.SocketErrorCode)
                        {
                            case SocketError.ConnectionReset:
                                result.Status = "Closed";
                                break;
                            case SocketError.TimedOut:
                                result.Status = "Open|Filtered";
                                break;
                            default:
                                result.Status = "Filtered";
                                break;
                        }
                    }
                }
                catch (Exception)
                {
                    result.Status = "Error";
                }
                finally
                {
                    try
                    {
                        udpClient.Close();
                    }
                    catch { }
                }
            }

            return result;
        }
    }
}