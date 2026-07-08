using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Threading.Tasks;
using System.Threading;
using System.Net;
using System.Linq;

namespace PROSCANNERCONT.Views
{
    public class PortScanner
    {
        public static async Task<List<int>> TCPSYNScan(string ip, int[] ports, int timeout, CancellationToken cancellationToken)
        {
            var openPorts = new List<int>();
            foreach (int port in ports)
            {
                if (cancellationToken.IsCancellationRequested)
                    break;

                using (var client = new TcpClient())
                {
                    try
                    {
                        var connectTask = client.ConnectAsync(ip, port);
                        if (await Task.WhenAny(connectTask, Task.Delay(timeout, cancellationToken)) == connectTask)
                        {
                            openPorts.Add(port);
                        }
                    }
                    catch { }
                    finally
                    {
                        client.Close();
                    }
                }
            }
            return openPorts;
        }

        public static async Task<List<int>> UDPScan(string ip, int[] ports, int timeout, CancellationToken cancellationToken)
        {
            var openPorts = new List<int>();
            var tasks = new List<Task<int?>>();

            // Common UDP service payload data
            var payloads = new Dictionary<int, byte[]>
            {
                { 53, Dns.GetHostName().Select(c => (byte)c).ToArray() },  // DNS
                { 161, new byte[] { 0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6C, 0x69, 0x63 } },  // SNMP
                { 137, new byte[] { 0x80, 0x94, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },  // NetBIOS
                { 67, new byte[] { 0x01, 0x01, 0x06, 0x00 } },  // DHCP
                { 123, new byte[] { 0x1B, 0x00, 0x00, 0x00 } }  // NTP
            };

            foreach (int port in ports)
            {
                if (cancellationToken.IsCancellationRequested)
                    break;

                tasks.Add(ScanUdpPort(ip, port, timeout, payloads.ContainsKey(port) ? payloads[port] : new byte[] { 0x0 }, cancellationToken));
            }

            var results = await Task.WhenAll(tasks);

            foreach (var port in results.Where(p => p.HasValue).Select(p => p.Value))
            {
                openPorts.Add(port);
            }

            return openPorts;
        }

        private static async Task<int?> ScanUdpPort(string ip, int port, int timeout, byte[] payload, CancellationToken cancellationToken)
        {
            using (var udpClient = new UdpClient())
            {
                try
                {
                    udpClient.Client.ReceiveTimeout = timeout;
                    udpClient.Client.SendTimeout = timeout;

                    // Bind to a random local port
                    udpClient.Client.Bind(new IPEndPoint(IPAddress.Any, 0));

                    // Send the probe
                    await udpClient.SendAsync(payload, payload.Length, ip, port);

                    // Create an endpoint to receive the response
                    var remoteEP = new IPEndPoint(IPAddress.Any, 0);

                    // Try to receive a response
                    var receiveTask = Task.Run(async () =>
                    {
                        try
                        {
                            var result = await udpClient.ReceiveAsync();
                            return true;
                        }
                        catch (SocketException ex)
                        {
                            
                          

                            if (ex.SocketErrorCode == SocketError.ConnectionReset)
                                return true;

                            if (ex.SocketErrorCode == SocketError.ConnectionRefused || ex.SocketErrorCode == SocketError.NetworkUnreachable)
                                return false;


                                return true;
                        }
                    });
                    if (await Task.WhenAny(receiveTask, Task.Delay(timeout, cancellationToken)) == receiveTask)
                    {
                        var result = await receiveTask;
                        if (result)
                            return port;
                    }
                    else
                    {
                        return port;
                    }
                }
                catch (OperationCanceledException)
                {
                    // Handle cancellation
                    return null;
                }
                catch (Exception)
                {
                    // For other exceptions, assume the port is closed
                    return null;
                }
                finally
                {
                    udpClient.Close();
                }
            }

            return null;
        }
    }
}