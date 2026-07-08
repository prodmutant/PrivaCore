using System.Net.Sockets;
using System.Net;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.PortScanProtocols
{
    public class TcpXmasScanner : IPortScanner
    {
        public bool RequiresElevatedPrivileges => true;
        public string ScannerName => "TCP XMAS Scan (-sX)";

        public async Task<PortScanResult> ScanPortAsync(string ipAddress, int port, int timeout, CancellationToken cancellationToken)
        {
            var result = new PortScanResult
            {
                IPAddress = ipAddress,
                Port = port,
                Protocol = "TCP",
                Status = "Unknown"
            };
            var serviceInfo = ServiceDetection.GetService(port);
            result.Service = serviceInfo.Name;
            result.Protocol = serviceInfo.Protocol;


            using (var socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP))
            {
                try
                {
                    byte[] packet = CreateXmasPacket(ipAddress, port);
                    await socket.SendToAsync(packet, SocketFlags.None, new IPEndPoint(IPAddress.Parse(ipAddress), port));

                    byte[] receiveBuffer = new byte[256];
                    var receiveTask = socket.ReceiveAsync(receiveBuffer, SocketFlags.None);

                    if (await Task.WhenAny(receiveTask, Task.Delay(timeout, cancellationToken)) == receiveTask)
                    {
                        result.Status = "Closed";
                    }
                    else
                    {
                        result.Status = "Open|Filtered";
                    }
                }
                catch (SocketException)
                {
                    result.Status = "Filtered";
                }
            }

            return result;
        }

        private byte[] CreateXmasPacket(string destIp, int destPort)
        {
            byte[] packet = new byte[40];
            packet[13] = 0x29; // FIN, PSH, URG flags
            return packet;
        }
    }
}