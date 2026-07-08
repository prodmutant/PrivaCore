using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.PortScanProtocols
{
    public class TcpAckScanner : IPortScanner
    {
        public bool RequiresElevatedPrivileges => true;
        public string ScannerName => "TCP ACK Scan (-sA)";

        private const int IP_HEADER_LENGTH = 20;
        private const int TCP_HEADER_LENGTH = 20;

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
                using (var socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP))
                {
                    socket.Bind(new IPEndPoint(IPAddress.Any, 0));
                    socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);

                    byte[] packet = CreateAckPacket(ipAddress, port);
                    var endpoint = new IPEndPoint(IPAddress.Parse(ipAddress), port);

                    await socket.SendToAsync(packet, SocketFlags.None, endpoint);

                    byte[] receiveBuffer = new byte[256];
                    var receiveTask = socket.ReceiveAsync(receiveBuffer, SocketFlags.None);

                    if (await Task.WhenAny(receiveTask, Task.Delay(timeout, cancellationToken)) == receiveTask)
                    {
                        var bytesRead = await receiveTask;
                        result.Status = AnalyzeResponse(receiveBuffer, bytesRead);
                    }
                    else
                    {
                        result.Status = "Filtered";
                    }
                }
            }
            catch (Exception)
            {
                result.Status = "Error";
            }

            // ACK scan doesn't determine if ports are open, only if they're unfiltered
            result.IsOpen = false;
            return result;
        }

        private byte[] CreateAckPacket(string destIp, int destPort)
        {
            byte[] packet = new byte[IP_HEADER_LENGTH + TCP_HEADER_LENGTH];

            // IP Header
            packet[0] = 0x45; // Version 4, Length 5 words
            packet[1] = 0x00; // DSCP/ECN
            BitConverter.GetBytes((short)(packet.Length)).CopyTo(packet, 2);
            packet[6] = 0x40; // Don't Fragment
            packet[8] = 64;   // TTL
            packet[9] = 0x06; // Protocol (TCP)

            // Source IP (random private IP)
            var rnd = new Random();
            byte[] sourceIp = new byte[] { 10, (byte)rnd.Next(1, 254), (byte)rnd.Next(1, 254), (byte)rnd.Next(1, 254) };
            Array.Copy(sourceIp, 0, packet, 12, 4);

            // Destination IP
            byte[] destIpBytes = IPAddress.Parse(destIp).GetAddressBytes();
            Array.Copy(destIpBytes, 0, packet, 16, 4);

            // TCP Header
            var srcPort = (ushort)rnd.Next(49152, 65535);
            BitConverter.GetBytes(srcPort).CopyTo(packet, IP_HEADER_LENGTH);
            BitConverter.GetBytes((ushort)destPort).CopyTo(packet, IP_HEADER_LENGTH + 2);

            // Sequence Number
            BitConverter.GetBytes(rnd.Next()).CopyTo(packet, IP_HEADER_LENGTH + 4);

            // ACK flag and a random ACK number
            packet[IP_HEADER_LENGTH + 13] = 0x10; // ACK flag
            BitConverter.GetBytes(rnd.Next()).CopyTo(packet, IP_HEADER_LENGTH + 8); // Random ACK number

            // Window Size
            BitConverter.GetBytes((ushort)8192).CopyTo(packet, IP_HEADER_LENGTH + 14);

            CalculateChecksum(packet);
            return packet;
        }

        private string AnalyzeResponse(byte[] buffer, int bytesReceived)
        {
            if (bytesReceived < IP_HEADER_LENGTH + TCP_HEADER_LENGTH)
                return "Error";

            byte flags = buffer[IP_HEADER_LENGTH + 13];
            bool rstSet = (flags & 0x04) != 0;

            // For ACK scan:
            // RST response = unfiltered
            // No response or ICMP unreachable = filtered
            return rstSet ? "Unfiltered" : "Filtered";
        }

        private void CalculateChecksum(byte[] packet)
        {
            ushort checksum = 0;
            for (int i = 0; i < IP_HEADER_LENGTH; i += 2)
            {
                if (i != 10) // Skip checksum field
                    checksum += BitConverter.ToUInt16(packet, i);
            }
            checksum = (ushort)~((checksum & 0xFFFF) + (checksum >> 16));
            BitConverter.GetBytes(checksum).CopyTo(packet, 10);
        }
    }
}