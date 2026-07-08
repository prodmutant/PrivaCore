using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using PacketDotNet;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Services
{
    /// <summary>
    /// Deep packet inspection and protocol analysis service
    /// </summary>
    public class ProtocolAnalyzerService
    {
        #region Singleton

        private static readonly Lazy<ProtocolAnalyzerService> _instance =
            new Lazy<ProtocolAnalyzerService>(() => new ProtocolAnalyzerService());

        public static ProtocolAnalyzerService Instance => _instance.Value;

        #endregion

        #region Port Mappings

        private readonly Dictionary<int, ApplicationProtocol> _portToProtocol = new Dictionary<int, ApplicationProtocol>
        {
            { 20, ApplicationProtocol.FTP },
            { 21, ApplicationProtocol.FTP },
            { 22, ApplicationProtocol.SSH },
            { 23, ApplicationProtocol.Telnet },
            { 25, ApplicationProtocol.SMTP },
            { 53, ApplicationProtocol.DNS },
            { 67, ApplicationProtocol.DHCP },
            { 68, ApplicationProtocol.DHCP },
            { 69, ApplicationProtocol.Unknown }, // TFTP
            { 80, ApplicationProtocol.HTTP },
            { 110, ApplicationProtocol.POP3 },
            { 119, ApplicationProtocol.Unknown }, // NNTP
            { 123, ApplicationProtocol.NTP },
            { 143, ApplicationProtocol.IMAP },
            { 161, ApplicationProtocol.SNMP },
            { 162, ApplicationProtocol.SNMP },
            { 389, ApplicationProtocol.LDAP },
            { 443, ApplicationProtocol.HTTPS },
            { 445, ApplicationProtocol.SMB },
            { 465, ApplicationProtocol.SMTPS },
            { 514, ApplicationProtocol.Unknown }, // Syslog
            { 587, ApplicationProtocol.SMTP },
            { 636, ApplicationProtocol.LDAP },
            { 993, ApplicationProtocol.IMAP },
            { 995, ApplicationProtocol.POP3 },
            { 1433, ApplicationProtocol.MSSQL },
            { 1521, ApplicationProtocol.Unknown }, // Oracle
            { 1883, ApplicationProtocol.MQTT },
            { 3306, ApplicationProtocol.MySQL },
            { 3389, ApplicationProtocol.RDP },
            { 5432, ApplicationProtocol.PostgreSQL },
            { 5672, ApplicationProtocol.Unknown }, // AMQP
            { 5900, ApplicationProtocol.VNC },
            { 5901, ApplicationProtocol.VNC },
            { 6379, ApplicationProtocol.Redis },
            { 8080, ApplicationProtocol.HTTP },
            { 8443, ApplicationProtocol.HTTPS },
            { 9200, ApplicationProtocol.Unknown }, // Elasticsearch
            { 11211, ApplicationProtocol.Memcached },
            { 27017, ApplicationProtocol.MongoDB },
        };

        private readonly Dictionary<int, string> _portToServiceName = new Dictionary<int, string>
        {
            { 20, "FTP Data" },
            { 21, "FTP Control" },
            { 22, "SSH" },
            { 23, "Telnet" },
            { 25, "SMTP" },
            { 53, "DNS" },
            { 67, "DHCP Server" },
            { 68, "DHCP Client" },
            { 69, "TFTP" },
            { 80, "HTTP" },
            { 110, "POP3" },
            { 119, "NNTP" },
            { 123, "NTP" },
            { 137, "NetBIOS Name" },
            { 138, "NetBIOS Datagram" },
            { 139, "NetBIOS Session" },
            { 143, "IMAP" },
            { 161, "SNMP" },
            { 162, "SNMP Trap" },
            { 389, "LDAP" },
            { 443, "HTTPS" },
            { 445, "SMB" },
            { 465, "SMTPS" },
            { 514, "Syslog" },
            { 587, "SMTP Submission" },
            { 636, "LDAPS" },
            { 993, "IMAPS" },
            { 995, "POP3S" },
            { 1433, "MS SQL" },
            { 1521, "Oracle" },
            { 1883, "MQTT" },
            { 3306, "MySQL" },
            { 3389, "RDP" },
            { 5432, "PostgreSQL" },
            { 5672, "AMQP" },
            { 5900, "VNC" },
            { 6379, "Redis" },
            { 8080, "HTTP Proxy" },
            { 8443, "HTTPS Alt" },
            { 9200, "Elasticsearch" },
            { 11211, "Memcached" },
            { 27017, "MongoDB" },
        };

        #endregion

        #region Main Analysis Method

        public EnhancedPacketInfo AnalyzePacket(Packet packet, byte[] rawData, int packetNumber, DateTime captureStartTime)
        {
            var info = new EnhancedPacketInfo
            {
                PacketNumber = packetNumber,
                Timestamp = DateTime.Now,
                RelativeTime = (DateTime.Now - captureStartTime).TotalSeconds,
                RawPacket = rawData,
                Length = rawData?.Length ?? 0,
                ThreatLevel = ThreatLevel.None
            };

            try
            {
                AnalyzeLayers(packet, info);
                DetermineApplicationProtocol(info);
                AnalyzePayload(packet, info);
                GenerateConversationId(info);
                DetectThreats(info);
            }
            catch (Exception ex)
            {
                info.Info = $"Analysis error: {ex.Message}";
            }

            return info;
        }

        #endregion

        #region Layer Analysis

        private void AnalyzeLayers(Packet packet, EnhancedPacketInfo info)
        {
            if (packet == null) return;

            // Ethernet Layer
            if (packet is EthernetPacket ethPacket)
            {
                var layer = new ProtocolLayer
                {
                    Name = "Ethernet",
                    HeaderOffset = 0,
                    HeaderLength = 14,
                    DisplayFields = new List<ProtocolField>
                    {
                        new ProtocolField { Name = "Source MAC", Value = ethPacket.SourceHardwareAddress?.ToString() ?? "Unknown", IsImportant = true },
                        new ProtocolField { Name = "Destination MAC", Value = ethPacket.DestinationHardwareAddress?.ToString() ?? "Unknown", IsImportant = true },
                        new ProtocolField { Name = "Type", Value = ethPacket.Type.ToString() }
                    }
                };
                info.Layers.Add(layer);
                info.SourceMac = ethPacket.SourceHardwareAddress?.ToString();
                info.DestinationMac = ethPacket.DestinationHardwareAddress?.ToString();

                AnalyzeIPPacket(ethPacket.PayloadPacket as IPPacket, info, 14);
            }
        }

        private void AnalyzeIPPacket(IPPacket ipPacket, EnhancedPacketInfo info, int offset)
        {
            if (ipPacket == null) return;

            if (ipPacket is IPv4Packet ipv4)
            {
                var layer = new ProtocolLayer
                {
                    Name = "IPv4",
                    HeaderOffset = offset,
                    HeaderLength = ipv4.HeaderLength,
                    DisplayFields = new List<ProtocolField>
                    {
                        new ProtocolField { Name = "Version", Value = "4" },
                        new ProtocolField { Name = "Header Length", Value = $"{ipv4.HeaderLength} bytes" },
                        new ProtocolField { Name = "Total Length", Value = $"{ipv4.TotalLength} bytes" },
                        new ProtocolField { Name = "Identification", Value = $"0x{ipv4.Id:X4}" },
                        new ProtocolField { Name = "TTL", Value = ipv4.TimeToLive.ToString(), IsImportant = true },
                        new ProtocolField { Name = "Protocol", Value = ipv4.Protocol.ToString(), IsImportant = true },
                        new ProtocolField { Name = "Source", Value = ipv4.SourceAddress?.ToString() ?? "Unknown", IsImportant = true },
                        new ProtocolField { Name = "Destination", Value = ipv4.DestinationAddress?.ToString() ?? "Unknown", IsImportant = true },
                        new ProtocolField { Name = "Checksum", Value = $"0x{ipv4.Checksum:X4}" },
                        new ProtocolField { Name = "Don't Fragment", Value = ipv4.FragmentFlags.ToString() }
                    }
                };
                info.Layers.Add(layer);
                info.SourceIP = ipv4.SourceAddress?.ToString();
                info.DestinationIP = ipv4.DestinationAddress?.ToString();
                info.Protocol = ipv4.Protocol.ToString();
                info.PayloadLength = ipv4.PayloadLength;

                AnalyzeTransportLayer(ipv4.PayloadPacket, info, offset + ipv4.HeaderLength);
            }
            else if (ipPacket is IPv6Packet ipv6)
            {
                var layer = new ProtocolLayer
                {
                    Name = "IPv6",
                    HeaderOffset = offset,
                    HeaderLength = 40,
                    DisplayFields = new List<ProtocolField>
                    {
                        new ProtocolField { Name = "Version", Value = "6" },
                        new ProtocolField { Name = "Traffic Class", Value = ipv6.TrafficClass.ToString() },
                        new ProtocolField { Name = "Flow Label", Value = ipv6.FlowLabel.ToString() },
                        new ProtocolField { Name = "Payload Length", Value = $"{ipv6.PayloadLength} bytes" },
                        new ProtocolField { Name = "Next Header", Value = ipv6.Protocol.ToString(), IsImportant = true },
                        new ProtocolField { Name = "Hop Limit", Value = ipv6.HopLimit.ToString(), IsImportant = true },
                        new ProtocolField { Name = "Source", Value = ipv6.SourceAddress?.ToString() ?? "Unknown", IsImportant = true },
                        new ProtocolField { Name = "Destination", Value = ipv6.DestinationAddress?.ToString() ?? "Unknown", IsImportant = true }
                    }
                };
                info.Layers.Add(layer);
                info.SourceIP = ipv6.SourceAddress?.ToString();
                info.DestinationIP = ipv6.DestinationAddress?.ToString();
                info.Protocol = ipv6.Protocol.ToString();
                info.PayloadLength = ipv6.PayloadLength;

                AnalyzeTransportLayer(ipv6.PayloadPacket, info, offset + 40);
            }
        }

        private void AnalyzeTransportLayer(Packet transportPacket, EnhancedPacketInfo info, int offset)
        {
            if (transportPacket == null) return;

            if (transportPacket is TcpPacket tcp)
            {
                AnalyzeTcpPacket(tcp, info, offset);
            }
            else if (transportPacket is UdpPacket udp)
            {
                AnalyzeUdpPacket(udp, info, offset);
            }
            else if (transportPacket is IcmpV4Packet icmp4)
            {
                AnalyzeIcmpPacket(icmp4, info, offset);
            }
            else if (transportPacket is IcmpV6Packet icmp6)
            {
                AnalyzeIcmpV6Packet(icmp6, info, offset);
            }
        }

        private void AnalyzeTcpPacket(TcpPacket tcp, EnhancedPacketInfo info, int offset)
        {
            info.Protocol = "TCP";
            info.SourcePort = tcp.SourcePort;
            info.DestinationPort = tcp.DestinationPort;
            info.SequenceNumber = tcp.SequenceNumber;
            info.AcknowledgmentNumber = tcp.AcknowledgmentNumber;
            info.WindowSize = tcp.WindowSize;

            info.TcpFlags = new TcpFlags
            {
                SYN = tcp.Synchronize,
                ACK = tcp.Acknowledgment,
                FIN = tcp.Finished,
                RST = tcp.Reset,
                PSH = tcp.Push,
                URG = tcp.Urgent,
                ECE = tcp.ExplicitCongestionNotificationEcho,
                CWR = tcp.CongestionWindowReduced
            };

            var layer = new ProtocolLayer
            {
                Name = "TCP",
                HeaderOffset = offset,
                HeaderLength = tcp.DataOffset * 4,
                PayloadOffset = offset + tcp.DataOffset * 4,
                PayloadLength = tcp.PayloadData?.Length ?? 0,
                DisplayFields = new List<ProtocolField>
                {
                    new ProtocolField { Name = "Source Port", Value = tcp.SourcePort.ToString(), IsImportant = true },
                    new ProtocolField { Name = "Destination Port", Value = tcp.DestinationPort.ToString(), IsImportant = true },
                    new ProtocolField { Name = "Sequence Number", Value = tcp.SequenceNumber.ToString(), IsImportant = true },
                    new ProtocolField { Name = "Acknowledgment Number", Value = tcp.AcknowledgmentNumber.ToString() },
                    new ProtocolField { Name = "Header Length", Value = $"{tcp.DataOffset * 4} bytes" },
                    new ProtocolField { Name = "Flags", Value = info.TcpFlags.ToString(), IsImportant = true },
                    new ProtocolField { Name = "Window Size", Value = tcp.WindowSize.ToString() },
                    new ProtocolField { Name = "Checksum", Value = $"0x{tcp.Checksum:X4}" },
                    new ProtocolField { Name = "Urgent Pointer", Value = tcp.UrgentPointer.ToString() }
                }
            };
            info.Layers.Add(layer);

            // Build info string
            var infoBuilder = new StringBuilder();
            infoBuilder.Append($"{tcp.SourcePort} → {tcp.DestinationPort} ");
            infoBuilder.Append(info.TcpFlags.ToShortString());
            infoBuilder.Append($" Seq={tcp.SequenceNumber}");
            if (tcp.Acknowledgment)
                infoBuilder.Append($" Ack={tcp.AcknowledgmentNumber}");
            infoBuilder.Append($" Win={tcp.WindowSize}");
            if (tcp.PayloadData?.Length > 0)
                infoBuilder.Append($" Len={tcp.PayloadData.Length}");

            info.Info = infoBuilder.ToString();
        }

        private void AnalyzeUdpPacket(UdpPacket udp, EnhancedPacketInfo info, int offset)
        {
            info.Protocol = "UDP";
            info.SourcePort = udp.SourcePort;
            info.DestinationPort = udp.DestinationPort;

            var layer = new ProtocolLayer
            {
                Name = "UDP",
                HeaderOffset = offset,
                HeaderLength = 8,
                PayloadOffset = offset + 8,
                PayloadLength = udp.PayloadData?.Length ?? 0,
                DisplayFields = new List<ProtocolField>
                {
                    new ProtocolField { Name = "Source Port", Value = udp.SourcePort.ToString(), IsImportant = true },
                    new ProtocolField { Name = "Destination Port", Value = udp.DestinationPort.ToString(), IsImportant = true },
                    new ProtocolField { Name = "Length", Value = $"{udp.Length} bytes" },
                    new ProtocolField { Name = "Checksum", Value = $"0x{udp.Checksum:X4}" }
                }
            };
            info.Layers.Add(layer);

            info.Info = $"{udp.SourcePort} → {udp.DestinationPort} Len={udp.Length}";
        }

        private void AnalyzeIcmpPacket(IcmpV4Packet icmp, EnhancedPacketInfo info, int offset)
        {
            info.Protocol = "ICMP";

            string typeDesc = GetIcmpTypeDescription(icmp.TypeCode);

            var layer = new ProtocolLayer
            {
                Name = "ICMP",
                HeaderOffset = offset,
                HeaderLength = 8,
                DisplayFields = new List<ProtocolField>
                {
                    new ProtocolField { Name = "Type", Value = $"{(int)icmp.TypeCode} ({typeDesc})", IsImportant = true },
                    new ProtocolField { Name = "Code", Value = icmp.TypeCode.ToString() },
                    new ProtocolField { Name = "Checksum", Value = $"0x{icmp.Checksum:X4}" },
                    new ProtocolField { Name = "Identifier", Value = icmp.Id.ToString() },
                    new ProtocolField { Name = "Sequence", Value = icmp.Sequence.ToString() }
                }
            };
            info.Layers.Add(layer);

            info.Info = $"{typeDesc} id={icmp.Id} seq={icmp.Sequence}";
        }

        private void AnalyzeIcmpV6Packet(IcmpV6Packet icmp6, EnhancedPacketInfo info, int offset)
        {
            info.Protocol = "ICMPv6";

            var layer = new ProtocolLayer
            {
                Name = "ICMPv6",
                HeaderOffset = offset,
                HeaderLength = 8,
                DisplayFields = new List<ProtocolField>
                {
                    new ProtocolField { Name = "Type", Value = icmp6.Type.ToString(), IsImportant = true },
                    new ProtocolField { Name = "Code", Value = icmp6.Code.ToString() },
                    new ProtocolField { Name = "Checksum", Value = $"0x{icmp6.Checksum:X4}" }
                }
            };
            info.Layers.Add(layer);

            info.Info = $"ICMPv6 Type={icmp6.Type} Code={icmp6.Code}";
        }

        private string GetIcmpTypeDescription(IcmpV4TypeCode typeCode)
        {
            int type = (int)typeCode >> 8;
            return type switch
            {
                0 => "Echo Reply",
                3 => "Destination Unreachable",
                4 => "Source Quench",
                5 => "Redirect",
                8 => "Echo Request",
                9 => "Router Advertisement",
                10 => "Router Solicitation",
                11 => "Time Exceeded",
                12 => "Parameter Problem",
                13 => "Timestamp Request",
                14 => "Timestamp Reply",
                _ => $"Type {type}"
            };
        }

        #endregion

        #region Application Protocol Detection

        private void DetermineApplicationProtocol(EnhancedPacketInfo info)
        {
            // Check by port first
            if (_portToProtocol.TryGetValue(info.DestinationPort, out var destProto))
            {
                info.AppProtocol = destProto;
            }
            else if (_portToProtocol.TryGetValue(info.SourcePort, out var srcProto))
            {
                info.AppProtocol = srcProto;
            }
            else
            {
                info.AppProtocol = ApplicationProtocol.Unknown;
            }
        }

        #endregion

        #region Payload Analysis

        private void AnalyzePayload(Packet packet, EnhancedPacketInfo info)
        {
            byte[] payload = null;

            // Get payload from TCP or UDP
            if (packet is EthernetPacket eth)
            {
                if (eth.PayloadPacket is IPPacket ip)
                {
                    if (ip.PayloadPacket is TcpPacket tcp)
                    {
                        payload = tcp.PayloadData;
                    }
                    else if (ip.PayloadPacket is UdpPacket udp)
                    {
                        payload = udp.PayloadData;
                    }
                }
            }

            if (payload == null || payload.Length == 0) return;

            // Analyze based on detected or suspected protocol
            switch (info.AppProtocol)
            {
                case ApplicationProtocol.HTTP:
                    AnalyzeHttpPayload(payload, info);
                    break;
                case ApplicationProtocol.DNS:
                    AnalyzeDnsPayload(payload, info);
                    break;
                case ApplicationProtocol.HTTPS:
                    AnalyzeTlsPayload(payload, info);
                    break;
                default:
                    // Try to detect protocol from payload content
                    DetectProtocolFromPayload(payload, info);
                    break;
            }
        }

        private void AnalyzeHttpPayload(byte[] payload, EnhancedPacketInfo info)
        {
            try
            {
                string content = Encoding.ASCII.GetString(payload);
                info.HttpData = new HttpInfo();

                // Check if request or response
                if (content.StartsWith("GET ") || content.StartsWith("POST ") ||
                    content.StartsWith("PUT ") || content.StartsWith("DELETE ") ||
                    content.StartsWith("HEAD ") || content.StartsWith("OPTIONS ") ||
                    content.StartsWith("PATCH ") || content.StartsWith("CONNECT "))
                {
                    info.HttpData.IsRequest = true;
                    ParseHttpRequest(content, info.HttpData);
                    info.Info = $"HTTP {info.HttpData.Method} {info.HttpData.Uri}";
                }
                else if (content.StartsWith("HTTP/"))
                {
                    info.HttpData.IsRequest = false;
                    ParseHttpResponse(content, info.HttpData);
                    info.Info = $"HTTP {info.HttpData.StatusCode} {info.HttpData.StatusText}";
                }

                // Add HTTP layer
                var layer = new ProtocolLayer
                {
                    Name = "HTTP",
                    DisplayFields = new List<ProtocolField>()
                };

                if (info.HttpData.IsRequest)
                {
                    layer.DisplayFields.Add(new ProtocolField { Name = "Method", Value = info.HttpData.Method, IsImportant = true });
                    layer.DisplayFields.Add(new ProtocolField { Name = "URI", Value = info.HttpData.Uri, IsImportant = true });
                    layer.DisplayFields.Add(new ProtocolField { Name = "Host", Value = info.HttpData.Host });
                    layer.DisplayFields.Add(new ProtocolField { Name = "User-Agent", Value = info.HttpData.UserAgent });
                }
                else
                {
                    layer.DisplayFields.Add(new ProtocolField { Name = "Status Code", Value = info.HttpData.StatusCode.ToString(), IsImportant = true });
                    layer.DisplayFields.Add(new ProtocolField { Name = "Status Text", Value = info.HttpData.StatusText, IsImportant = true });
                    layer.DisplayFields.Add(new ProtocolField { Name = "Content-Type", Value = info.HttpData.ContentType });
                    layer.DisplayFields.Add(new ProtocolField { Name = "Content-Length", Value = info.HttpData.ContentLength.ToString() });
                }

                info.Layers.Add(layer);
                info.AppProtocol = ApplicationProtocol.HTTP;
            }
            catch
            {
                // Not valid HTTP
            }
        }

        private void ParseHttpRequest(string content, HttpInfo httpInfo)
        {
            var lines = content.Split(new[] { "\r\n" }, StringSplitOptions.None);
            if (lines.Length == 0) return;

            // Parse request line
            var requestLine = lines[0].Split(' ');
            if (requestLine.Length >= 2)
            {
                httpInfo.Method = requestLine[0];
                httpInfo.Uri = requestLine[1];
                if (requestLine.Length >= 3)
                    httpInfo.HttpVersion = requestLine[2].Replace("HTTP/", "");
            }

            // Parse headers
            for (int i = 1; i < lines.Length; i++)
            {
                if (string.IsNullOrEmpty(lines[i])) break;

                var colonIndex = lines[i].IndexOf(':');
                if (colonIndex > 0)
                {
                    var headerName = lines[i].Substring(0, colonIndex).Trim();
                    var headerValue = lines[i].Substring(colonIndex + 1).Trim();
                    httpInfo.Headers[headerName] = headerValue;

                    switch (headerName.ToLowerInvariant())
                    {
                        case "host":
                            httpInfo.Host = headerValue;
                            break;
                        case "user-agent":
                            httpInfo.UserAgent = headerValue;
                            break;
                        case "content-type":
                            httpInfo.ContentType = headerValue;
                            break;
                        case "content-length":
                            if (long.TryParse(headerValue, out var len))
                                httpInfo.ContentLength = len;
                            break;
                        case "referer":
                            httpInfo.Referer = headerValue;
                            break;
                    }
                }
            }
        }

        private void ParseHttpResponse(string content, HttpInfo httpInfo)
        {
            var lines = content.Split(new[] { "\r\n" }, StringSplitOptions.None);
            if (lines.Length == 0) return;

            // Parse status line
            var statusLine = lines[0].Split(' ');
            if (statusLine.Length >= 2)
            {
                httpInfo.HttpVersion = statusLine[0].Replace("HTTP/", "");
                if (int.TryParse(statusLine[1], out var code))
                    httpInfo.StatusCode = code;
                if (statusLine.Length >= 3)
                    httpInfo.StatusText = string.Join(" ", statusLine.Skip(2));
            }

            // Parse headers
            for (int i = 1; i < lines.Length; i++)
            {
                if (string.IsNullOrEmpty(lines[i])) break;

                var colonIndex = lines[i].IndexOf(':');
                if (colonIndex > 0)
                {
                    var headerName = lines[i].Substring(0, colonIndex).Trim();
                    var headerValue = lines[i].Substring(colonIndex + 1).Trim();
                    httpInfo.Headers[headerName] = headerValue;

                    switch (headerName.ToLowerInvariant())
                    {
                        case "content-type":
                            httpInfo.ContentType = headerValue;
                            break;
                        case "content-length":
                            if (long.TryParse(headerValue, out var len))
                                httpInfo.ContentLength = len;
                            break;
                    }
                }
            }
        }

        private void AnalyzeDnsPayload(byte[] payload, EnhancedPacketInfo info)
        {
            if (payload.Length < 12) return;

            try
            {
                info.DnsData = new DnsInfo();

                // Parse DNS header
                info.DnsData.TransactionId = (ushort)((payload[0] << 8) | payload[1]);
                ushort flags = (ushort)((payload[2] << 8) | payload[3]);
                info.DnsData.IsQuery = (flags & 0x8000) == 0;
                info.DnsData.IsResponse = !info.DnsData.IsQuery;
                info.DnsData.OpCode = (DnsOpCode)((flags >> 11) & 0xF);
                info.DnsData.IsAuthoritative = (flags & 0x0400) != 0;
                info.DnsData.IsTruncated = (flags & 0x0200) != 0;
                info.DnsData.RecursionDesired = (flags & 0x0100) != 0;
                info.DnsData.RecursionAvailable = (flags & 0x0080) != 0;
                info.DnsData.ResponseCode = (DnsResponseCode)(flags & 0xF);

                ushort questionCount = (ushort)((payload[4] << 8) | payload[5]);
                ushort answerCount = (ushort)((payload[6] << 8) | payload[7]);

                // Parse questions
                int offset = 12;
                for (int i = 0; i < questionCount && offset < payload.Length; i++)
                {
                    var question = new DnsQuestion();
                    question.Name = ParseDnsName(payload, ref offset);
                    if (offset + 4 <= payload.Length)
                    {
                        question.Type = GetDnsRecordType((ushort)((payload[offset] << 8) | payload[offset + 1]));
                        question.Class = GetDnsClass((ushort)((payload[offset + 2] << 8) | payload[offset + 3]));
                        offset += 4;
                    }
                    info.DnsData.Questions.Add(question);
                }

                // Parse answers
                for (int i = 0; i < answerCount && offset < payload.Length; i++)
                {
                    var answer = new DnsResourceRecord();
                    answer.Name = ParseDnsName(payload, ref offset);
                    if (offset + 10 <= payload.Length)
                    {
                        answer.Type = GetDnsRecordType((ushort)((payload[offset] << 8) | payload[offset + 1]));
                        answer.Class = GetDnsClass((ushort)((payload[offset + 2] << 8) | payload[offset + 3]));
                        answer.TTL = (uint)((payload[offset + 4] << 24) | (payload[offset + 5] << 16) |
                                           (payload[offset + 6] << 8) | payload[offset + 7]);
                        ushort rdLength = (ushort)((payload[offset + 8] << 8) | payload[offset + 9]);
                        offset += 10;

                        if (answer.Type == "A" && rdLength == 4 && offset + 4 <= payload.Length)
                        {
                            answer.Data = $"{payload[offset]}.{payload[offset + 1]}.{payload[offset + 2]}.{payload[offset + 3]}";
                        }
                        else if (answer.Type == "AAAA" && rdLength == 16 && offset + 16 <= payload.Length)
                        {
                            var ipv6 = new IPAddress(payload.Skip(offset).Take(16).ToArray());
                            answer.Data = ipv6.ToString();
                        }
                        else if (answer.Type == "CNAME" || answer.Type == "NS" || answer.Type == "PTR")
                        {
                            int nameOffset = offset;
                            answer.Data = ParseDnsName(payload, ref nameOffset);
                        }
                        else
                        {
                            answer.Data = BitConverter.ToString(payload, offset, Math.Min(rdLength, payload.Length - offset));
                        }
                        offset += rdLength;
                    }
                    info.DnsData.Answers.Add(answer);
                }

                // Update info string
                info.Info = info.DnsData.Summary;
                info.AppProtocol = ApplicationProtocol.DNS;

                // Add DNS layer
                var layer = new ProtocolLayer
                {
                    Name = "DNS",
                    DisplayFields = new List<ProtocolField>
                    {
                        new ProtocolField { Name = "Transaction ID", Value = $"0x{info.DnsData.TransactionId:X4}", IsImportant = true },
                        new ProtocolField { Name = "Type", Value = info.DnsData.IsQuery ? "Query" : "Response", IsImportant = true },
                        new ProtocolField { Name = "Response Code", Value = info.DnsData.ResponseCode.ToString() }
                    }
                };

                foreach (var q in info.DnsData.Questions)
                {
                    layer.DisplayFields.Add(new ProtocolField
                    {
                        Name = "Query",
                        Value = $"{q.Name} ({q.Type})",
                        IsImportant = true
                    });
                }

                foreach (var a in info.DnsData.Answers)
                {
                    layer.DisplayFields.Add(new ProtocolField
                    {
                        Name = "Answer",
                        Value = $"{a.Name} → {a.Data} (TTL: {a.TTL})",
                        IsImportant = true
                    });
                }

                info.Layers.Add(layer);
            }
            catch
            {
                // Invalid DNS packet
            }
        }

        private string ParseDnsName(byte[] data, ref int offset)
        {
            var sb = new StringBuilder();
            int maxJumps = 10;
            int jumps = 0;
            int originalOffset = offset;
            bool jumped = false;

            while (offset < data.Length && jumps < maxJumps)
            {
                byte len = data[offset];

                if (len == 0)
                {
                    offset++;
                    break;
                }

                // Compression pointer
                if ((len & 0xC0) == 0xC0)
                {
                    if (!jumped)
                    {
                        originalOffset = offset + 2;
                        jumped = true;
                    }
                    offset = ((len & 0x3F) << 8) | data[offset + 1];
                    jumps++;
                    continue;
                }

                offset++;
                if (sb.Length > 0) sb.Append('.');

                for (int i = 0; i < len && offset < data.Length; i++)
                {
                    sb.Append((char)data[offset++]);
                }
            }

            if (jumped)
                offset = originalOffset;

            return sb.ToString();
        }

        private string GetDnsRecordType(ushort type)
        {
            return type switch
            {
                1 => "A",
                2 => "NS",
                5 => "CNAME",
                6 => "SOA",
                12 => "PTR",
                15 => "MX",
                16 => "TXT",
                28 => "AAAA",
                33 => "SRV",
                41 => "OPT",
                255 => "ANY",
                _ => $"Type{type}"
            };
        }

        private string GetDnsClass(ushort cls)
        {
            return cls switch
            {
                1 => "IN",
                3 => "CH",
                4 => "HS",
                255 => "ANY",
                _ => $"Class{cls}"
            };
        }

        private void AnalyzeTlsPayload(byte[] payload, EnhancedPacketInfo info)
        {
            if (payload.Length < 5) return;

            try
            {
                info.TlsData = new TlsInfo();

                byte contentType = payload[0];
                info.TlsData.ContentType = contentType switch
                {
                    20 => "Change Cipher Spec",
                    21 => "Alert",
                    22 => "Handshake",
                    23 => "Application Data",
                    _ => $"Unknown ({contentType})"
                };

                // Version
                ushort version = (ushort)((payload[1] << 8) | payload[2]);
                info.TlsData.Version = version switch
                {
                    0x0301 => "TLS 1.0",
                    0x0302 => "TLS 1.1",
                    0x0303 => "TLS 1.2",
                    0x0304 => "TLS 1.3",
                    0x0300 => "SSL 3.0",
                    _ => $"0x{version:X4}"
                };

                // If handshake, parse further
                if (contentType == 22 && payload.Length >= 6)
                {
                    byte handshakeType = payload[5];
                    info.TlsData.HandshakeType = handshakeType switch
                    {
                        0 => "HelloRequest",
                        1 => "ClientHello",
                        2 => "ServerHello",
                        4 => "NewSessionTicket",
                        11 => "Certificate",
                        12 => "ServerKeyExchange",
                        13 => "CertificateRequest",
                        14 => "ServerHelloDone",
                        15 => "CertificateVerify",
                        16 => "ClientKeyExchange",
                        20 => "Finished",
                        _ => $"Unknown ({handshakeType})"
                    };

                    // Extract SNI from ClientHello
                    if (handshakeType == 1)
                    {
                        ExtractSniFromClientHello(payload, info.TlsData);
                    }
                }

                info.TlsData.IsEncrypted = contentType == 23;
                info.Info = info.TlsData.Summary;
                info.AppProtocol = ApplicationProtocol.HTTPS;

                // Add TLS layer
                var layer = new ProtocolLayer
                {
                    Name = "TLS",
                    DisplayFields = new List<ProtocolField>
                    {
                        new ProtocolField { Name = "Content Type", Value = info.TlsData.ContentType, IsImportant = true },
                        new ProtocolField { Name = "Version", Value = info.TlsData.Version, IsImportant = true }
                    }
                };

                if (!string.IsNullOrEmpty(info.TlsData.HandshakeType))
                {
                    layer.DisplayFields.Add(new ProtocolField
                    {
                        Name = "Handshake Type",
                        Value = info.TlsData.HandshakeType,
                        IsImportant = true
                    });
                }

                if (!string.IsNullOrEmpty(info.TlsData.ServerName))
                {
                    layer.DisplayFields.Add(new ProtocolField
                    {
                        Name = "Server Name (SNI)",
                        Value = info.TlsData.ServerName,
                        IsImportant = true
                    });
                }

                info.Layers.Add(layer);
            }
            catch
            {
                // Invalid TLS packet
            }
        }

        private void ExtractSniFromClientHello(byte[] payload, TlsInfo tlsInfo)
        {
            try
            {
                // Skip to extensions in ClientHello
                // This is a simplified extraction
                int offset = 43; // Minimum offset to session ID length

                if (offset >= payload.Length) return;

                // Skip session ID
                byte sessionIdLen = payload[offset];
                offset += 1 + sessionIdLen;

                if (offset + 2 >= payload.Length) return;

                // Skip cipher suites
                ushort cipherSuitesLen = (ushort)((payload[offset] << 8) | payload[offset + 1]);
                offset += 2 + cipherSuitesLen;

                if (offset >= payload.Length) return;

                // Skip compression methods
                byte compMethodsLen = payload[offset];
                offset += 1 + compMethodsLen;

                if (offset + 2 >= payload.Length) return;

                // Extensions length
                ushort extensionsLen = (ushort)((payload[offset] << 8) | payload[offset + 1]);
                offset += 2;

                int extensionsEnd = offset + extensionsLen;

                // Parse extensions
                while (offset + 4 < extensionsEnd && offset + 4 < payload.Length)
                {
                    ushort extType = (ushort)((payload[offset] << 8) | payload[offset + 1]);
                    ushort extLen = (ushort)((payload[offset + 2] << 8) | payload[offset + 3]);
                    offset += 4;

                    // SNI extension (type 0)
                    if (extType == 0 && offset + extLen <= payload.Length && extLen > 5)
                    {
                        int sniOffset = offset + 5; // Skip SNI list length and name type
                        ushort nameLen = (ushort)((payload[offset + 3] << 8) | payload[offset + 4]);

                        if (sniOffset + nameLen <= payload.Length)
                        {
                            tlsInfo.ServerName = Encoding.ASCII.GetString(payload, sniOffset, nameLen);
                        }
                        break;
                    }

                    offset += extLen;
                }
            }
            catch
            {
                // Failed to extract SNI
            }
        }

        private void DetectProtocolFromPayload(byte[] payload, EnhancedPacketInfo info)
        {
            if (payload.Length < 4) return;

            try
            {
                // Check for HTTP
                string start = Encoding.ASCII.GetString(payload, 0, Math.Min(10, payload.Length));
                if (start.StartsWith("GET ") || start.StartsWith("POST ") ||
                    start.StartsWith("HTTP/") || start.StartsWith("PUT ") ||
                    start.StartsWith("HEAD ") || start.StartsWith("DELETE "))
                {
                    AnalyzeHttpPayload(payload, info);
                    return;
                }

                // Check for TLS
                if (payload[0] >= 20 && payload[0] <= 23 &&
                    payload[1] == 3 && payload[2] <= 4)
                {
                    AnalyzeTlsPayload(payload, info);
                    return;
                }

                // Check for SSH
                if (start.StartsWith("SSH-"))
                {
                    info.AppProtocol = ApplicationProtocol.SSH;
                    info.Info = start.Split('\n')[0].Trim();
                    return;
                }

                // Check for SMTP
                if (start.StartsWith("220 ") || start.StartsWith("EHLO ") ||
                    start.StartsWith("HELO ") || start.StartsWith("MAIL FROM"))
                {
                    info.AppProtocol = ApplicationProtocol.SMTP;
                    info.Info = start.Split('\n')[0].Trim();
                    return;
                }

                // Check for FTP
                if (Regex.IsMatch(start, @"^(220|USER|PASS|QUIT|LIST|RETR|STOR|PWD|CWD)\s", RegexOptions.IgnoreCase))
                {
                    info.AppProtocol = ApplicationProtocol.FTP;
                    info.Info = start.Split('\n')[0].Trim();
                    return;
                }
            }
            catch
            {
                // Failed to detect protocol
            }
        }

        #endregion

        #region Conversation ID Generation

        private void GenerateConversationId(EnhancedPacketInfo info)
        {
            // Create a bidirectional conversation ID
            var endpoints = new[]
            {
                $"{info.SourceIP}:{info.SourcePort}",
                $"{info.DestinationIP}:{info.DestinationPort}"
            };
            Array.Sort(endpoints);
            info.ConversationId = $"{info.Protocol}_{endpoints[0]}_{endpoints[1]}";
        }

        #endregion

        #region Threat Detection

        private void DetectThreats(EnhancedPacketInfo info)
        {
            var threats = new List<string>();

            // Port scan detection (SYN without ACK to many ports)
            if (info.TcpFlags?.SYN == true && info.TcpFlags?.ACK == false)
            {
                // This would need context from other packets for proper detection
                // Just flag as informational for now
            }

            // Suspicious ports
            var suspiciousPorts = new[] { 4444, 5555, 6666, 7777, 8888, 31337, 1234, 12345 };
            if (suspiciousPorts.Contains(info.SourcePort) || suspiciousPorts.Contains(info.DestinationPort))
            {
                info.ThreatLevel = ThreatLevel.Medium;
                threats.Add("Suspicious port detected");
            }

            // Large ICMP packets (potential ICMP tunnel or DoS)
            if (info.Protocol == "ICMP" && info.Length > 1000)
            {
                info.ThreatLevel = ThreatLevel.Low;
                threats.Add("Large ICMP packet");
            }

            // DNS over unusual ports
            if (info.AppProtocol == ApplicationProtocol.DNS &&
                info.DestinationPort != 53 && info.SourcePort != 53)
            {
                info.ThreatLevel = ThreatLevel.Medium;
                threats.Add("DNS on non-standard port");
            }

            // Private IP in public traffic (potential data leak)
            if (IsPublicIP(info.DestinationIP) && IsPrivateIP(info.SourceIP))
            {
                // Normal, but could track for DLP
            }

            // RST flood detection (too many RSTs)
            if (info.TcpFlags?.RST == true)
            {
                // Would need context for proper detection
            }

            // Null scan detection
            if (info.Protocol == "TCP" && info.TcpFlags != null &&
                !info.TcpFlags.SYN && !info.TcpFlags.ACK && !info.TcpFlags.FIN &&
                !info.TcpFlags.RST && !info.TcpFlags.PSH && !info.TcpFlags.URG)
            {
                info.ThreatLevel = ThreatLevel.High;
                threats.Add("Potential NULL scan");
            }

            // XMAS scan detection
            if (info.TcpFlags?.FIN == true && info.TcpFlags?.URG == true && info.TcpFlags?.PSH == true)
            {
                info.ThreatLevel = ThreatLevel.High;
                threats.Add("Potential XMAS scan");
            }

            if (threats.Count > 0)
            {
                info.ThreatDescription = string.Join("; ", threats);
            }
        }

        private bool IsPrivateIP(string ip)
        {
            if (string.IsNullOrEmpty(ip)) return false;
            if (!IPAddress.TryParse(ip, out var addr)) return false;

            var bytes = addr.GetAddressBytes();
            if (bytes.Length != 4) return false;

            // 10.0.0.0/8
            if (bytes[0] == 10) return true;
            // 172.16.0.0/12
            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;
            // 192.168.0.0/16
            if (bytes[0] == 192 && bytes[1] == 168) return true;
            // 127.0.0.0/8
            if (bytes[0] == 127) return true;

            return false;
        }

        private bool IsPublicIP(string ip)
        {
            return !IsPrivateIP(ip);
        }

        #endregion

        #region Utility Methods

        public string GetServiceName(int port)
        {
            return _portToServiceName.TryGetValue(port, out var name) ? name : $"Port {port}";
        }

        public ApplicationProtocol GetProtocolForPort(int port)
        {
            return _portToProtocol.TryGetValue(port, out var proto) ? proto : ApplicationProtocol.Unknown;
        }

        #endregion
    }
}
