using PacketDotNet;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using PROSCANNERCONT.Views;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Services
{
    public class PacketFilter
    {
        public bool TcpEnabled { get; set; }
        public bool UdpEnabled { get; set; }
        public bool IcmpEnabled { get; set; }
        public bool HttpEnabled { get; set; }
        public string PortFilter { get; set; }
        public string IpFilter { get; set; }
        public string ConversationFilter { get; internal set; }

        private HashSet<int> _ports;
        private HashSet<IPAddress> _ipAddresses;

        public PacketFilter()
        {
            ResetFilters();
        }

        public void UpdatePortFilter(string portFilter)
        {
            PortFilter = portFilter;
            _ports = new HashSet<int>();

            if (!string.IsNullOrWhiteSpace(portFilter))
            {
                var ports = portFilter.Split(',')
                    .Select(p => p.Trim())
                    .Where(p => !string.IsNullOrEmpty(p));

                foreach (var port in ports)
                {
                    if (int.TryParse(port, out int portNumber))
                    {
                        _ports.Add(portNumber);
                    }
                }
            }
        }

        public void UpdateIpFilter(string ipFilter)
        {
            IpFilter = ipFilter;
            _ipAddresses = new HashSet<IPAddress>();

            if (!string.IsNullOrWhiteSpace(ipFilter))
            {
                var ips = ipFilter.Split(',')
                    .Select(ip => ip.Trim())
                    .Where(ip => !string.IsNullOrEmpty(ip));

                foreach (var ip in ips)
                {
                    if (IPAddress.TryParse(ip, out IPAddress address))
                    {
                        _ipAddresses.Add(address);
                    }
                }
            }
        }

        public void ResetFilters()
        {
            TcpEnabled = false;
            UdpEnabled = false;
            IcmpEnabled = false;
            HttpEnabled = false;
            PortFilter = string.Empty;
            IpFilter = string.Empty;
            _ports = new HashSet<int>();
            _ipAddresses = new HashSet<IPAddress>();
        }

        public bool ShouldDisplayPacket(PacketInfo packet)
        {
            // Don't show any packets if none meet the criteria
            if (string.IsNullOrEmpty(packet.Protocol))
                return false;

            // If no filters are enabled at all, show everything
            if (!TcpEnabled && !UdpEnabled && !IcmpEnabled && !HttpEnabled &&
                string.IsNullOrWhiteSpace(PortFilter) && string.IsNullOrWhiteSpace(IpFilter))
            {
                return true;
            }

            // Check protocol filters
            bool protocolMatch = false;
            if (TcpEnabled && packet.Protocol.Equals("TCP", StringComparison.OrdinalIgnoreCase))
                protocolMatch = true;
            if (UdpEnabled && packet.Protocol.Equals("UDP", StringComparison.OrdinalIgnoreCase))
                protocolMatch = true;
            if (IcmpEnabled && packet.Protocol.Equals("ICMP", StringComparison.OrdinalIgnoreCase))
                protocolMatch = true;
            if (HttpEnabled && packet.Info != null &&
                (packet.Info.Contains("80") || packet.Info.Contains("443")))
                protocolMatch = true;

            // If protocol filters are enabled but no match, reject packet
            if ((TcpEnabled || UdpEnabled || IcmpEnabled || HttpEnabled) && !protocolMatch)
                return false;

            return true;
        }

        internal bool ShouldDisplayPacket(EnhancedPacketInfo enhancedPacket)
        {
            if (enhancedPacket == null) return false;

            bool anyProto = TcpEnabled || UdpEnabled || IcmpEnabled || HttpEnabled;
            if (anyProto)
            {
                bool match = false;
                var proto = enhancedPacket.Protocol?.ToUpperInvariant() ?? "";
                if (TcpEnabled && proto == "TCP") match = true;
                if (UdpEnabled && proto == "UDP") match = true;
                if (IcmpEnabled && (proto == "ICMP" || proto == "ICMPV6")) match = true;
                if (HttpEnabled && (enhancedPacket.DestinationPort == 80 || enhancedPacket.SourcePort == 80 ||
                                    enhancedPacket.DestinationPort == 443 || enhancedPacket.SourcePort == 443)) match = true;
                if (!match) return false;
            }

            if (!string.IsNullOrWhiteSpace(IpFilter))
            {
                bool m = enhancedPacket.SourceIP?.Contains(IpFilter, StringComparison.OrdinalIgnoreCase) == true ||
                         enhancedPacket.DestinationIP?.Contains(IpFilter, StringComparison.OrdinalIgnoreCase) == true;
                if (!m) return false;
            }

            if (_ports.Count > 0)
            {
                bool portMatch = _ports.Contains(enhancedPacket.SourcePort) || _ports.Contains(enhancedPacket.DestinationPort);
                if (!portMatch) return false;
            }

            if (!string.IsNullOrWhiteSpace(ConversationFilter) &&
                enhancedPacket.ConversationId != ConversationFilter) return false;

            return true;
        }
    }
}
