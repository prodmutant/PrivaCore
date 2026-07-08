using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Text;

namespace PROSCANNERCONT.Models
{
    public enum PacketDirection { Inbound, Outbound, Internal, External, Unknown }
    public enum ThreatLevel { None = 0, Low = 1, Medium = 2, High = 3, Critical = 4 }
    public enum ConnectionState { New, Established, Closing, Closed, Reset, Unknown }
    public enum ApplicationProtocol { Unknown, HTTP, HTTPS, FTP, FTPS, SSH, Telnet, SMTP, SMTPS, POP3, IMAP, DNS, DHCP, SNMP, NTP, LDAP, RDP, VNC, SMB, NetBIOS, MySQL, PostgreSQL, MSSQL, MongoDB, Redis, Memcached, MQTT, CoAP, SIP, RTP, RTSP, WebSocket, QUIC, WireGuard, OpenVPN, IPSec, GRE, VXLAN, Custom }
    public enum DnsOpCode { Query = 0, IQuery = 1, Status = 2, Notify = 4, Update = 5 }
    public enum DnsResponseCode { NoError = 0, FormatError = 1, ServerFailure = 2, NameError = 3, NotImplemented = 4, Refused = 5, YXDomain = 6, YXRRSet = 7, NXRRSet = 8, NotAuth = 9, NotZone = 10 }

    public class EnhancedPacketInfo : INotifyPropertyChanged
    {
        private int _packetNumber; private DateTime _timestamp; private double _relativeTime;
        private string _sourceIP, _destinationIP, _sourceMac, _destinationMac, _protocol, _info, _threatDescription, _conversationId, _comments;
        private int _sourcePort, _destinationPort, _length, _payloadLength, _streamIndex;
        private ApplicationProtocol _applicationProtocol; private byte[] _rawPacket;
        private PacketDirection _direction; private ThreatLevel _threatLevel; private bool _isMarked;

        public int PacketNumber { get => _packetNumber; set { _packetNumber = value; OnPropertyChanged(); } }
        public DateTime Timestamp { get => _timestamp; set { _timestamp = value; OnPropertyChanged(); } }
        public double RelativeTime { get => _relativeTime; set { _relativeTime = value; OnPropertyChanged(); } }
        public string SourceIP { get => _sourceIP; set { _sourceIP = value; OnPropertyChanged(); } }
        public string DestinationIP { get => _destinationIP; set { _destinationIP = value; OnPropertyChanged(); } }
        public int SourcePort { get => _sourcePort; set { _sourcePort = value; OnPropertyChanged(); } }
        public int DestinationPort { get => _destinationPort; set { _destinationPort = value; OnPropertyChanged(); } }
        public string SourceMac { get => _sourceMac; set { _sourceMac = value; OnPropertyChanged(); } }
        public string DestinationMac { get => _destinationMac; set { _destinationMac = value; OnPropertyChanged(); } }
        public string Protocol { get => _protocol; set { _protocol = value; OnPropertyChanged(); } }
        public ApplicationProtocol AppProtocol { get => _applicationProtocol; set { _applicationProtocol = value; OnPropertyChanged(); } }
        public int Length { get => _length; set { _length = value; OnPropertyChanged(); } }
        public int PayloadLength { get => _payloadLength; set { _payloadLength = value; OnPropertyChanged(); } }
        public string Info { get => _info; set { _info = value; OnPropertyChanged(); } }
        public byte[] RawPacket { get => _rawPacket; set { _rawPacket = value; OnPropertyChanged(); } }
        public PacketDirection Direction { get => _direction; set { _direction = value; OnPropertyChanged(); } }
        public ThreatLevel ThreatLevel { get => _threatLevel; set { _threatLevel = value; OnPropertyChanged(); } }
        public string ThreatDescription { get => _threatDescription; set { _threatDescription = value; OnPropertyChanged(); } }
        public string ConversationId { get => _conversationId; set { _conversationId = value; OnPropertyChanged(); } }
        public int StreamIndex { get => _streamIndex; set { _streamIndex = value; OnPropertyChanged(); } }
        public bool IsMarked { get => _isMarked; set { _isMarked = value; OnPropertyChanged(); } }
        public string Comments { get => _comments; set { _comments = value; OnPropertyChanged(); } }
        public TcpFlags TcpFlags { get; set; }
        public uint SequenceNumber { get; set; }
        public uint AcknowledgmentNumber { get; set; }
        public int WindowSize { get; set; }
        public HttpInfo HttpData { get; set; }
        public DnsInfo DnsData { get; set; }
        public TlsInfo TlsData { get; set; }
        public List<ProtocolLayer> Layers { get; set; } = new List<ProtocolLayer>();
        public string SourceEndpoint => string.IsNullOrEmpty(SourceIP) ? "Unknown" : (SourcePort > 0 ? $"{SourceIP}:{SourcePort}" : SourceIP);
        public string DestinationEndpoint => string.IsNullOrEmpty(DestinationIP) ? "Unknown" : (DestinationPort > 0 ? $"{DestinationIP}:{DestinationPort}" : DestinationIP);
        public string FormattedTimestamp => Timestamp.ToString("HH:mm:ss.ffffff");
        public string FormattedRelativeTime => RelativeTime.ToString("F6");
        public string ThreatIcon => ThreatLevel switch { ThreatLevel.None => "", ThreatLevel.Low => "⚪", ThreatLevel.Medium => "🟡", ThreatLevel.High => "🟠", ThreatLevel.Critical => "🔴", _ => "" };
        public event PropertyChangedEventHandler? PropertyChanged;
        protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }

    public class TcpFlags
    {
        public bool SYN { get; set; }
        public bool ACK { get; set; }
        public bool FIN { get; set; }
        public bool RST { get; set; }
        public bool PSH { get; set; }
        public bool URG { get; set; }
        public bool ECE { get; set; }
        public bool CWR { get; set; }
        public override string ToString() { var f = new List<string>(); if (SYN) f.Add("SYN"); if (ACK) f.Add("ACK"); if (FIN) f.Add("FIN"); if (RST) f.Add("RST"); if (PSH) f.Add("PSH"); if (URG) f.Add("URG"); if (ECE) f.Add("ECE"); if (CWR) f.Add("CWR"); return f.Count > 0 ? string.Join(", ", f) : "None"; }
        public string ToShortString() { var sb = new StringBuilder("["); if (SYN) sb.Append("S"); if (ACK) sb.Append("A"); if (FIN) sb.Append("F"); if (RST) sb.Append("R"); if (PSH) sb.Append("P"); if (URG) sb.Append("U"); sb.Append("]"); return sb.ToString(); }
    }

    public class HttpInfo
    {
        public bool IsRequest { get; set; }
        public string Method { get; set; }
        public string Uri { get; set; }
        public string Host { get; set; }
        public string HttpVersion { get; set; }
        public int StatusCode { get; set; }
        public string StatusText { get; set; }
        public Dictionary<string, string> Headers { get; set; } = new Dictionary<string, string>();
        public string ContentType { get; set; }
        public long ContentLength { get; set; }
        public string UserAgent { get; set; }
        public string Referer { get; set; }
        public byte[] Body { get; set; }
        public string BodyPreview { get; set; }
        public string Summary => IsRequest ? $"{Method} {Uri} HTTP/{HttpVersion}" : $"HTTP/{HttpVersion} {StatusCode} {StatusText}";
    }

    public class DnsInfo
    {
        public ushort TransactionId { get; set; }
        public bool IsQuery { get; set; }
        public bool IsResponse { get; set; }
        public DnsOpCode OpCode { get; set; }
        public DnsResponseCode ResponseCode { get; set; }
        public bool IsAuthoritative { get; set; }
        public bool IsTruncated { get; set; }
        public bool RecursionDesired { get; set; }
        public bool RecursionAvailable { get; set; }
        public List<DnsQuestion> Questions { get; set; } = new List<DnsQuestion>();
        public List<DnsResourceRecord> Answers { get; set; } = new List<DnsResourceRecord>();
        public List<DnsResourceRecord> Authorities { get; set; } = new List<DnsResourceRecord>();
        public List<DnsResourceRecord> Additional { get; set; } = new List<DnsResourceRecord>();
        public string Summary => IsQuery && Questions.Count > 0 ? $"Query: {Questions[0].Name} ({Questions[0].Type})" : IsResponse && Answers.Count > 0 ? $"Response: {Answers[0].Data}" : IsQuery ? "DNS Query" : "DNS Response";
    }

    public class DnsQuestion { public string Name { get; set; } public string Type { get; set; } public string Class { get; set; } }
    public class DnsResourceRecord { public string Name { get; set; } public string Type { get; set; } public string Class { get; set; } public uint TTL { get; set; } public string Data { get; set; } }

    public class TlsInfo
    {
        public string Version { get; set; }
        public string ContentType { get; set; }
        public string HandshakeType { get; set; }
        public string ServerName { get; set; }
        public string CipherSuite { get; set; }
        public List<string> SupportedVersions { get; set; } = new List<string>();
        public List<string> CipherSuites { get; set; } = new List<string>();
        public string CertificateIssuer { get; set; }
        public string CertificateSubject { get; set; }
        public DateTime? CertificateExpiry { get; set; }
        public bool IsEncrypted { get; set; }
        public byte[] JA3Fingerprint { get; set; }
        public string JA3Hash { get; set; }
        public string Summary => !string.IsNullOrEmpty(HandshakeType) ? $"TLS {Version} {HandshakeType}" : $"TLS {Version} {ContentType}";
    }

    public class ProtocolLayer
    {
        public string Name { get; set; }
        public int HeaderOffset { get; set; }
        public int HeaderLength { get; set; }
        public int PayloadOffset { get; set; }
        public int PayloadLength { get; set; }
        public Dictionary<string, object> Fields { get; set; } = new Dictionary<string, object>();
        public List<ProtocolField> DisplayFields { get; set; } = new List<ProtocolField>();
    }

    public class ProtocolField { public string Name { get; set; } public string Value { get; set; } public int BitOffset { get; set; } public int BitLength { get; set; } public string Description { get; set; } public bool IsImportant { get; set; } }

    public class Conversation : INotifyPropertyChanged
    {
        private int _packetCount; private long _bytesAtoB, _bytesBtoA;
        private DateTime _startTime, _lastActivity; private ConnectionState _state;
        public string Id { get; set; }
        public string EndpointA { get; set; }
        public string EndpointB { get; set; }
        public string Protocol { get; set; }
        public ApplicationProtocol AppProtocol { get; set; }
        public int PacketCount { get => _packetCount; set { _packetCount = value; OnPropertyChanged(); } }
        public long BytesAtoB { get => _bytesAtoB; set { _bytesAtoB = value; OnPropertyChanged(); OnPropertyChanged(nameof(TotalBytes)); } }
        public long BytesBtoA { get => _bytesBtoA; set { _bytesBtoA = value; OnPropertyChanged(); OnPropertyChanged(nameof(TotalBytes)); } }
        public long TotalBytes => BytesAtoB + BytesBtoA;
        public DateTime StartTime { get => _startTime; set { _startTime = value; OnPropertyChanged(); OnPropertyChanged(nameof(Duration)); } }
        public DateTime LastActivity { get => _lastActivity; set { _lastActivity = value; OnPropertyChanged(); OnPropertyChanged(nameof(Duration)); } }
        public TimeSpan Duration => LastActivity - StartTime;
        public ConnectionState State { get => _state; set { _state = value; OnPropertyChanged(); } }
        public List<EnhancedPacketInfo> Packets { get; set; } = new List<EnhancedPacketInfo>();
        public event PropertyChangedEventHandler? PropertyChanged;
        protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }

    public class TrafficStatistics : INotifyPropertyChanged
    {
        private long _totalPackets, _totalBytes; private double _packetsPerSecond, _bytesPerSecond, _averagePacketSize;
        private DateTime _captureStartTime; private TimeSpan _captureDuration;
        public long TotalPackets { get => _totalPackets; set { _totalPackets = value; OnPropertyChanged(); } }
        public long TotalBytes { get => _totalBytes; set { _totalBytes = value; OnPropertyChanged(); OnPropertyChanged(nameof(FormattedTotalBytes)); } }
        public string FormattedTotalBytes => FormatBytes(TotalBytes);
        public double PacketsPerSecond { get => _packetsPerSecond; set { _packetsPerSecond = value; OnPropertyChanged(); } }
        public double BytesPerSecond { get => _bytesPerSecond; set { _bytesPerSecond = value; OnPropertyChanged(); OnPropertyChanged(nameof(FormattedBytesPerSecond)); } }
        public string FormattedBytesPerSecond => FormatBytes((long)BytesPerSecond) + "/s";
        public double AveragePacketSize { get => _averagePacketSize; set { _averagePacketSize = value; OnPropertyChanged(); } }
        public DateTime CaptureStartTime { get => _captureStartTime; set { _captureStartTime = value; OnPropertyChanged(); } }
        public TimeSpan CaptureDuration { get => _captureDuration; set { _captureDuration = value; OnPropertyChanged(); OnPropertyChanged(nameof(FormattedDuration)); } }
        public string FormattedDuration => CaptureDuration.ToString(@"hh\:mm\:ss\.fff");
        public Dictionary<string, long> ProtocolPacketCounts { get; set; } = new Dictionary<string, long>();
        public Dictionary<string, long> ProtocolByteCounts { get; set; } = new Dictionary<string, long>();
        public Dictionary<string, long> TopSourceIPs { get; set; } = new Dictionary<string, long>();
        public Dictionary<string, long> TopDestinationIPs { get; set; } = new Dictionary<string, long>();
        public Dictionary<int, long> TopPorts { get; set; } = new Dictionary<int, long>();
        public int ThreatCount { get; set; }
        public Dictionary<ThreatLevel, int> ThreatsByLevel { get; set; } = new Dictionary<ThreatLevel, int>();
        private string FormatBytes(long bytes) { if (bytes < 0) return "0 B"; string[] s = { "B", "KB", "MB", "GB", "TB" }; int o = 0; double sz = bytes; while (sz >= 1024 && o < s.Length - 1) { o++; sz /= 1024; } return $"{sz:F2} {s[o]}"; }
        public event PropertyChangedEventHandler? PropertyChanged;
        protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }

    // IMPORTANT: Renamed to TrafficPacketFilter to avoid conflicts with existing PacketFilter class
    public class TrafficPacketFilter : INotifyPropertyChanged
    {
        private bool _tcpEnabled, _udpEnabled, _icmpEnabled, _httpEnabled, _httpsEnabled, _dnsEnabled, _sshEnabled, _ftpEnabled, _smtpEnabled;
        private bool _otherEnabled = true, _showOnlyMarked, _showOnlyThreats;
        private string _sourceIpFilter, _destinationIpFilter, _ipFilter, _macFilter, _infoContains, _conversationFilter, _customDisplayFilter;
        private int? _portFilter, _sourcePortFilter, _destinationPortFilter, _minLength, _maxLength;
        private ThreatLevel? _minThreatLevel;

        public bool TcpEnabled { get => _tcpEnabled; set { _tcpEnabled = value; OnPropertyChanged(); } }
        public bool UdpEnabled { get => _udpEnabled; set { _udpEnabled = value; OnPropertyChanged(); } }
        public bool IcmpEnabled { get => _icmpEnabled; set { _icmpEnabled = value; OnPropertyChanged(); } }
        public bool HttpEnabled { get => _httpEnabled; set { _httpEnabled = value; OnPropertyChanged(); } }
        public bool HttpsEnabled { get => _httpsEnabled; set { _httpsEnabled = value; OnPropertyChanged(); } }
        public bool DnsEnabled { get => _dnsEnabled; set { _dnsEnabled = value; OnPropertyChanged(); } }
        public bool SshEnabled { get => _sshEnabled; set { _sshEnabled = value; OnPropertyChanged(); } }
        public bool FtpEnabled { get => _ftpEnabled; set { _ftpEnabled = value; OnPropertyChanged(); } }
        public bool SmtpEnabled { get => _smtpEnabled; set { _smtpEnabled = value; OnPropertyChanged(); } }
        public bool OtherEnabled { get => _otherEnabled; set { _otherEnabled = value; OnPropertyChanged(); } }
        public string SourceIpFilter { get => _sourceIpFilter; set { _sourceIpFilter = value; OnPropertyChanged(); } }
        public string DestinationIpFilter { get => _destinationIpFilter; set { _destinationIpFilter = value; OnPropertyChanged(); } }
        public string IpFilter { get => _ipFilter; set { _ipFilter = value; OnPropertyChanged(); } }
        public int? PortFilter { get => _portFilter; set { _portFilter = value; OnPropertyChanged(); } }
        public int? SourcePortFilter { get => _sourcePortFilter; set { _sourcePortFilter = value; OnPropertyChanged(); } }
        public int? DestinationPortFilter { get => _destinationPortFilter; set { _destinationPortFilter = value; OnPropertyChanged(); } }
        public string MacFilter { get => _macFilter; set { _macFilter = value; OnPropertyChanged(); } }
        public int? MinLength { get => _minLength; set { _minLength = value; OnPropertyChanged(); } }
        public int? MaxLength { get => _maxLength; set { _maxLength = value; OnPropertyChanged(); } }
        public string InfoContains { get => _infoContains; set { _infoContains = value; OnPropertyChanged(); } }
        public bool ShowOnlyMarked { get => _showOnlyMarked; set { _showOnlyMarked = value; OnPropertyChanged(); } }
        public bool ShowOnlyThreats { get => _showOnlyThreats; set { _showOnlyThreats = value; OnPropertyChanged(); } }
        public ThreatLevel? MinThreatLevel { get => _minThreatLevel; set { _minThreatLevel = value; OnPropertyChanged(); } }
        public string ConversationFilter { get => _conversationFilter; set { _conversationFilter = value; OnPropertyChanged(); } }
        public string CustomDisplayFilter { get => _customDisplayFilter; set { _customDisplayFilter = value; OnPropertyChanged(); } }

        public bool HasActiveFilters => TcpEnabled || UdpEnabled || IcmpEnabled || HttpEnabled || HttpsEnabled || DnsEnabled || SshEnabled || FtpEnabled || SmtpEnabled || !string.IsNullOrEmpty(SourceIpFilter) || !string.IsNullOrEmpty(DestinationIpFilter) || !string.IsNullOrEmpty(IpFilter) || PortFilter.HasValue || SourcePortFilter.HasValue || DestinationPortFilter.HasValue || !string.IsNullOrEmpty(MacFilter) || MinLength.HasValue || MaxLength.HasValue || !string.IsNullOrEmpty(InfoContains) || ShowOnlyMarked || ShowOnlyThreats || MinThreatLevel.HasValue || !string.IsNullOrEmpty(ConversationFilter) || !string.IsNullOrEmpty(CustomDisplayFilter);

        public bool ShouldDisplayPacket(EnhancedPacketInfo packet)
        {
            if (packet == null) return false;
            bool anyProto = TcpEnabled || UdpEnabled || IcmpEnabled || HttpEnabled || HttpsEnabled || DnsEnabled || SshEnabled || FtpEnabled || SmtpEnabled;
            if (anyProto)
            {
                bool match = false; var proto = packet.Protocol?.ToUpperInvariant() ?? "";
                if (TcpEnabled && proto == "TCP") match = true;
                if (UdpEnabled && proto == "UDP") match = true;
                if (IcmpEnabled && (proto == "ICMP" || proto == "ICMPV6")) match = true;
                if (HttpEnabled && (packet.AppProtocol == ApplicationProtocol.HTTP || proto == "HTTP")) match = true;
                if (HttpsEnabled && (packet.AppProtocol == ApplicationProtocol.HTTPS || proto == "HTTPS" || packet.DestinationPort == 443 || packet.SourcePort == 443)) match = true;
                if (DnsEnabled && (packet.AppProtocol == ApplicationProtocol.DNS || proto == "DNS" || packet.DestinationPort == 53 || packet.SourcePort == 53)) match = true;
                if (SshEnabled && (packet.AppProtocol == ApplicationProtocol.SSH || packet.DestinationPort == 22 || packet.SourcePort == 22)) match = true;
                if (FtpEnabled && (packet.AppProtocol == ApplicationProtocol.FTP || packet.DestinationPort == 21 || packet.SourcePort == 21)) match = true;
                if (SmtpEnabled && (packet.AppProtocol == ApplicationProtocol.SMTP || packet.DestinationPort == 25 || packet.SourcePort == 25)) match = true;
                if (!match && !OtherEnabled) return false;
            }
            if (!string.IsNullOrEmpty(IpFilter)) { bool m = false; if (packet.SourceIP?.Contains(IpFilter, StringComparison.OrdinalIgnoreCase) == true) m = true; if (packet.DestinationIP?.Contains(IpFilter, StringComparison.OrdinalIgnoreCase) == true) m = true; if (!m) return false; }
            if (!string.IsNullOrEmpty(SourceIpFilter) && packet.SourceIP?.Contains(SourceIpFilter, StringComparison.OrdinalIgnoreCase) != true) return false;
            if (!string.IsNullOrEmpty(DestinationIpFilter) && packet.DestinationIP?.Contains(DestinationIpFilter, StringComparison.OrdinalIgnoreCase) != true) return false;
            if (PortFilter.HasValue && packet.SourcePort != PortFilter.Value && packet.DestinationPort != PortFilter.Value) return false;
            if (SourcePortFilter.HasValue && packet.SourcePort != SourcePortFilter.Value) return false;
            if (DestinationPortFilter.HasValue && packet.DestinationPort != DestinationPortFilter.Value) return false;
            if (!string.IsNullOrEmpty(MacFilter)) { bool m = false; if (packet.SourceMac?.Contains(MacFilter, StringComparison.OrdinalIgnoreCase) == true) m = true; if (packet.DestinationMac?.Contains(MacFilter, StringComparison.OrdinalIgnoreCase) == true) m = true; if (!m) return false; }
            if (MinLength.HasValue && packet.Length < MinLength.Value) return false;
            if (MaxLength.HasValue && packet.Length > MaxLength.Value) return false;
            if (!string.IsNullOrEmpty(InfoContains) && packet.Info?.Contains(InfoContains, StringComparison.OrdinalIgnoreCase) != true) return false;
            if (ShowOnlyMarked && !packet.IsMarked) return false;
            if (ShowOnlyThreats && packet.ThreatLevel == ThreatLevel.None) return false;
            if (MinThreatLevel.HasValue && packet.ThreatLevel < MinThreatLevel.Value) return false;
            if (!string.IsNullOrEmpty(ConversationFilter) && packet.ConversationId != ConversationFilter) return false;
            return true;
        }

        public void ResetFilter()
        {
            TcpEnabled = false; UdpEnabled = false; IcmpEnabled = false; HttpEnabled = false; HttpsEnabled = false;
            DnsEnabled = false; SshEnabled = false; FtpEnabled = false; SmtpEnabled = false; OtherEnabled = true;
            SourceIpFilter = null; DestinationIpFilter = null; IpFilter = null; PortFilter = null;
            SourcePortFilter = null; DestinationPortFilter = null; MacFilter = null; MinLength = null; MaxLength = null;
            InfoContains = null; ShowOnlyMarked = false; ShowOnlyThreats = false; MinThreatLevel = null;
            ConversationFilter = null; CustomDisplayFilter = null;
        }

        public event PropertyChangedEventHandler? PropertyChanged;
        protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }

    public class TrafficAlert : INotifyPropertyChanged
    {
        private DateTime _timestamp; private ThreatLevel _severity; private string _title = string.Empty, _description = string.Empty, _sourceIp = string.Empty, _destinationIp = string.Empty, _category = string.Empty;
        private int _relatedPacketNumber; private bool _isAcknowledged;
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public DateTime Timestamp { get => _timestamp; set { _timestamp = value; OnPropertyChanged(); } }
        public ThreatLevel Severity { get => _severity; set { _severity = value; OnPropertyChanged(); } }
        public string Title { get => _title; set { _title = value; OnPropertyChanged(); } }
        public string Description { get => _description; set { _description = value; OnPropertyChanged(); } }
        public string SourceIP { get => _sourceIp; set { _sourceIp = value; OnPropertyChanged(); } }
        public string DestinationIP { get => _destinationIp; set { _destinationIp = value; OnPropertyChanged(); } }
        public int RelatedPacketNumber { get => _relatedPacketNumber; set { _relatedPacketNumber = value; OnPropertyChanged(); } }
        public bool IsAcknowledged { get => _isAcknowledged; set { _isAcknowledged = value; OnPropertyChanged(); } }
        public string Category { get => _category; set { _category = value; OnPropertyChanged(); } }
        public string SeverityIcon => Severity switch { ThreatLevel.Low => "ℹ️", ThreatLevel.Medium => "⚠️", ThreatLevel.High => "🔶", ThreatLevel.Critical => "🚨", _ => "📝" };
        public event PropertyChangedEventHandler? PropertyChanged;
        protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }

    public class IOGraphDataPoint
    {
        public DateTime Timestamp { get; set; }
        public double PacketsPerSecond { get; set; }
        public double BytesPerSecond { get; set; }
        public double BitsPerSecond { get; set; }
        public int PacketCount { get; set; }
        public long ByteCount { get; set; }
    }
}
