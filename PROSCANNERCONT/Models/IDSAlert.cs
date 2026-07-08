using System;
using System.ComponentModel;

namespace PROSCANNERCONT.Models
{
    /// <summary>
    /// Represents an Intrusion Detection System alert
    /// </summary>
    public class IDSAlert : INotifyPropertyChanged
    {
        private DateTime _timestamp;
        private string _sourceIP;
        private string _destinationIP;
        private int _sourcePort;
        private int _destinationPort;
        private string _protocol;
        private IDSAlertSeverity _severity;
        private string _alertType;
        private string _description;
        private string _honeypotName;
        private bool _isAcknowledged;
        private string _ruleId;

        public Guid AlertId { get; set; }
        public DateTime Timestamp
        {
            get => _timestamp;
            set
            {
                _timestamp = value;
                OnPropertyChanged(nameof(Timestamp));
                OnPropertyChanged(nameof(TimestampFormatted));
            }
        }

        public string TimestampFormatted => Timestamp.ToString("yyyy-MM-dd HH:mm:ss");

        public string SourceIP
        {
            get => _sourceIP;
            set
            {
                _sourceIP = value;
                OnPropertyChanged(nameof(SourceIP));
            }
        }

        public string DestinationIP
        {
            get => _destinationIP;
            set
            {
                _destinationIP = value;
                OnPropertyChanged(nameof(DestinationIP));
            }
        }

        public int SourcePort
        {
            get => _sourcePort;
            set
            {
                _sourcePort = value;
                OnPropertyChanged(nameof(SourcePort));
            }
        }

        public int DestinationPort
        {
            get => _destinationPort;
            set
            {
                _destinationPort = value;
                OnPropertyChanged(nameof(DestinationPort));
            }
        }

        public string Protocol
        {
            get => _protocol;
            set
            {
                _protocol = value;
                OnPropertyChanged(nameof(Protocol));
            }
        }

        public IDSAlertSeverity Severity
        {
            get => _severity;
            set
            {
                _severity = value;
                OnPropertyChanged(nameof(Severity));
                OnPropertyChanged(nameof(SeverityText));
                OnPropertyChanged(nameof(SeverityColor));
            }
        }

        public string SeverityText => Severity.ToString();

        

        public string AlertType
        {
            get => _alertType;
            set
            {
                _alertType = value;
                OnPropertyChanged(nameof(AlertType));
            }
        }

        public string Description
        {
            get => _description;
            set
            {
                _description = value;
                OnPropertyChanged(nameof(Description));
            }
        }

        public string HoneypotName
        {
            get => _honeypotName;
            set
            {
                _honeypotName = value;
                OnPropertyChanged(nameof(HoneypotName));
            }
        }

        public bool IsAcknowledged
        {
            get => _isAcknowledged;
            set
            {
                _isAcknowledged = value;
                OnPropertyChanged(nameof(IsAcknowledged));
            }
        }

        public string RuleId
        {
            get => _ruleId;
            set
            {
                _ruleId = value;
                OnPropertyChanged(nameof(RuleId));
            }
        }

        // Additional metadata
        public string PayloadPreview { get; set; }

        // GeoIP enrichment (populated on demand via GeoIpService)
        public string Country { get; set; }
        public string CountryCode { get; set; }
        public string ISP { get; set; }
        public string ASN { get; set; }

        // JA3 fingerprint (populated when TLS ClientHello detected)
        public string JA3Hash { get; set; }
        public string JA3Info { get; set; }

        // IPS: true when the source IP has been blocked by the firewall
        public bool IsBlocked { get; set; }

        // Computed display helpers
        [System.Text.Json.Serialization.JsonIgnore]
        public string SourceEndpoint => string.IsNullOrEmpty(SourceIP) ? "?" :
            SourcePort > 0 ? $"{SourceIP}:{SourcePort}" : SourceIP;

        [System.Text.Json.Serialization.JsonIgnore]
        public string DstEndpoint => string.IsNullOrEmpty(DestinationIP) ? "?" :
            DestinationPort > 0 ? $"{DestinationIP}:{DestinationPort}" : DestinationIP;

        [System.Text.Json.Serialization.JsonIgnore]
        public string SeverityColor => Severity switch
        {
            IDSAlertSeverity.Critical => "#F44747",
            IDSAlertSeverity.High     => "#FF8C00",
            IDSAlertSeverity.Medium   => "#FFA500",
            IDSAlertSeverity.Low      => "#4EC9B0",
            IDSAlertSeverity.Info     => "#007ACC",
            _ => "#666666"
        };
        public long PacketSize { get; set; }
        public string AttackCategory { get; set; }

        // ── MITRE ATT&CK mapping ─────────────────────────────────────────────
        // Filled by IDSManager from rule definitions (or the legacy
        // AttackCategory string via MitreReferenceService.FromCategory).
        // Surfaced in the alerts grid and reports as a coloured tactic badge.
        public string? MitreTechniqueId { get; set; }
        public string? MitreTechniqueName { get; set; }
        public string? MitreTactic { get; set; }

        // JA4 fingerprint (FoxIO spec, JA3 successor — see Ja4Fingerprinter)
        public string? JA4Hash { get; set; }
        public string? JA4String { get; set; }

        // Threat-intel enrichment tags applied by ThreatIntelService.
        public string? ThreatIntelTags { get; set; }

        public event PropertyChangedEventHandler? PropertyChanged;

        protected virtual void OnPropertyChanged(string? propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }

    /// <summary>
    /// Severity levels for IDS alerts
    /// </summary>
    public enum IDSAlertSeverity
    {
        Info,
        Low,
        Medium,
        High,
        Critical
    }
}