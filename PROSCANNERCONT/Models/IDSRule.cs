using System;
using System.ComponentModel;

namespace PROSCANNERCONT.Models
{
    /// <summary>
    /// Represents an IDS detection rule
    /// </summary>
    public class IDSRule : INotifyPropertyChanged
    {
        private string _ruleId;
        private string _name;
        private string _description;
        private bool _isEnabled;
        private IDSAlertSeverity _severity;
        private string _protocol;
        private string _sourceIP;
        private string _destinationIP;
        private string _sourcePort;
        private string _destinationPort;
        private string _pattern;
        private DateTime _lastTriggered;
        private int _triggerCount;

        public Guid Id { get; set; }

        public string RuleId
        {
            get => _ruleId;
            set
            {
                _ruleId = value;
                OnPropertyChanged(nameof(RuleId));
            }
        }

        public string Name
        {
            get => _name;
            set
            {
                _name = value;
                OnPropertyChanged(nameof(Name));
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

        public bool IsEnabled
        {
            get => _isEnabled;
            set
            {
                _isEnabled = value;
                OnPropertyChanged(nameof(IsEnabled));
                OnPropertyChanged(nameof(StatusText));
            }
        }

        public string StatusText => IsEnabled ? "Enabled" : "Disabled";

        public IDSAlertSeverity Severity
        {
            get => _severity;
            set
            {
                _severity = value;
                OnPropertyChanged(nameof(Severity));
                OnPropertyChanged(nameof(SeverityText));
            }
        }

        public string SeverityText => Severity.ToString();

        public string Protocol
        {
            get => _protocol;
            set
            {
                _protocol = value;
                OnPropertyChanged(nameof(Protocol));
            }
        }

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

        public string SourcePort
        {
            get => _sourcePort;
            set
            {
                _sourcePort = value;
                OnPropertyChanged(nameof(SourcePort));
            }
        }

        public string DestinationPort
        {
            get => _destinationPort;
            set
            {
                _destinationPort = value;
                OnPropertyChanged(nameof(DestinationPort));
            }
        }

        public string Pattern
        {
            get => _pattern;
            set
            {
                _pattern = value;
                OnPropertyChanged(nameof(Pattern));
            }
        }

        public DateTime LastTriggered
        {
            get => _lastTriggered;
            set
            {
                _lastTriggered = value;
                OnPropertyChanged(nameof(LastTriggered));
                OnPropertyChanged(nameof(LastTriggeredFormatted));
            }
        }

        public string LastTriggeredFormatted => LastTriggered == DateTime.MinValue
            ? "Never"
            : LastTriggered.ToString("yyyy-MM-dd HH:mm:ss");

        public int TriggerCount
        {
            get => _triggerCount;
            set
            {
                _triggerCount = value;
                OnPropertyChanged(nameof(TriggerCount));
            }
        }

        // Rule matching criteria
        public int MinPacketSize { get; set; }
        public int MaxPacketSize { get; set; }
        public string AttackCategory { get; set; }

        // ── MITRE ATT&CK linkage (optional per rule) ─────────────────────────
        // Set on built-in rules in IDSEngine.LoadDefaultRules(); custom user
        // rules can leave these null and fall back to category-derived mapping.
        public string? MitreTechniqueId { get; set; }
        public string? MitreTactic { get; set; }
        public RuleKind RuleKind { get; set; } = RuleKind.Signature;
        public bool RequireNullFlags  { get; set; }
        public bool RequireXmasFlags  { get; set; }
        public DateTime CreatedDate { get; set; }
        public DateTime ModifiedDate { get; set; }

        // Per-rule alert threshold: fire only after N matches in WindowSec seconds (0 = fire on first match)
        public int AlertThreshold { get; set; } = 0;
        public int AlertWindowSec { get; set; } = 60;

        public event PropertyChangedEventHandler? PropertyChanged;

        protected virtual void OnPropertyChanged(string? propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));

        }
    }
    public enum RuleKind { Signature, Behavioral }
}
