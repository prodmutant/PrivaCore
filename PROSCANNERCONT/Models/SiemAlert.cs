using System;
using System.ComponentModel;

namespace PROSCANNERCONT.Models
{
    public enum SiemAlertStatus { Open, Acknowledged, Closed }

    /// <summary>
    /// A triggered detection — one instance of a <see cref="SiemRule"/> firing. Carries a triage
    /// status (open → acknowledged → closed) that the analyst can move through in the Alerts tab.
    /// </summary>
    public sealed class SiemAlert : INotifyPropertyChanged
    {
        public string Id { get; set; } = Guid.NewGuid().ToString("N");
        public string RuleId { get; set; } = "";
        public string RuleName { get; set; } = "";
        public DateTime Timestamp { get; set; } = DateTime.Now;
        public SiemSeverity Severity { get; set; } = SiemSeverity.High;
        public string Message { get; set; } = "";
        public int Count { get; set; }
        public string GroupValue { get; set; } = "";
        public string MitreId { get; set; } = "";
        public string MitreName { get; set; } = "";
        public string MitreTactic { get; set; } = "";
        public int RiskScore { get; set; }              // 0-100, computed from the rule's base risk + overage

        private SiemAlertStatus _status = SiemAlertStatus.Open;
        public SiemAlertStatus Status
        {
            get => _status;
            set { if (_status != value) { _status = value; OnAll(); } }
        }

        private string _assignee = "";
        public string Assignee
        {
            get => _assignee;
            set { if (_assignee != (value ?? "")) { _assignee = value ?? ""; OnAll(); } }
        }

        public string TimeText => Timestamp.ToString("MMM dd, HH:mm:ss");
        public string SeverityText => Severity.ToString();
        public string CountText => Count.ToString("N0");
        public string StatusText => Status.ToString();
        public string RiskText => RiskScore.ToString();
        public string AssigneeText => string.IsNullOrEmpty(Assignee) ? "—" : Assignee;

        /// <summary>Risk band colour (Kibana-style 0-21 low / 22-47 / 48-73 / 74-100).</summary>
        public string RiskColor => RiskScore switch
        {
            >= 74 => "#F85149",
            >= 48 => "#FF7B72",
            >= 22 => "#E3B341",
            _     => "#8B949E",
        };
        public string MitreText => string.IsNullOrEmpty(MitreId) ? "—" :
            (string.IsNullOrEmpty(MitreName) ? MitreId : $"{MitreId} · {MitreName}");

        public string SeverityColor => Severity switch
        {
            SiemSeverity.Critical => "#F85149",
            SiemSeverity.High     => "#FF7B72",
            SiemSeverity.Medium   => "#E3B341",
            SiemSeverity.Low      => "#58A6FF",
            _                     => "#8B949E",
        };

        public string StatusColor => Status switch
        {
            SiemAlertStatus.Open         => "#F85149",
            SiemAlertStatus.Acknowledged => "#E3B341",
            _                            => "#56D364",
        };

        public event PropertyChangedEventHandler? PropertyChanged;
        private void OnAll() => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(string.Empty));
    }
}
