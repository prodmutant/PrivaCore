    using System;
    using System.Collections.Generic;
    using System.ComponentModel;
    using System.Runtime.CompilerServices;

    namespace PROSCANNERCONT.Models
    {
        

        public class NetworkDevice : INotifyPropertyChanged
        {
            private string _hostname;
            private string _ipAddress;
            private string _os;
            private string _status;
            private string _macAddress;
            private bool _isOnline;
            private string _deviceType;

            public string Hostname
            {
                get => _hostname;
                set
                {
                    if (_hostname != value)
                    {
                        _hostname = value;
                        OnPropertyChanged();
                    }
                }
            }

            public string IPAddress
            {
                get => _ipAddress;
                set
                {
                    if (_ipAddress != value)
                    {
                        _ipAddress = value;
                        OnPropertyChanged();
                    }
                }
            }

            public string OS
            {
                get => _os;
                set
                {
                    if (_os != value)
                    {
                        _os = value;
                        OnPropertyChanged();
                    }
                }
            }

            public string Status
            {
                get => _status;
                set
                {
                    if (_status != value)
                    {
                        _status = value;
                        OnPropertyChanged();
                    }
                }
            }

            public string MACAddress
            {
                get => _macAddress;
                set
                {
                    if (_macAddress != value)
                    {
                        _macAddress = value;
                        OnPropertyChanged();
                    }
                }
            }

            public bool IsOnline
            {
                get => _isOnline;
                set
                {
                    if (_isOnline != value)
                    {
                        _isOnline = value;
                        OnPropertyChanged();
                    }
                }
            }

            public string DeviceType
            {
                get => _deviceType;
                set
                {
                    if (_deviceType != value)
                    {
                        _deviceType = value;
                        OnPropertyChanged();
                    }
                }
            }

            private long _responseTimeMs = -1;
            public long ResponseTimeMs
            {
                get => _responseTimeMs;
                set { if (_responseTimeMs != value) { _responseTimeMs = value; OnPropertyChanged(); OnPropertyChanged(nameof(ResponseDisplay)); } }
            }

            public string ResponseDisplay => ResponseTimeMs >= 0 ? $"{ResponseTimeMs} ms" : "—";

            private string _openPorts;
            public string OpenPorts
            {
                get => _openPorts;
                set { if (_openPorts != value) { _openPorts = value; OnPropertyChanged(); } }
            }

            public event PropertyChangedEventHandler? PropertyChanged;

            protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
            {
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
            }
        }

        public class PortScanResult : INotifyPropertyChanged
        {
            private string _ipAddress;
            private int _port;
            private string _status;
            private string _service;
            private string _protocol;
            private string _version;
            private bool _isOpen;

            public string IPAddress
            {
                get => _ipAddress;
                set
                {
                    _ipAddress = value;
                    OnPropertyChanged();
                }
            }

            public int Port
            {
                get => _port;
                set
                {
                    _port = value;
                    OnPropertyChanged();
                }
            }

            public string Status
            {
                get => _status;
                set
                {
                    _status = value;
                    OnPropertyChanged();
                }
            }

            public string Service
            {
                get => _service;
                set
                {
                    _service = value;
                    OnPropertyChanged();
                }
            }

            public string Protocol
            {
                get => _protocol;
                set
                {
                    _protocol = value;
                    OnPropertyChanged();
                }
            }

            public string Version
            {
                get => _version;
                set
                {
                    _version = value;
                    OnPropertyChanged();
                }
            }

            public bool IsOpen
            {
                get => _isOpen;
                set
                {
                    _isOpen = value;
                    OnPropertyChanged();
                }
            }
        private string _rawBanner;

        public string RawBanner
        {
            get => _rawBanner;
            set { _rawBanner = value; OnPropertyChanged(); }
        }

        private int _vulnCount;
        private string _riskLevel = "—";
        private string _riskColor = "#555555";
        private bool _cveChecked;
        private List<CveSummary> _cveFindings = new();

        public int VulnCount
        {
            get => _vulnCount;
            set { _vulnCount = value; OnPropertyChanged(); OnPropertyChanged(nameof(VulnCountText)); }
        }

        public string RiskLevel
        {
            get => _riskLevel;
            set { _riskLevel = value; OnPropertyChanged(); }
        }

        public string RiskColor
        {
            get => _riskColor;
            set { _riskColor = value; OnPropertyChanged(); }
        }

        public bool CveChecked
        {
            get => _cveChecked;
            set { _cveChecked = value; OnPropertyChanged(); OnPropertyChanged(nameof(CveStatusText)); }
        }

        public List<CveSummary> CveFindings
        {
            get => _cveFindings;
            set { _cveFindings = value; OnPropertyChanged(); }
        }

        public string VulnCountText => _cveChecked ? (_vulnCount == 0 ? "Clean" : $"{_vulnCount} CVEs") : "—";
        public string CveStatusText => !_cveChecked ? "Run 'Check CVEs' to analyse vulnerabilities for this service."
                                     : _vulnCount == 0 ? "✓  No known CVEs found for this service."
                                     : $"⚠  {_vulnCount} CVE(s) found:";

        public event PropertyChangedEventHandler? PropertyChanged;

        protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }

    public class CveSummary
    {
        public string CveId    { get; set; } = "";
        public decimal Cvss    { get; set; }
        public string Severity { get; set; } = "";
        public string Summary  { get; set; } = "";
        public string Reference { get; set; } = "";

        public string SeverityColor => Severity switch
        {
            "Critical" => "#F44747",
            "High"     => "#FF8C00",
            "Medium"   => "#FFA500",
            "Low"      => "#4EC9B0",
            _          => "#666666"
        };

        public string CvssText => Cvss > 0 ? $"CVSS {Cvss:F1}" : "";
    }

        public class PacketInfo : INotifyPropertyChanged
        {
            private DateTime _time;
            private string _sourceIP;
            private string _destinationIP;
            private string _protocol;
            private string _length;
            private string _info;
            private string _source;
            private string _destination;
            private byte[] _rawPacket;

            public DateTime Time
            {
                get => _time;
                set
                {
                    if (_time != value)
                    {
                        _time = value;
                        OnPropertyChanged();
                    }
                }
            }

            public string SourceIP
            {
                get => _sourceIP;
                set
                {
                    if (_sourceIP != value)
                    {
                        _sourceIP = value;
                        OnPropertyChanged();
                    }
                }
            }

            public string DestinationIP
            {
                get => _destinationIP;
                set
                {
                    if (_destinationIP != value)
                    {
                        _destinationIP = value;
                        OnPropertyChanged();
                    }
                }
            }

            public string Protocol
            {
                get => _protocol;
                set
                {
                    if (_protocol != value)
                    {
                        _protocol = value;
                        OnPropertyChanged();
                    }
                }
            }

            public string Length
            {
                get => _length;
                set
                {
                    if (_length != value)
                    {
                        _length = value;
                        OnPropertyChanged();
                    }
                }
            }

            public string Info
            {
                get => _info;
                set
                {
                    if (_info != value)
                    {
                        _info = value;
                        OnPropertyChanged();
                    }
                }
            }

            // Additional properties needed for traffic analysis
            public string Source
            {
                get => _source;
                set
                {
                    if (_source != value)
                    {
                        _source = value;
                        OnPropertyChanged();
                    }
                }
            }

            public string Destination
            {
                get => _destination;
                set
                {
                    if (_destination != value)
                    {
                        _destination = value;
                        OnPropertyChanged();
                    }
                }
            }

            public byte[] RawPacket
            {
                get => _rawPacket;
                set
                {
                    if (_rawPacket != value)
                    {
                        _rawPacket = value;
                        OnPropertyChanged();
                    }
                }
            }

            public event PropertyChangedEventHandler? PropertyChanged;

            protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
            {
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
            }
        }
    }