using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using Newtonsoft.Json;

namespace PROSCANNERCONT.Models
{
    /// <summary>
    /// Represents a honeypot virtual machine with SSH access
    /// </summary>
    public class HoneypotVM : INotifyPropertyChanged
    {
        private string _name;
        private HoneypotStatus _status;
        private string _ipAddress;
        private int _totalConnectionAttempts;
        private int _alertCount;
        private DateTime _lastActivity;
        private bool _sshConnected;

        // ============================================================
        // BASIC VM PROPERTIES
        // ============================================================

        public string Name
        {
            get => _name;
            set { _name = value; OnPropertyChanged(); }
        }

        public string HyperVVMId { get; set; }

        public HoneypotStatus Status
        {
            get => _status;
            set { _status = value; OnPropertyChanged(); OnPropertyChanged(nameof(StatusText)); }
        }

        public string Hostname
        {
            get => Name;
            set => Name = value;
        }

        public string IPAddress
        {
            get => _ipAddress;
            set { _ipAddress = value; OnPropertyChanged(); }
        }

        public HoneypotProfileType ProfileType { get; set; }
        public string Description { get; set; }
        public string OSType { get; set; }

        // ============================================================
        // HARDWARE PROPERTIES
        // ============================================================

        public int MemoryMB { get; set; }
        public int CPUCores { get; set; }
        public int StorageSizeGB { get; set; }

        // ============================================================
        // NETWORK PROPERTIES
        // ============================================================

        public NetworkAdapterType NetworkType { get; set; }
        public string NetworkAdapter { get; set; }

        // ============================================================
        // DISK PROPERTIES
        // ============================================================

        public bool UsesDifferencingDisk { get; set; }
        public string BaseImagePath { get; set; }

        // ============================================================
        // SSH PROPERTIES (NEW!)
        // ============================================================

        /// <summary>
        /// SSH host (IP address or hostname)
        /// </summary>
        public string SSHHost { get; set; }

        /// <summary>
        /// SSH port (default: 22)
        /// </summary>
        public int SSHPort { get; set; } = 22;

        /// <summary>
        /// SSH username
        /// </summary>
        public string SSHUsername { get; set; }

        /// <summary>
        /// Encrypted SSH password (stored securely)
        /// </summary>
        public string SSHPasswordEncrypted { get; set; }

        /// <summary>
        /// Whether to use SSH key instead of password
        /// </summary>
        public bool UseSSHKey { get; set; }

        /// <summary>
        /// Path to SSH private key file
        /// </summary>
        public string SSHKeyPath { get; set; }

        /// <summary>
        /// Whether SSH connection is currently active
        /// </summary>
        [JsonIgnore]
        public bool SSHConnected
        {
            get => _sshConnected;
            set
            {
                _sshConnected = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(SSHStatusText));
                OnPropertyChanged(nameof(SSHStatusIcon));
            }
        }

        /// <summary>
        /// Last successful SSH connection time
        /// </summary>
        public DateTime LastSSHConnection { get; set; }

        /// <summary>
        /// Whether SSH credentials are configured
        /// </summary>
        [JsonIgnore]
        public bool HasSSHConfigured
        {
            get
            {
                return !string.IsNullOrEmpty(SSHHost) &&
                       !string.IsNullOrEmpty(SSHUsername) &&
                       (UseSSHKey ? !string.IsNullOrEmpty(SSHKeyPath) : !string.IsNullOrEmpty(SSHPasswordEncrypted));
            }
        }

        // ============================================================
        // STATISTICS
        // ============================================================

        public int TotalConnectionAttempts
        {
            get => _totalConnectionAttempts;
            set { _totalConnectionAttempts = value; OnPropertyChanged(); }
        }

        public int AlertCount
        {
            get => _alertCount;
            set { _alertCount = value; OnPropertyChanged(); }
        }

        public DateTime LastActivity
        {
            get => _lastActivity;
            set { _lastActivity = value; OnPropertyChanged(); }
        }

        public DateTime CreatedDate { get; set; }
        public DateTime LastStarted { get; set; }

        // ============================================================
        // COMPUTED PROPERTIES
        // ============================================================

        [JsonIgnore]
        public string StatusText => Status switch
        {
            HoneypotStatus.Running => "Running",
            HoneypotStatus.Stopped => "Stopped",
            HoneypotStatus.Starting => "Starting",
            HoneypotStatus.Stopping => "Stopping",
            HoneypotStatus.Paused => "Paused",
            HoneypotStatus.Saved => "Saved",
            _ => "Unknown"
        };

        [JsonIgnore]
        public string SSHStatusText => SSHConnected ? "SSH Connected" :
                                        HasSSHConfigured ? "SSH Configured" : "SSH Not Configured";

        [JsonIgnore]
        public string SSHStatusIcon => SSHConnected ? "🟢" :
                                        HasSSHConfigured ? "🟡" : "🔴";

        [JsonIgnore]
        public string SSHConnectionString => !string.IsNullOrEmpty(SSHHost) && !string.IsNullOrEmpty(SSHUsername)
            ? $"{SSHUsername}@{SSHHost}:{SSHPort}"
            : "Not configured";

        [JsonIgnore]
        public string LastActivityText
        {
            get
            {
                if (LastActivity == DateTime.MinValue)
                    return "Never";

                var elapsed = DateTime.Now - LastActivity;
                if (elapsed.TotalMinutes < 1)
                    return "Just now";
                if (elapsed.TotalHours < 1)
                    return $"{(int)elapsed.TotalMinutes}m ago";
                if (elapsed.TotalDays < 1)
                    return $"{(int)elapsed.TotalHours}h ago";
                return $"{(int)elapsed.TotalDays}d ago";
            }
        }

        // ============================================================
        // INOTIFYPROPERTYCHANGED
        // ============================================================

        public event PropertyChangedEventHandler? PropertyChanged;

        protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }

    // ============================================================
    // ENUMS
    // ============================================================

    public enum HoneypotStatus
    {
        Unknown,
        Running,
        Stopped,
        Starting,
        Stopping,
        Paused,
        Saved,
        Error
    }

    public enum NetworkAdapterType
    {
        None,
        DefaultSwitch,
        Internal,
        External,
        Private,
        NAT,
        Bridged
    }
}