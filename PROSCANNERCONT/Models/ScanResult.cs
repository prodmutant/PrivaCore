using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Media.Imaging;
using System.Text.Json.Serialization; // ADD THIS

namespace PROSCANNERCONT.Models
{
    public class ScanResult : INotifyPropertyChanged
    {
        private BitmapSource? _pageSnapshot;

        public DateTime Timestamp { get; set; }
        public string Type { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public List<string> Details { get; set; } = new List<string>();
        public string Status { get; set; } = "Good";

        // Navigation properties
        public string PageType { get; set; } = string.Empty;
        public Dictionary<string, object> PageState { get; set; } = new Dictionary<string, object>();
        public string ScanId { get; set; } = Guid.NewGuid().ToString();

        // Screenshot properties
        [JsonIgnore]
        public BitmapSource? PageSnapshot
        {
            get => _pageSnapshot;
            set
            {
                if (_pageSnapshot != value)
                {
                    _pageSnapshot = value;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(HasSnapshot));
                }
            }
        }

        [JsonIgnore]
        public bool HasSnapshot => PageSnapshot != null;

        // Base64 encoded screenshot for serialization
        public string SnapshotData { get; set; } = string.Empty;

        public event PropertyChangedEventHandler? PropertyChanged;

        protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }

    // Navigation constants
    public static class PageTypes
    {
        public const string Dashboard = "Dashboard";
        public const string NetworkDiscovery = "Network Discovery";
        public const string NetworkTopology = "Network Topology";
        public const string PortScanner = "PortScanner";
        public const string Miscellaneous = "Miscellaneous";
        public const string TrafficAnalysis = "Traffic Analysis";
        public const string Achievements = "Achievements";
        public const string Settings = "Settings";
        public const string Profile = "Profile";
    }
}