using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Services;
using PROSCANNERCONT.Utils;

namespace PROSCANNERCONT.Views
{
    public partial class Add : Page
    {
        private readonly ScanProfileService _profileService = new();
        private ObservableCollection<ScanProfile> _profiles = new();

        public Add()
        {
            InitializeComponent();
            ProfilesList.ItemsSource = _profiles;
            LoadProfiles();
        }

        // â”€â”€ Focus ring for the icon-prefix target input â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        private void TargetBox_GotFocus(object sender, RoutedEventArgs e)
        {
            TargetInputBorder.BorderBrush = (Brush)FindResource("AccentBrush");
        }

        private void TargetBox_LostFocus(object sender, RoutedEventArgs e)
        {
            TargetInputBorder.BorderBrush = (Brush)FindResource("BorderBrush");
        }

        // â”€â”€ Port preset chips â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        private void PortPreset_Checked(object sender, RoutedEventArgs e)
        {
            if (StartPortBox == null || EndPortBox == null) return;

            var (start, end) = (sender as System.Windows.Controls.Primitives.ToggleButton)?.Name switch
            {
                "PortPreset_Quick"    => (1,   100),
                "PortPreset_Standard" => (1,   1024),
                "PortPreset_Common"   => (1,   8080),
                "PortPreset_Full"     => (1,   65535),
                _                     => (-1,  -1)
            };

            if (start > 0)
            {
                StartPortBox.Text = start.ToString();
                EndPortBox.Text   = end.ToString();
            }
        }

        // â”€â”€ Quick preset buttons â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        private void QuickPreset_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not Button btn) return;

            switch (btn.Tag?.ToString())
            {
                case "WebServer":
                    ApplyPreset(startPort: 1, endPort: 8443,
                        scanTypeName: "ScanType_TcpConnect",
                        timeout: 2000, concurrent: 50,
                        versions: true, cves: false,
                        profileHint: "Web Server Check");
                    break;

                case "SshAdmin":
                    ApplyPreset(startPort: 1, endPort: 1024,
                        scanTypeName: "ScanType_TcpSyn",
                        timeout: 1500, concurrent: 40,
                        versions: true, cves: true,
                        profileHint: "SSH / Admin Audit");
                    break;

                case "Database":
                    ApplyPreset(startPort: 1, endPort: 1024,
                        scanTypeName: "ScanType_TcpConnect",
                        timeout: 2000, concurrent: 30,
                        versions: true, cves: true,
                        profileHint: "Database Scan");
                    break;

                case "FullAudit":
                    ApplyPreset(startPort: 1, endPort: 65535,
                        scanTypeName: "ScanType_TcpConnect",
                        timeout: 3000, concurrent: 100,
                        versions: true, cves: true,
                        profileHint: "Full Port Audit");
                    break;

                case "StealthRecon":
                    ApplyPreset(startPort: 1, endPort: 1024,
                        scanTypeName: "ScanType_TcpSyn",
                        timeout: 1000, concurrent: 25,
                        versions: false, cves: false,
                        profileHint: "Stealth Recon");
                    break;
            }

            HideValidation();
        }

        private void ApplyPreset(int startPort, int endPort, string scanTypeName,
            int timeout, int concurrent, bool versions, bool cves, string profileHint)
        {
            StartPortBox.Text  = startPort.ToString();
            EndPortBox.Text    = endPort.ToString();
            TimeoutBox.Text    = timeout.ToString();
            ConcurrentBox.Text = concurrent.ToString();
            DetectVersionsCheck.IsChecked = versions;
            CheckCvesCheck.IsChecked      = cves;

            // Select the matching port preset chip
            if      (startPort == 1 && endPort == 100)   PortPreset_Quick.IsChecked    = true;
            else if (startPort == 1 && endPort == 1024)  PortPreset_Standard.IsChecked = true;
            else if (startPort == 1 && endPort == 8080)  PortPreset_Common.IsChecked   = true;
            else if (startPort == 1 && endPort == 8443)  PortPreset_Custom.IsChecked   = true;
            else if (startPort == 1 && endPort == 65535) PortPreset_Full.IsChecked     = true;
            else                                         PortPreset_Custom.IsChecked   = true;

            // Select scan type
            if (FindName(scanTypeName) is System.Windows.Controls.Primitives.ToggleButton tb)
                tb.IsChecked = true;

            // Suggest a profile name if the field is empty
            if (string.IsNullOrWhiteSpace(ProfileNameBox.Text))
                ProfileNameBox.Text = profileHint;
        }

        // â”€â”€ Profile list â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        private void LoadProfiles()
        {
            _profileService.Load();
            _profiles.Clear();
            foreach (var p in _profileService.Profiles)
                _profiles.Add(p);

            bool has = _profiles.Count > 0;
            NoProfilesText.Visibility = has ? Visibility.Collapsed : Visibility.Visible;
            ProfilesList.Visibility   = has ? Visibility.Visible   : Visibility.Collapsed;
        }

        private void ProfilesList_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (ProfilesList.SelectedItem is not ScanProfile p) return;
            PopulateForm(p);
        }

        private void PopulateForm(ScanProfile p)
        {
            ProfileNameBox.Text   = p.Name;
            TargetBox.Text        = p.Target;
            DescriptionBox.Text   = p.Description;
            StartPortBox.Text     = p.StartPort.ToString();
            EndPortBox.Text       = p.EndPort.ToString();
            TimeoutBox.Text       = p.TimeoutMs.ToString();
            ConcurrentBox.Text    = p.MaxConcurrent.ToString();
            DetectVersionsCheck.IsChecked = p.DetectVersions;
            CheckCvesCheck.IsChecked      = p.CheckCves;

            // Restore port preset chip
            if      (p.StartPort == 1 && p.EndPort == 100)   PortPreset_Quick.IsChecked    = true;
            else if (p.StartPort == 1 && p.EndPort == 1024)  PortPreset_Standard.IsChecked = true;
            else if (p.StartPort == 1 && p.EndPort == 8080)  PortPreset_Common.IsChecked   = true;
            else if (p.StartPort == 1 && p.EndPort == 65535) PortPreset_Full.IsChecked     = true;
            else                                              PortPreset_Custom.IsChecked   = true;

            // Restore scan type card
            var scanTypeName = p.ScanType.ToLowerInvariant() switch
            {
                var s when s.Contains("syn")     => "ScanType_TcpSyn",
                var s when s.Contains("ack")     => "ScanType_TcpAck",
                var s when s.Contains("fin")     => "ScanType_TcpFin",
                var s when s.Contains("xmas")    => "ScanType_Xmas",
                var s when s.Contains("udp")     => "ScanType_Udp",
                _                                => "ScanType_TcpConnect"
            };
            if (FindName(scanTypeName) is System.Windows.Controls.Primitives.ToggleButton tb)
                tb.IsChecked = true;

            HideValidation();
        }

        private void DeleteProfile_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not Button btn) return;
            var id = btn.Tag?.ToString();
            if (string.IsNullOrEmpty(id)) return;

            var p = _profiles.FirstOrDefault(x => x.Id == id);
            if (p == null) return;

            if (AppDialog.Show($"Delete profile \"{p.Name}\"?", "Confirm Delete",
                    MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;

            _profileService.Delete(id);
            LoadProfiles();
        }

        // â”€â”€ Action buttons â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        private void StartScanButton_Click(object sender, RoutedEventArgs e)
        {
            if (!TryBuildProfile(out var profile, out var error))
            {
                ShowValidation(error);
                return;
            }

            HideValidation();

            if (Window.GetWindow(this) is not MainWindow main) return;

            main.NavigateToPageWithState("Port Scanner", new System.Collections.Generic.Dictionary<string, object>
            {
                ["target"]         = profile.Target,
                ["startPort"]      = profile.StartPort,
                ["endPort"]        = profile.EndPort,
                ["scanType"]       = profile.ScanType,
                ["timeoutMs"]      = profile.TimeoutMs,
                ["maxConcurrent"]  = profile.MaxConcurrent,
                ["detectVersions"] = profile.DetectVersions,
                ["checkCves"]      = profile.CheckCves,
            });
        }

        private void SaveProfileButton_Click(object sender, RoutedEventArgs e)
        {
            if (!TryBuildProfile(out var profile, out var error))
            {
                ShowValidation(error);
                return;
            }

            if (string.IsNullOrWhiteSpace(profile.Name))
            {
                ShowValidation("Enter a profile name before saving.");
                ProfileNameBox.Focus();
                return;
            }

            _profileService.Save(profile);
            LoadProfiles();
            HideValidation();
            AppDialog.Show($"Profile \"{profile.Name}\" saved.", "Saved",
                MessageBoxButton.OK, MessageBoxImage.Information);
        }

        // â”€â”€ Build profile from current form state â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        private bool TryBuildProfile(out ScanProfile profile, out string error)
        {
            profile = new ScanProfile();
            error   = string.Empty;

            if (string.IsNullOrWhiteSpace(TargetBox.Text))
            {
                error = "Target host or IP is required.";
                TargetBox.Focus();
                return false;
            }

            if (!int.TryParse(StartPortBox.Text, out int start) || start < 1 || start > 65535)
            {
                error = "Start port must be between 1 and 65535.";
                StartPortBox.Focus();
                return false;
            }

            if (!int.TryParse(EndPortBox.Text, out int end) || end < 1 || end > 65535)
            {
                error = "End port must be between 1 and 65535.";
                EndPortBox.Focus();
                return false;
            }

            if (start > end)
            {
                error = "Start port cannot be greater than end port.";
                StartPortBox.Focus();
                return false;
            }

            if (!int.TryParse(TimeoutBox.Text, out int timeout) || timeout < 100 || timeout > 60000)
            {
                error = "Timeout must be between 100 and 60000 ms.";
                TimeoutBox.Focus();
                return false;
            }

            if (!int.TryParse(ConcurrentBox.Text, out int concurrent) || concurrent < 1 || concurrent > 500)
            {
                error = "Max concurrent must be between 1 and 500.";
                ConcurrentBox.Focus();
                return false;
            }

            string scanType = "TCP Connect";
            if      (ScanType_TcpSyn.IsChecked  == true) scanType = "TCP SYN";
            else if (ScanType_TcpAck.IsChecked  == true) scanType = "TCP ACK";
            else if (ScanType_TcpFin.IsChecked  == true) scanType = "TCP FIN";
            else if (ScanType_Xmas.IsChecked    == true) scanType = "XMAS";
            else if (ScanType_Udp.IsChecked     == true) scanType = "UDP";

            profile.Name           = ProfileNameBox.Text.Trim();
            profile.Target         = TargetBox.Text.Trim();
            profile.Description    = DescriptionBox.Text.Trim();
            profile.StartPort      = start;
            profile.EndPort        = end;
            profile.ScanType       = scanType;
            profile.TimeoutMs      = timeout;
            profile.MaxConcurrent  = concurrent;
            profile.DetectVersions = DetectVersionsCheck.IsChecked == true;
            profile.CheckCves      = CheckCvesCheck.IsChecked == true;

            return true;
        }

        // â”€â”€ Validation helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        private void ShowValidation(string msg)
        {
            ValidationText.Text = msg;
            ValidationBorder.Visibility = Visibility.Visible;
        }

        private void HideValidation()
        {
            ValidationBorder.Visibility = Visibility.Collapsed;
        }
    }
}



