using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using System.IO;
using System.Text.Json;
using PROSCANNERCONT.Services;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Utils;

namespace PROSCANNERCONT.Views
{
    public partial class ProfilePage : Page, INotifyPropertyChanged
    {
        #region Properties and Fields

        private bool _isEditMode = false;
        private UserProfile? _currentUser;

        public event PropertyChangedEventHandler? PropertyChanged;

        public bool IsEditMode
        {
            get => _isEditMode;
            set
            {
                _isEditMode = value;
                OnPropertyChanged();
                UpdateEditMode();
            }
        }

        #endregion

        #region Constructor and Initialization

        public ProfilePage()
        {
            InitializeComponent();
            LoadUserProfile();
            DataContext = this;
        }

        private void LoadUserProfile()
        {
            _currentUser = LoadSavedProfile() ?? new UserProfile
            {
                FullName = "Admin User",
                Email = "admin@company.com",
                Role = "Security Analyst",
                Department = "Information Security",
                EmployeeId = "EMP-2024-001",
                LastLogin = DateTime.Now,
                TotalScans = 147,
                VulnerabilitiesFound = 23,
                HostsDiscovered = 89,
                AchievementsEarned = 8,
                TotalAchievements = 30
            };

            UpdateUI();
            UpdateLicenseDisplay();
        }

        private void UpdateLicenseDisplay()
        {
            var license = LicenseService.Instance.Current;
            if (LicenseTierText != null)
                LicenseTierText.Text = $"License: {license.TierDisplayName}";

            if (LicenseExpiryText != null)
            {
                LicenseExpiryText.Text = license.Tier == LicenseTier.Free
                    ? "Upgrade to Pro or Enterprise to unlock all features."
                    : license.ExpiresAt == DateTime.MaxValue
                        ? $"Licensed to: {license.LicensedTo}"
                        : $"Licensed to: {license.LicensedTo}  ·  Expires: {license.ExpiresAt:yyyy-MM-dd}";
            }

            if (ActivateLicenseButton != null)
                ActivateLicenseButton.Visibility = license.Tier == LicenseTier.Free
                    ? Visibility.Visible : Visibility.Collapsed;
        }

        private void UpdateUI()
        {
            if (_currentUser != null)
            {
                FullNameTextBox.Text = _currentUser.FullName;
                EmailTextBox.Text = _currentUser.Email;
                DepartmentTextBox.Text = _currentUser.Department;
                EmployeeIdTextBox.Text = _currentUser.EmployeeId;
                LastLoginTextBox.Text = _currentUser.LastLogin.ToString("MMM dd, yyyy - HH:mm");

                TotalScansText.Text = _currentUser.TotalScans.ToString();
                VulnerabilitiesFoundText.Text = _currentUser.VulnerabilitiesFound.ToString();
                HostsDiscoveredText.Text = _currentUser.HostsDiscovered.ToString();
                AchievementsText.Text = $"{_currentUser.AchievementsEarned}/{_currentUser.TotalAchievements}";

                // Set role in ComboBox
                for (int i = 0; i < RoleComboBox.Items.Count; i++)
                {
                    if (((ComboBoxItem)RoleComboBox.Items[i]).Content.ToString() == _currentUser.Role)
                    {
                        RoleComboBox.SelectedIndex = i;
                        break;
                    }
                }
            }
        }

        #endregion

        #region Edit Mode Management

        private void UpdateEditMode()
        {
            // Toggle read-only states
            FullNameTextBox.IsReadOnly = !IsEditMode;
            EmailTextBox.IsReadOnly = !IsEditMode;
            DepartmentTextBox.IsReadOnly = !IsEditMode;
            RoleComboBox.IsEnabled = IsEditMode;

            // Toggle button visibility
            EditProfileButton.Visibility = IsEditMode ? Visibility.Collapsed : Visibility.Visible;
            SaveChangesButton.Visibility = IsEditMode ? Visibility.Visible : Visibility.Collapsed;

            // Update UI styling for edit mode
            if (IsEditMode)
            {
                FullNameTextBox.Background = System.Windows.Media.Brushes.White;
                EmailTextBox.Background = System.Windows.Media.Brushes.White;
                DepartmentTextBox.Background = System.Windows.Media.Brushes.White;
            }
            else
            {
                FullNameTextBox.Background = System.Windows.Media.Brushes.Transparent;
                EmailTextBox.Background = System.Windows.Media.Brushes.Transparent;
                DepartmentTextBox.Background = System.Windows.Media.Brushes.Transparent;
            }
        }

        #endregion

        #region Event Handlers

        private void ActivateLicense_Click(object sender, RoutedEventArgs e)
        {
            // Build a simple inline dialog for key entry
            var keyBox = new TextBox
            {
                Width = 340,
                Margin = new Thickness(0, 8, 0, 0),
                Padding = new Thickness(6, 4, 6, 4),
                FontFamily = new System.Windows.Media.FontFamily("Consolas"),
                Text = "PROS-"
            };
            var panel = new StackPanel { Margin = new Thickness(14) };
            panel.Children.Add(new TextBlock
            {
                Text = "Enter your license key (format: PROS-XXXX-XXXX-XXXX-XXXX):",
                TextWrapping = TextWrapping.Wrap,
                Width = 340
            });
            panel.Children.Add(keyBox);
            var okBtn = new Button { Content = "Activate", Width = 90, Margin = new Thickness(0, 12, 8, 0), IsDefault = true };
            var cancelBtn = new Button { Content = "Cancel",   Width = 90, Margin = new Thickness(0, 12, 0, 0), IsCancel = true };
            var btnRow = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
            btnRow.Children.Add(okBtn);
            btnRow.Children.Add(cancelBtn);
            panel.Children.Add(btnRow);

            var dlg = new Window
            {
                Title = "Activate License",
                Content = panel,
                SizeToContent = SizeToContent.WidthAndHeight,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Owner = Window.GetWindow(this),
                ResizeMode = ResizeMode.NoResize,
                ShowInTaskbar = false
            };
            bool confirmed = false;
            okBtn.Click     += (_, __) => { confirmed = true; dlg.Close(); };
            cancelBtn.Click += (_, __) => dlg.Close();
            dlg.ShowDialog();

            if (!confirmed || string.IsNullOrWhiteSpace(keyBox.Text)) return;

            var result = LicenseService.Instance.Activate(keyBox.Text.Trim());
            if (result.IsValid)
            {
                AppDialog.Show(
                    $"License activated successfully!\nTier: {result.License!.TierDisplayName}",
                    "License Activated", MessageBoxButton.OK, MessageBoxImage.Information);
                UpdateLicenseDisplay();
            }
            else
            {
                AppDialog.Show(
                    $"Activation failed: {result.ErrorMessage}",
                    "Invalid License", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private void EditProfile_Click(object sender, RoutedEventArgs e)
        {
            IsEditMode = true;
            FullNameTextBox.Focus();
        }

        private void SaveChanges_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // Validate input
                if (string.IsNullOrWhiteSpace(FullNameTextBox.Text))
                {
                    AppDialog.Show("Full name is required.", "Validation Error",
                                  MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                if (string.IsNullOrWhiteSpace(EmailTextBox.Text) || !IsValidEmail(EmailTextBox.Text))
                {
                    AppDialog.Show("Please enter a valid email address.", "Validation Error",
                                  MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                // Update user profile
                _currentUser.FullName = FullNameTextBox.Text.Trim();
                _currentUser.Email = EmailTextBox.Text.Trim();
                _currentUser.Department = DepartmentTextBox.Text.Trim();

                if (RoleComboBox.SelectedItem != null)
                {
                    _currentUser.Role = ((ComboBoxItem)RoleComboBox.SelectedItem).Content.ToString();
                }

                // Save changes (implement actual save logic here)
                SaveUserProfile();

                IsEditMode = false;

                AppDialog.Show("Profile updated successfully!", "Success",
                              MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                AppDialog.Show($"Error saving profile: {ex.Message}", "Error",
                              MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ChangePhoto_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                OpenFileDialog openFileDialog = new OpenFileDialog
                {
                    Title = "Select Profile Picture",
                    Filter = "Image files (*.jpg, *.jpeg, *.png, *.bmp)|*.jpg;*.jpeg;*.png;*.bmp",
                    FilterIndex = 1
                };

                if (openFileDialog.ShowDialog() == true)
                {
                    try
                    {
                        var dir = Path.GetDirectoryName(ProfilePath);
                        if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);
                        var destPath = Path.Combine(dir, "avatar" + System.IO.Path.GetExtension(openFileDialog.FileName));
                        File.Copy(openFileDialog.FileName, destPath, true);
                        var bitmap = new System.Windows.Media.Imaging.BitmapImage();
                        bitmap.BeginInit();
                        bitmap.UriSource = new Uri(destPath);
                        bitmap.CacheOption = System.Windows.Media.Imaging.BitmapCacheOption.OnLoad;
                        bitmap.EndInit();
                        if (FindName("ProfileImageLarge") is System.Windows.Controls.Image img) img.Source = bitmap;
                        AppDialog.Show("Profile photo updated.", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                    catch (Exception imgEx)
                    {
                        AppDialog.Show("Could not set photo: " + imgEx.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                }
            }
            catch (Exception ex)
            {
                AppDialog.Show($"Error selecting photo: {ex.Message}", "Error",
                              MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ChangePassword_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new ChangePasswordDialog { Owner = Window.GetWindow(this) };
            if (dlg.ShowDialog() == true)
                AppDialog.Show("Password changed successfully.", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void DownloadReport_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                SaveFileDialog saveFileDialog = new SaveFileDialog
                {
                    Title = "Save Activity Report",
                    Filter = "PDF files (*.pdf)|*.pdf|CSV files (*.csv)|*.csv",
                    FilterIndex = 1,
                    FileName = $"ActivityReport_{DateTime.Now:yyyyMMdd}.pdf"
                };

                if (saveFileDialog.ShowDialog() == true)
                {
                    try
                    {
                        var csv = new System.Text.StringBuilder();
                        csv.AppendLine("PrivaCore Activity Report");
                        csv.AppendLine("Generated: " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
                        csv.AppendLine();
                        csv.AppendLine("Metric,Value");
                        csv.AppendLine("Name," + _currentUser.FullName);
                        csv.AppendLine("Email," + _currentUser.Email);
                        csv.AppendLine("Role," + _currentUser.Role);
                        csv.AppendLine("Department," + _currentUser.Department);
                        csv.AppendLine("Employee ID," + _currentUser.EmployeeId);
                        csv.AppendLine("Last Login," + _currentUser.LastLogin.ToString("yyyy-MM-dd HH:mm:ss"));
                        csv.AppendLine("Total Scans," + _currentUser.TotalScans);
                        csv.AppendLine("Vulnerabilities Found," + _currentUser.VulnerabilitiesFound);
                        csv.AppendLine("Hosts Discovered," + _currentUser.HostsDiscovered);
                        csv.AppendLine("Achievements," + _currentUser.AchievementsEarned + "/" + _currentUser.TotalAchievements);
                        var dest = saveFileDialog.FileName;
                        if (!dest.EndsWith(".csv", StringComparison.OrdinalIgnoreCase)) dest = Path.ChangeExtension(dest, ".csv");
                        File.WriteAllText(dest, csv.ToString());
                        AppDialog.Show("Report saved to:\n" + dest, "Report Saved", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                    catch (Exception repEx)
                    {
                        AppDialog.Show("Could not save report: " + repEx.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                }
            }
            catch (Exception ex)
            {
                AppDialog.Show($"Error downloading report: {ex.Message}", "Error",
                              MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void SignOut_Click(object sender, RoutedEventArgs e)
        {
            var result = AppDialog.Show("Are you sure you want to sign out?", "Sign Out",
                                       MessageBoxButton.YesNo, MessageBoxImage.Question);

            if (result == MessageBoxResult.Yes)
            {
                try
                {
                    SaveUserProfile();
                    Application.Current.Shutdown();
                }
                catch (Exception ex)
                {
                    AppDialog.Show($"Error during sign out: {ex.Message}", "Error",
                                  MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        #endregion

        #region Helper Methods

        private bool IsValidEmail(string email)
        {
            try
            {
                var addr = new System.Net.Mail.MailAddress(email);
                return addr.Address == email;
            }
            catch
            {
                return false;
            }
        }

        private static string ProfilePath => System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PrivaCore", "profile.json");

        private void SaveUserProfile()
        {
            try
            {
                var dir = System.IO.Path.GetDirectoryName(ProfilePath);
                if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);
                var json = System.Text.Json.JsonSerializer.Serialize(_currentUser, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(ProfilePath, json);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine("Profile save failed: " + ex.Message);
            }
        }

        private UserProfile LoadSavedProfile()
        {
            try
            {
                if (File.Exists(ProfilePath))
                {
                    var json = File.ReadAllText(ProfilePath);
                    return System.Text.Json.JsonSerializer.Deserialize<UserProfile>(json);
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine("Profile load failed: " + ex.Message);
            }
            return null;
        }

        protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        #endregion
    }

    #region User Profile Model

    public class UserProfile
    {
        public string FullName { get; set; }
        public string Email { get; set; }
        public string Role { get; set; }
        public string Department { get; set; }
        public string EmployeeId { get; set; }
        public DateTime LastLogin { get; set; }
        public int TotalScans { get; set; }
        public int VulnerabilitiesFound { get; set; }
        public int HostsDiscovered { get; set; }
        public int AchievementsEarned { get; set; }
        public int TotalAchievements { get; set; }
        public bool TwoFactorEnabled { get; set; } = true;
        public bool EmailNotificationsEnabled { get; set; } = true;
        public bool AutoLockEnabled { get; set; } = false;
    }

    #endregion
}


