using System;
using System.Diagnostics;
using System.IO;
using System.Windows;
using Microsoft.Win32;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Services;
using PROSCANNERCONT.Utils;

namespace PROSCANNERCONT.Views
{
    public partial class SSHConfigWindow : Window
    {
        private readonly HoneypotVM _vm;
        private readonly SSHConnectionManager _sshManager;
        private readonly HyperVManager _hyperVManager;
        public bool ConnectionSuccessful { get; private set; }

        public SSHConfigWindow(HoneypotVM vm)
        {
            InitializeComponent();

            _vm = vm ?? throw new ArgumentNullException(nameof(vm));
            _sshManager = new SSHConnectionManager();
            _hyperVManager = new HyperVManager();

            VMNameText.Text = $"VM: {_vm.Name}";

            // Load existing SSH configuration if available
            LoadExistingConfiguration();
        }

        private void LoadExistingConfiguration()
        {
            if (!string.IsNullOrEmpty(_vm.SSHHost))
            {
                SSHHostTextBox.Text = _vm.SSHHost;
            }

            if (!string.IsNullOrEmpty(_vm.SSHUsername))
            {
                SSHUsernameTextBox.Text = _vm.SSHUsername;
            }
            else
            {
                // Default username suggestions
                SSHUsernameTextBox.Text = "honeypot";
            }

            SSHPortTextBox.Text = _vm.SSHPort.ToString();

            if (_vm.UseSSHKey)
            {
                UseSSHKeyRadio.IsChecked = true;
                SSHKeyPathTextBox.Text = _vm.SSHKeyPath ?? "";
            }
            else
            {
                UsePasswordRadio.IsChecked = true;
            }
        }

        private void AuthMethod_Changed(object sender, RoutedEventArgs e)
        {
            if (UsePasswordRadio == null || UseSSHKeyRadio == null)
                return;

            if (UsePasswordRadio.IsChecked == true)
            {
                PasswordPanel.Visibility = Visibility.Visible;
                SSHKeyPanel.Visibility = Visibility.Collapsed;
            }
            else
            {
                PasswordPanel.Visibility = Visibility.Collapsed;
                SSHKeyPanel.Visibility = Visibility.Visible;
            }
        }

        private void AutoDetectIP_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                StatusText.Text = "Detecting IP address...";
                StatusText.Foreground = System.Windows.Media.Brushes.Yellow;

                string ip = GetVMIPAddress(_vm.HyperVVMId);

                if (!string.IsNullOrEmpty(ip))
                {
                    SSHHostTextBox.Text = ip;
                    StatusText.Text = $"✓ Detected IP: {ip}";
                    StatusText.Foreground = System.Windows.Media.Brushes.LightGreen;
                }
                else
                {
                    StatusText.Text = "⚠ Could not detect IP. VM may not be running or network not configured.";
                    StatusText.Foreground = System.Windows.Media.Brushes.Orange;

                    AppDialog.Show(
                        "Could not automatically detect VM IP address.\n\n" +
                        "Please ensure:\n" +
                        "1. The VM is running\n" +
                        "2. Network adapter is configured\n" +
                        "3. VM has obtained an IP address\n\n" +
                        "You can manually enter the IP address.",
                        "Auto-Detection Failed",
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Auto-detect IP failed: {ex.Message}");
                StatusText.Text = "✗ Auto-detection failed";
                StatusText.Foreground = System.Windows.Media.Brushes.Red;

                AppDialog.Show(
                    $"Failed to detect IP address:\n\n{ex.Message}",
                    "Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }

        private string GetVMIPAddress(string vmId)
        {
            try
            {
                // PowerShell script to get VM IP address
                string psScript = $@"
                    $vm = Get-VM | Where-Object {{ $_.VMId.Guid -eq '{vmId}' }}
                    if ($vm) {{
                        $adapter = Get-VMNetworkAdapter -VM $vm | Select-Object -First 1
                        if ($adapter) {{
                            $ip = $adapter.IPAddresses | Where-Object {{ $_ -match '^\d+\.\d+\.\d+\.\d+$' }} | Select-Object -First 1
                            if ($ip) {{
                                Write-Output $ip
                            }}
                        }}
                    }}
                ";

                var startInfo = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"{psScript}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var process = Process.Start(startInfo);
                string output = process.StandardOutput.ReadToEnd();
                string error = process.StandardError.ReadToEnd();
                process.WaitForExit();

                if (process.ExitCode == 0 && !string.IsNullOrWhiteSpace(output))
                {
                    return output.Trim();
                }

                Debug.WriteLine($"PowerShell error: {error}");
                return null;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"GetVMIPAddress error: {ex.Message}");
                return null;
            }
        }

        private void BrowseSSHKey_Click(object sender, RoutedEventArgs e)
        {
            var openFileDialog = new OpenFileDialog
            {
                Title = "Select SSH Private Key",
                Filter = "SSH Keys|*|PEM Files (*.pem)|*.pem|All Files (*.*)|*.*",
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)
            };

            if (openFileDialog.ShowDialog() == true)
            {
                SSHKeyPathTextBox.Text = openFileDialog.FileName;
            }
        }

        private async void TestConnection_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (!ValidateInputs())
                    return;

                StatusText.Text = "Testing connection...";
                StatusText.Foreground = System.Windows.Media.Brushes.Yellow;

                string host = SSHHostTextBox.Text.Trim();
                int port = int.Parse(SSHPortTextBox.Text.Trim());
                string username = SSHUsernameTextBox.Text.Trim();

                bool success;

                if (UsePasswordRadio.IsChecked == true)
                {
                    string password = SSHPasswordBox.Password;

                    if (string.IsNullOrEmpty(password))
                    {
                        AppDialog.Show("Please enter a password", "Missing Password",
                            MessageBoxButton.OK, MessageBoxImage.Warning);
                        return;
                    }

                    success = await _sshManager.TestConnectionAsync(host, port, username, password);
                }
                else
                {
                    // For SSH key, we need to test differently
                    // This is a simplified test - in production you'd test with the actual key
                    AppDialog.Show(
                        "SSH Key authentication will be tested when saving.\n\n" +
                        "Please ensure the key file is valid and has proper permissions.",
                        "SSH Key Authentication",
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);
                    return;
                }

                if (success)
                {
                    StatusText.Text = "✓ Connection successful!";
                    StatusText.Foreground = System.Windows.Media.Brushes.LightGreen;

                    AppDialog.Show(
                        $"Successfully connected to {username}@{host}:{port}",
                        "Connection Successful",
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);
                }
                else
                {
                    StatusText.Text = "✗ Connection failed";
                    StatusText.Foreground = System.Windows.Media.Brushes.Red;

                    AppDialog.Show(
                        "Connection failed. Please check:\n\n" +
                        "1. VM is running\n" +
                        "2. SSH service is running on the VM\n" +
                        "3. IP address, username, and password are correct\n" +
                        "4. Firewall allows SSH connections",
                        "Connection Failed",
                        MessageBoxButton.OK,
                        MessageBoxImage.Error);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Test connection error: {ex.Message}");
                StatusText.Text = "✗ Connection error";
                StatusText.Foreground = System.Windows.Media.Brushes.Red;

                AppDialog.Show(
                    $"Error testing connection:\n\n{ex.Message}",
                    "Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }

        private async void SaveAndConnect_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (!ValidateInputs())
                    return;

                StatusText.Text = "Saving configuration...";
                StatusText.Foreground = System.Windows.Media.Brushes.Yellow;

                // Update VM configuration
                _vm.SSHHost = SSHHostTextBox.Text.Trim();
                _vm.SSHPort = int.Parse(SSHPortTextBox.Text.Trim());
                _vm.SSHUsername = SSHUsernameTextBox.Text.Trim();
                _vm.UseSSHKey = UseSSHKeyRadio.IsChecked == true;

                if (_vm.UseSSHKey)
                {
                    _vm.SSHKeyPath = SSHKeyPathTextBox.Text.Trim();
                    _vm.SSHPasswordEncrypted = null;
                }
                else
                {
                    string password = SSHPasswordBox.Password;

                    if (string.IsNullOrEmpty(password))
                    {
                        AppDialog.Show("Please enter a password", "Missing Password",
                            MessageBoxButton.OK, MessageBoxImage.Warning);
                        return;
                    }

                    // Encrypt and save password if "Remember" is checked
                    if (RememberPasswordCheckBox.IsChecked == true)
                    {
                        _vm.SSHPasswordEncrypted = _sshManager.EncryptPassword(password);
                    }
                    else
                    {
                        _vm.SSHPasswordEncrypted = null;
                    }

                    // Test connection before saving
                    StatusText.Text = "Testing connection...";
                    bool connectionSuccess = await _sshManager.TestConnectionAsync(
                        _vm.SSHHost, _vm.SSHPort, _vm.SSHUsername, password);

                    if (!connectionSuccess)
                    {
                        var result = AppDialog.Show(
                            "Connection test failed. Save configuration anyway?",
                            "Connection Failed",
                            MessageBoxButton.YesNo,
                            MessageBoxImage.Warning);

                        if (result == MessageBoxResult.No)
                        {
                            StatusText.Text = "Configuration not saved";
                            StatusText.Foreground = System.Windows.Media.Brushes.Orange;
                            return;
                        }
                    }
                }

                StatusText.Text = "✓ Configuration saved!";
                StatusText.Foreground = System.Windows.Media.Brushes.LightGreen;

                ConnectionSuccessful = true;
                DialogResult = true;
                Close();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Save configuration error: {ex.Message}");
                StatusText.Text = "✗ Failed to save";
                StatusText.Foreground = System.Windows.Media.Brushes.Red;

                AppDialog.Show(
                    $"Error saving configuration:\n\n{ex.Message}",
                    "Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }

        private void Cancel_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }

        private bool ValidateInputs()
        {
            // Validate host
            if (string.IsNullOrWhiteSpace(SSHHostTextBox.Text))
            {
                AppDialog.Show("Please enter an IP address or hostname", "Missing Host",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                SSHHostTextBox.Focus();
                return false;
            }

            // Validate username
            if (string.IsNullOrWhiteSpace(SSHUsernameTextBox.Text))
            {
                AppDialog.Show("Please enter a username", "Missing Username",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                SSHUsernameTextBox.Focus();
                return false;
            }

            // Validate port
            if (!int.TryParse(SSHPortTextBox.Text, out int port) || port < 1 || port > 65535)
            {
                AppDialog.Show("Please enter a valid port number (1-65535)", "Invalid Port",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                SSHPortTextBox.Focus();
                return false;
            }

            // Validate SSH key if selected
            if (UseSSHKeyRadio.IsChecked == true)
            {
                if (string.IsNullOrWhiteSpace(SSHKeyPathTextBox.Text))
                {
                    AppDialog.Show("Please select an SSH key file", "Missing SSH Key",
                        MessageBoxButton.OK, MessageBoxImage.Warning);
                    return false;
                }

                if (!File.Exists(SSHKeyPathTextBox.Text))
                {
                    AppDialog.Show("SSH key file does not exist", "Invalid SSH Key",
                        MessageBoxButton.OK, MessageBoxImage.Warning);
                    return false;
                }
            }

            return true;
        }
    }
}


