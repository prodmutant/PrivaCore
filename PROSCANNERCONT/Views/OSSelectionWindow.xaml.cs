using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Services;
using PROSCANNERCONT.Utils;

namespace PROSCANNERCONT.Views
{
    public partial class OSSelectionWindow : Window
    {
        private List<OSTemplate> _osTemplates;
        private OSTemplate _selectedTemplate;
        private HyperVManager _hyperVManager;
        private string _selectedISOPath = null;
        private int _selectedGeneration = 1;

        // System specs
        private int _maxRAM;
        private int _maxCPU;
        private int _maxStorage;

        public HoneypotVM CreatedVM { get; private set; }

        public OSSelectionWindow()
        {
            InitializeComponent();

            _hyperVManager = new HyperVManager();

            // Detect system specifications
            DetectSystemSpecs();

            // Load OS templates
            _osTemplates = OSTemplate.GetAllTemplates();
            OSTemplateComboBox.ItemsSource = _osTemplates;
            OSTemplateComboBox.SelectedIndex = 0; // Select TinyCore by default

            // Add event handler for network type selection
            NetworkTypeComboBox.SelectionChanged += NetworkTypeComboBox_SelectionChanged;

            InitializeWindow();
        }

        private void DetectSystemSpecs()
        {
            try
            {
                _maxRAM = SystemSpecsDetector.GetRecommendedMaxRAM();
                _maxCPU = SystemSpecsDetector.GetRecommendedMaxCores();
                _maxStorage = SystemSpecsDetector.GetRecommendedMaxStorage();

                int totalRAM = SystemSpecsDetector.GetTotalRAM();
                int totalCPU = SystemSpecsDetector.GetCPUCores();
                long availableStorage = SystemSpecsDetector.GetAvailableDiskSpace();

                // Update system specs display
                SystemSpecsText.Text = $"System: {totalRAM} MB RAM, {totalCPU} CPU Cores, {availableStorage} GB Available | " +
                                      $"VM Limits: {_maxRAM} MB RAM, {_maxCPU} Cores, {_maxStorage} GB Storage";

                // Update slider maximums dynamically
                MemorySlider.Maximum = _maxRAM;
                MemoryMaxText.Text = $"Max: {_maxRAM} MB";

                CPUSlider.Maximum = _maxCPU;
                CPUMaxText.Text = $"Max: {_maxCPU} Core{(_maxCPU > 1 ? "s" : "")}";

                StorageSlider.Maximum = _maxStorage;
                StorageMaxText.Text = $"Max: {_maxStorage} GB";

                Debug.WriteLine($"System specs detected: RAM={totalRAM}MB (max={_maxRAM}), CPU={totalCPU} (max={_maxCPU}), Storage={availableStorage}GB (max={_maxStorage}GB)");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error detecting system specs: {ex.Message}");
                AppDialog.Show(
                    "Warning: Could not detect system specifications.\n" +
                    "Using default resource limits.",
                    "System Detection Warning",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
            }
        }

        private void OSTemplate_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (OSTemplateComboBox.SelectedItem is OSTemplate template)
            {
                _selectedTemplate = template;

                // Update OS details
                OSCategoryText.Text = $"Category: {template.Category}";
                OSFeaturesText.Text = "Features: " + string.Join(", ", template.Features);

                // Show/hide download link
                if (!string.IsNullOrEmpty(template.ISODownloadURL))
                {
                    ISODownloadLink.Visibility = Visibility.Visible;
                }
                else
                {
                    ISODownloadLink.Visibility = Visibility.Collapsed;
                }

                // Update resource sliders with recommended values
                MemorySlider.Value = Math.Min(template.RecommendedRAM, _maxRAM);
                MemoryRecommendedText.Text = $"Recommended: {template.RecommendedRAM} MB";
                MemoryMinText.Text = $"Min: {template.MinRAM} MB";
                MemorySlider.Minimum = template.MinRAM;

                CPUSlider.Value = Math.Min(template.RecommendedCPU, _maxCPU);
                CPURecommendedText.Text = $"Recommended: {template.RecommendedCPU} Core{(template.RecommendedCPU > 1 ? "s" : "")}";

                StorageSlider.Value = Math.Min(template.RecommendedStorage, _maxStorage);
                StorageRecommendedText.Text = $"Recommended: {template.RecommendedStorage} GB";
                StorageMinText.Text = $"Min: {template.MinStorage} GB";
                StorageSlider.Minimum = template.MinStorage;

                // Set recommended generation
                if (template.RecommendedGeneration == 2)
                {
                    Gen2Radio.IsChecked = true;
                }
                else
                {
                    Gen1Radio.IsChecked = true;
                }

                // Update base image availability
                bool hasBaseImage = template.UsePrebuiltImage && template.IsBaseImageAvailable();

                if (hasBaseImage)
                {
                    UseBaseImageRadio.IsEnabled = true;
                    UseBaseImageRadio.IsChecked = true;
                    BaseImageStatusText.Text = "✓ Base image available - instant deployment";
                    BaseImageStatusText.Foreground = Brushes.LightGreen;
                    StatusText.Text = "Ready to deploy (instant)";
                }
                else
                {
                    UseBaseImageRadio.IsEnabled = false;
                    UseISORadio.IsChecked = true;
                    BaseImageStatusText.Text = "⚠ Base image not available - ISO required";
                    BaseImageStatusText.Foreground = Brushes.Orange;
                    BaseImageRecommendedLabel.Visibility = Visibility.Collapsed;
                    ISOBrowserPanel.Visibility = Visibility.Visible;
                    StatusText.Text = "Please select an ISO file";
                    StatusText.Foreground = Brushes.Orange;
                }

                ValidateConfiguration();
            }
        }

        private async void ISODownloadLink_Click(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            if (_selectedTemplate != null && !string.IsNullOrEmpty(_selectedTemplate.ISODownloadURL))
            {
                try
                {
                    // Ask user where to save
                    var saveFileDialog = new SaveFileDialog
                    {
                        Title = $"Save {_selectedTemplate.DisplayName} ISO",
                        Filter = "ISO Files (*.iso)|*.iso|All Files (*.*)|*.*",
                        FileName = $"{_selectedTemplate.Name}.iso",
                        InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)
                    };

                    if (saveFileDialog.ShowDialog() == true)
                    {
                        string savePath = saveFileDialog.FileName;

                        // Show download progress
                        var progressWindow = new Window
                        {
                            Title = "Downloading ISO",
                            Width = 400,
                            Height = 150,
                            WindowStartupLocation = WindowStartupLocation.CenterOwner,
                            Owner = this,
                            ResizeMode = ResizeMode.NoResize,
                            Background = new SolidColorBrush(Color.FromRgb(30, 30, 30))
                        };

                        var stackPanel = new StackPanel { Margin = new Thickness(20) };
                        var statusText = new TextBlock
                        {
                            Text = $"Downloading {_selectedTemplate.DisplayName}...",
                            Foreground = Brushes.White,
                            FontSize = 14,
                            Margin = new Thickness(0, 0, 0, 10)
                        };
                        var progressBar = new System.Windows.Controls.ProgressBar
                        {
                            Height = 25,
                            Margin = new Thickness(0, 0, 0, 10)
                        };
                        var progressText = new TextBlock
                        {
                            Text = "0%",
                            Foreground = Brushes.LightGray,
                            FontSize = 12
                        };

                        stackPanel.Children.Add(statusText);
                        stackPanel.Children.Add(progressBar);
                        stackPanel.Children.Add(progressText);
                        progressWindow.Content = stackPanel;

                        progressWindow.Show();

                        // Download the file
                        using (var client = new System.Net.WebClient())
                        {
                            client.DownloadProgressChanged += (s, args) =>
                            {
                                Dispatcher.Invoke(() =>
                                {
                                    progressBar.Value = args.ProgressPercentage;
                                    progressText.Text = $"{args.ProgressPercentage}% ({args.BytesReceived / 1024 / 1024} MB / {args.TotalBytesToReceive / 1024 / 1024} MB)";
                                });
                            };

                            client.DownloadFileCompleted += (s, args) =>
                            {
                                Dispatcher.Invoke(() =>
                                {
                                    progressWindow.Close();

                                    if (args.Error != null)
                                    {
                                        AppDialog.Show(
                                            $"Download failed:\n{args.Error.Message}\n\nOpening download page in browser instead...",
                                            "Download Error",
                                            MessageBoxButton.OK,
                                            MessageBoxImage.Error);

                                        // Fallback to browser
                                        Process.Start(new ProcessStartInfo
                                        {
                                            FileName = _selectedTemplate.ISODownloadURL,
                                            UseShellExecute = true
                                        });
                                    }
                                    else
                                    {
                                        AppDialog.Show(
                                            $"Download complete!\n\nSaved to:\n{savePath}\n\nYou can now use this ISO to deploy honeypots.",
                                            "Download Complete",
                                            MessageBoxButton.OK,
                                            MessageBoxImage.Information);

                                        // Auto-select the downloaded ISO
                                        _selectedISOPath = savePath;
                                        ISOPathTextBox.Text = savePath;
                                        ISOValidationText.Visibility = Visibility.Visible;
                                        ISOValidationText.Text = $"✓ Downloaded ISO ready";
                                        UseISORadio.IsChecked = true;
                                    }
                                });
                            };

                            try
                            {
                                await client.DownloadFileTaskAsync(new Uri(_selectedTemplate.ISODownloadURL), savePath);
                            }
                            catch (Exception downloadEx)
                            {
                                Dispatcher.Invoke(() =>
                                {
                                    progressWindow.Close();
                                    AppDialog.Show(
                                        $"Download failed:\n{downloadEx.Message}\n\nOpening download page in browser instead...",
                                        "Download Error",
                                        MessageBoxButton.OK,
                                        MessageBoxImage.Error);

                                    // Fallback to browser
                                    Process.Start(new ProcessStartInfo
                                    {
                                        FileName = _selectedTemplate.ISODownloadURL,
                                        UseShellExecute = true
                                    });
                                });
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    AppDialog.Show($"Could not start download:\n{ex.Message}", "Error",
                        MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void NetworkTypeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (NetworkDescriptionText == null || NetworkTypeComboBox == null)
                return;

            switch (NetworkTypeComboBox.SelectedIndex)
            {
                case 0: // NAT
                    NetworkDescriptionText.Text = "💡 NAT isolates the honeypot from your network while allowing outbound internet access";
                    NetworkDescriptionText.Foreground = new SolidColorBrush(Color.FromRgb(78, 201, 176));
                    break;
                case 1: // Bridged
                    NetworkDescriptionText.Text = "⚠ Bridged gives the VM direct access to your physical network";
                    NetworkDescriptionText.Foreground = new SolidColorBrush(Color.FromRgb(244, 135, 113));
                    break;
                case 2: // Internal
                    NetworkDescriptionText.Text = "📡 Internal allows VMs to communicate with each other and the host";
                    NetworkDescriptionText.Foreground = new SolidColorBrush(Color.FromRgb(156, 220, 254));
                    break;
                case 3: // Private
                    NetworkDescriptionText.Text = "🔒 Private completely isolates the VM - no network access";
                    NetworkDescriptionText.Foreground = new SolidColorBrush(Color.FromRgb(206, 145, 120));
                    break;
            }
        }

        private void InitializeWindow()
        {
            VMNameTextBox.Text = $"honeypot-{DateTime.Now:yyyyMMdd-HHmmss}";
            ValidateConfiguration();
        }

        private void Generation_Changed(object sender, RoutedEventArgs e)
        {
            if (Gen1Radio == null || Gen2Radio == null || Gen1Border == null || Gen2Border == null)
                return;

            if (Gen1Radio.IsChecked == true)
            {
                _selectedGeneration = 1;
                Gen1Border.BorderBrush = new SolidColorBrush(Color.FromRgb(0, 122, 204));
                Gen1Border.BorderThickness = new Thickness(2);
                Gen2Border.BorderBrush = new SolidColorBrush(Color.FromRgb(62, 62, 66));
                Gen2Border.BorderThickness = new Thickness(1);

                if (GenerationRecommendationText != null)
                {
                    GenerationRecommendationText.Text = "💡 Generation 1 is recommended for most Linux distributions";
                    GenerationRecommendationText.Foreground = new SolidColorBrush(Color.FromRgb(78, 201, 176));
                }
            }
            else if (Gen2Radio.IsChecked == true)
            {
                _selectedGeneration = 2;
                Gen2Border.BorderBrush = new SolidColorBrush(Color.FromRgb(197, 134, 192));
                Gen2Border.BorderThickness = new Thickness(2);
                Gen1Border.BorderBrush = new SolidColorBrush(Color.FromRgb(62, 62, 66));
                Gen1Border.BorderThickness = new Thickness(1);

                if (GenerationRecommendationText != null)
                {
                    GenerationRecommendationText.Text = "⚠ Generation 2 requires UEFI-compatible ISOs";
                    GenerationRecommendationText.Foreground = new SolidColorBrush(Color.FromRgb(244, 135, 113));
                }
            }
        }

        private void InstallationSource_Changed(object sender, RoutedEventArgs e)
        {
            if (ISOBrowserPanel == null) return;

            if (UseISORadio.IsChecked == true)
            {
                ISOBrowserPanel.Visibility = Visibility.Visible;
                StatusText.Text = "Please select an ISO file";
                StatusText.Foreground = Brushes.Orange;
            }
            else
            {
                ISOBrowserPanel.Visibility = Visibility.Collapsed;
                StatusText.Text = "Ready to deploy (instant)";
                StatusText.Foreground = Brushes.LightGreen;
            }

            ValidateConfiguration();
        }

        private void BrowseISO_Click(object sender, RoutedEventArgs e)
        {
            var openFileDialog = new OpenFileDialog
            {
                Title = $"Select {_selectedTemplate?.DisplayName ?? "ISO"} ISO File",
                Filter = "ISO Files (*.iso)|*.iso|All Files (*.*)|*.*",
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                CheckFileExists = true
            };

            if (openFileDialog.ShowDialog() == true)
            {
                _selectedISOPath = openFileDialog.FileName;
                ISOPathTextBox.Text = _selectedISOPath;

                if (File.Exists(_selectedISOPath))
                {
                    FileInfo fileInfo = new FileInfo(_selectedISOPath);
                    ISOValidationText.Visibility = Visibility.Visible;
                    ISOValidationText.Text = $"✓ Valid ISO ({fileInfo.Length / 1024 / 1024} MB)";
                    ISOErrorText.Visibility = Visibility.Collapsed;
                    StatusText.Text = "Ready to deploy";
                    StatusText.Foreground = Brushes.LightGreen;
                }
                else
                {
                    ISOValidationText.Visibility = Visibility.Collapsed;
                    ISOErrorText.Visibility = Visibility.Visible;
                    StatusText.Text = "Invalid ISO file";
                    StatusText.Foreground = Brushes.Red;
                }

                ValidateConfiguration();
            }
        }

        private void VMNameTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            ValidateConfiguration();
        }

        private void MemorySlider_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            if (MemoryValueText != null)
            {
                MemoryValueText.Text = $"{(int)e.NewValue} MB";
            }
        }

        private void CPUSlider_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            if (CPUValueText != null)
            {
                int cores = (int)e.NewValue;
                CPUValueText.Text = $"{cores} Core{(cores > 1 ? "s" : "")}";
            }
        }

        private void StorageSlider_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            if (StorageValueText != null)
            {
                StorageValueText.Text = $"{(int)e.NewValue} GB";
            }
        }

        private bool ValidateConfiguration()
        {
            bool isValid = true;

            if (string.IsNullOrWhiteSpace(VMNameTextBox?.Text))
            {
                if (VMNameError != null)
                    VMNameError.Visibility = Visibility.Visible;
                isValid = false;
            }
            else
            {
                if (VMNameError != null)
                    VMNameError.Visibility = Visibility.Collapsed;
            }

            if (UseISORadio?.IsChecked == true)
            {
                if (string.IsNullOrEmpty(_selectedISOPath) || !File.Exists(_selectedISOPath))
                {
                    isValid = false;
                }
            }

            if (DeployButton != null)
            {
                DeployButton.IsEnabled = isValid;
            }

            return isValid;
        }

        private async void DeployButton_Click(object sender, RoutedEventArgs e)
        {
            if (!ValidateConfiguration())
                return;

            if (_selectedTemplate == null)
            {
                AppDialog.Show("Please select an operating system", "No OS Selected",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            DeployButton.IsEnabled = false;
            CancelButton.IsEnabled = false;
            this.Cursor = System.Windows.Input.Cursors.Wait;

            try
            {
                StatusText.Text = "Creating honeypot...";
                StatusText.Foreground = Brushes.Yellow;

                var vmConfig = new HoneypotVM
                {
                    Name = VMNameTextBox.Text.Trim(),
                    OSType = _selectedTemplate.DisplayName,
                    MemoryMB = (int)MemorySlider.Value,
                    CPUCores = (int)CPUSlider.Value,
                    StorageSizeGB = (int)StorageSlider.Value,
                    NetworkType = GetNetworkAdapterType(),
                    NetworkAdapter = GetNetworkAdapterName(),
                    CreatedDate = DateTime.Now,
                    Status = HoneypotStatus.Stopped,
                    ProfileType = HoneypotProfileType.Basic,
                    SSHHost = null,
                    SSHUsername = null,
                    SSHPasswordEncrypted = null
                };

                if (!_hyperVManager.IsHyperVAvailable())
                {
                    AppDialog.Show(
                        "Hyper-V is not available.\n\nPlease ensure:\n" +
                        "1. Hyper-V is installed\n" +
                        "2. You're running as Administrator\n" +
                        "3. Hyper-V services are running",
                        "Hyper-V Not Available",
                        MessageBoxButton.OK,
                        MessageBoxImage.Error);
                    return;
                }

                string vmId;
                bool isPreConfigured = false;

                if (UseBaseImageRadio.IsChecked == true && _selectedTemplate.IsBaseImageAvailable())
                {
                    StatusText.Text = "Deploying from base image...";
                    vmId = await _hyperVManager.CreateVMFromBaseImage(vmConfig, _selectedTemplate.BaseImagePath, _selectedGeneration);
                    isPreConfigured = true;
                }
                else
                {
                    StatusText.Text = $"Installing from ISO (Generation {_selectedGeneration})...";
                    vmId = await _hyperVManager.CreateVirtualMachine(vmConfig, _selectedISOPath, _selectedGeneration);
                    isPreConfigured = false;
                }

                vmConfig.HyperVVMId = vmId;
                CreatedVM = vmConfig;

                StatusText.Text = "✓ Honeypot deployed successfully!";
                StatusText.Foreground = Brushes.LightGreen;

                await System.Threading.Tasks.Task.Delay(500);

                string sshInfo = isPreConfigured
                    ? "SSH pre-configured ✓ (Configure in dashboard)"
                    : "Manual OS installation required - Configure SSH after setup";

                AppDialog.Show(
                    $"Honeypot '{vmConfig.Name}' deployed successfully!\n\n" +
                    $"📊 Configuration:\n" +
                    $"  • OS: {_selectedTemplate.DisplayName}\n" +
                    $"  • Generation: {_selectedGeneration}\n" +
                    $"  • Memory: {vmConfig.MemoryMB} MB\n" +
                    $"  • CPU: {vmConfig.CPUCores} core(s)\n" +
                    $"  • Storage: {vmConfig.StorageSizeGB} GB\n" +
                    $"  • Network: {vmConfig.NetworkAdapter}\n\n" +
                    $"🔐 SSH Status: {sshInfo}",
                    "Deployment Successful",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);

                DialogResult = true;
                Close();
            }
            catch (Exception ex)
            {
                StatusText.Text = "❌ Deployment failed";
                StatusText.Foreground = Brushes.Red;

                AppDialog.Show(
                    $"Failed to deploy honeypot:\n\n{ex.Message}",
                    "Deployment Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);

                DeployButton.IsEnabled = true;
                CancelButton.IsEnabled = true;
                this.Cursor = System.Windows.Input.Cursors.Arrow;
            }
        }

        private NetworkAdapterType GetNetworkAdapterType()
        {
            int selectedIndex = NetworkTypeComboBox.SelectedIndex;
            return selectedIndex switch
            {
                0 => NetworkAdapterType.NAT,
                1 => NetworkAdapterType.Bridged,
                2 => NetworkAdapterType.Internal,
                3 => NetworkAdapterType.Private,
                _ => NetworkAdapterType.NAT
            };
        }

        private string GetNetworkAdapterName()
        {
            int selectedIndex = NetworkTypeComboBox.SelectedIndex;
            return selectedIndex switch
            {
                0 => "NAT",
                1 => "Bridged",
                2 => "Internal",
                3 => "Private",
                _ => "NAT"
            };
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }
    }
}


