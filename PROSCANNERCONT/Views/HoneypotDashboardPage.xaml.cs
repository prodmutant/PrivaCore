using PROSCANNERCONT.Models;
using PROSCANNERCONT.Services;
using PROSCANNERCONT.Views;
using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Collections.Generic;
using PROSCANNERCONT.Utils;

namespace PROSCANNERCONT.Views
{
    public partial class HoneypotDashboardPage : Page
    {
        private HyperVManager _hyperVManager;
        private ObservableCollection<HoneypotVM> _honeypots;
        private ObservableCollection<HoneypotVM> _filteredHoneypots;
        private System.Windows.Threading.DispatcherTimer _refreshTimer;
        private string _currentFilter = "All";

        public HoneypotDashboardPage()
        {
            try
            {
                Debug.WriteLine("=== HoneypotDashboardPage: Starting initialization ===");

                InitializeComponent();
                Debug.WriteLine("HoneypotDashboardPage: InitializeComponent completed");

                _honeypots = new ObservableCollection<HoneypotVM>();
                _filteredHoneypots = new ObservableCollection<HoneypotVM>();
                Debug.WriteLine("HoneypotDashboardPage: ObservableCollections created");

                VMListControl.ItemsSource = _filteredHoneypots;
                Debug.WriteLine("HoneypotDashboardPage: ItemsSource set");

                // Initialize HyperV Manager with error handling
                try
                {
                    _hyperVManager = new HyperVManager();
                    Debug.WriteLine("HoneypotDashboardPage: HyperVManager created successfully");
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"HoneypotDashboardPage: HyperVManager creation failed: {ex.Message}");
                    AppDialog.Show(
                        $"Warning: Could not connect to Hyper-V.\n\n" +
                        $"Error: {ex.Message}\n\n" +
                        $"The dashboard will load but VM management will be limited.\n" +
                        $"Please ensure:\n" +
                        $"1. Hyper-V is installed\n" +
                        $"2. You're running as Administrator\n" +
                        $"3. Hyper-V services are running",
                        "Hyper-V Connection Warning",
                        MessageBoxButton.OK,
                        MessageBoxImage.Warning);

                    _hyperVManager = null;
                }

                InitializeDashboard();

                // Set up auto-refresh timer (every 5 seconds)
                _refreshTimer = new System.Windows.Threading.DispatcherTimer();
                _refreshTimer.Interval = TimeSpan.FromSeconds(5);
                _refreshTimer.Tick += RefreshTimer_Tick;
                _refreshTimer.Start();
                Debug.WriteLine("HoneypotDashboardPage: Auto-refresh timer started (5 seconds)");

                Debug.WriteLine("=== HoneypotDashboardPage: Initialization completed successfully ===");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"!!! CRITICAL ERROR in HoneypotDashboardPage constructor: {ex.Message}");
                Debug.WriteLine($"Stack trace: {ex.StackTrace}");

                AppDialog.Show(
                    $"Critical error loading Honeypot Dashboard:\n\n{ex.Message}\n\n" +
                    $"Stack Trace:\n{ex.StackTrace}",
                    "Critical Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }

        private void RefreshTimer_Tick(object sender, EventArgs e)
        {
            try
            {
                Debug.WriteLine("RefreshTimer: Auto-refreshing VM states...");
                RefreshVMStates();
                UpdateLastUpdateTime();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"RefreshTimer: Error - {ex.Message}");
            }
        }

        private void RefreshVMStates()
        {
            try
            {
                if (_hyperVManager == null || _honeypots.Count == 0)
                    return;

                foreach (var honeypot in _honeypots)
                {
                    try
                    {
                        var currentState = _hyperVManager.GetVMRealState(honeypot.HyperVVMId);
                        if (honeypot.Status != currentState)
                        {
                            Debug.WriteLine($"RefreshVMStates: {honeypot.Name} state changed from {honeypot.Status} to {currentState}");
                            honeypot.Status = currentState;
                        }
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"RefreshVMStates: Error checking {honeypot.Name}: {ex.Message}");
                    }
                }

                UpdateDashboardStatistics();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"RefreshVMStates: Error - {ex.Message}");
            }
        }

        private void InitializeDashboard()
        {
            try
            {
                Debug.WriteLine("InitializeDashboard: Starting...");

                LoadExistingHoneypots();
                Debug.WriteLine("InitializeDashboard: LoadExistingHoneypots completed");

                UpdateDashboardStatistics();
                UpdateLastUpdateTime();
                Debug.WriteLine("InitializeDashboard: UpdateDashboardStatistics completed");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"!!! ERROR in InitializeDashboard: {ex.Message}");
                AppDialog.Show(
                    $"Error initializing dashboard: {ex.Message}\n\n" +
                    $"The dashboard will continue to load with limited functionality.",
                    "Initialization Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
            }
        }

        private void LoadExistingHoneypots()
        {
            try
            {
                Debug.WriteLine("LoadExistingHoneypots: Starting...");
                _honeypots.Clear();

                if (_hyperVManager == null)
                {
                    Debug.WriteLine("LoadExistingHoneypots: HyperVManager is null, skipping VM load");
                    EmptyStatePanel.Visibility = Visibility.Visible;
                    return;
                }

                if (_hyperVManager.IsHyperVAvailable())
                {
                    Debug.WriteLine("LoadExistingHoneypots: Hyper-V is available, loading VMs...");

                    try
                    {
                        var vms = _hyperVManager.GetAllVMs();
                        Debug.WriteLine($"LoadExistingHoneypots: Retrieved {vms.Count} VMs");

                        foreach (var vm in vms)
                        {
                            Debug.WriteLine($"LoadExistingHoneypots: Adding VM: {vm.Name}");
                            _honeypots.Add(vm);
                        }
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"!!! ERROR loading VMs: {ex.Message}");
                        AppDialog.Show(
                            $"Error loading virtual machines:\n\n{ex.Message}\n\n" +
                            $"You can still add new VMs, but existing VMs may not be visible.",
                            "VM Load Error",
                            MessageBoxButton.OK,
                            MessageBoxImage.Warning);
                    }
                }
                else
                {
                    Debug.WriteLine("LoadExistingHoneypots: Hyper-V is not available");
                    AppDialog.Show(
                        "Hyper-V is not available on this system.\n\n" +
                        "Please ensure Hyper-V is installed and enabled.",
                        "Hyper-V Not Available",
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);
                }

                // Apply current filter
                ApplyFilter();

                // Show/hide empty state
                EmptyStatePanel.Visibility = _honeypots.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
                Debug.WriteLine($"LoadExistingHoneypots: Empty state panel visibility = {EmptyStatePanel.Visibility}");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"!!! ERROR in LoadExistingHoneypots: {ex.Message}");
                Debug.WriteLine($"Stack trace: {ex.StackTrace}");

                AppDialog.Show(
                    $"Error in LoadExistingHoneypots:\n\n{ex.Message}",
                    "Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }


        private void UpdateDashboardStatistics()
        {
            try
            {
                Debug.WriteLine("UpdateDashboardStatistics: Starting...");

                int totalCount = _honeypots.Count;
                int runningCount = _honeypots.Count(h => h.Status == HoneypotStatus.Running);

                // Get all agents
                int sshConnected = _honeypots.Count(h => h.SSHConnected);
                Debug.WriteLine($"UpdateDashboardStatistics: SSH connected VMs: {sshConnected}");
                int connectedAgents = sshConnected;

                int totalAttacks = _honeypots.Sum(h => h.TotalConnectionAttempts);
                int totalAlerts = _honeypots.Sum(h => h.AlertCount);

                // Update UI statistics
                Dispatcher.Invoke(() =>
                {
                    TotalVMsText.Text = totalCount.ToString();
                    TotalActiveText.Text = $"{runningCount} active";

                    RunningVMsText.Text = runningCount.ToString();
                    RunningPercentText.Text = totalCount > 0 ? $"{(runningCount * 100 / totalCount)}%" : "0%";

                    ConnectedAgentsText.Text = connectedAgents.ToString();
                    AgentHealthText.Text = sshConnected > 0
                        ? $"{sshConnected} SSH Active"
                        : "No SSH";

                    AttackAttemptsText.Text = totalAttacks.ToString();
                    AttackRateText.Text = "0/hour";

                    ActiveAlertsText.Text = totalAlerts.ToString();
                });

                Debug.WriteLine($"UpdateDashboardStatistics: Complete - Total={totalCount}, Running={runningCount}, Agents={connectedAgents}");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"!!! ERROR in UpdateDashboardStatistics: {ex.Message}");
                Debug.WriteLine($"Stack trace: {ex.StackTrace}");
            }
        }
        private void UpdateLastUpdateTime()
        {
            LastUpdateText.Text = $"Last updated: {DateTime.Now:HH:mm:ss}";
        }

        #region Filtering and Search

        private void ApplyFilter()
        {
            _filteredHoneypots.Clear();

            IEnumerable<HoneypotVM> filtered = _honeypots;

            // Apply status filter
            switch (_currentFilter)
            {
                case "Running":
                    filtered = filtered.Where(h => h.Status == HoneypotStatus.Running);
                    break;
                case "Stopped":
                    filtered = filtered.Where(h => h.Status == HoneypotStatus.Stopped);
                    break;
                case "Agent":
                    filtered = filtered.Where(h => h.HasSSHConfigured);
                    break;
            }

            // Apply search filter
            if (!string.IsNullOrWhiteSpace(SearchTextBox.Text) &&
                SearchTextBox.Text != "Search honeypots...")
            {
                string searchTerm = SearchTextBox.Text.ToLower();
                filtered = filtered.Where(h =>
                    h.Name.ToLower().Contains(searchTerm) ||
                    h.OSType.ToLower().Contains(searchTerm));
            }

            foreach (var honeypot in filtered)
            {
                _filteredHoneypots.Add(honeypot);
            }

            EmptyStatePanel.Visibility = _filteredHoneypots.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        }

        private static System.Windows.Media.SolidColorBrush HpBr(string key) =>
            Application.Current.Resources[key] as System.Windows.Media.SolidColorBrush
            ?? new System.Windows.Media.SolidColorBrush(System.Windows.Media.Colors.Gray);

        private void FilterButton_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button button && button.Tag is string filter)
            {
                _currentFilter = filter;

                // Update button styles using dynamic resources
                var inactiveBrush = HpBr("BorderBrush");
                FilterAllButton.Background     = inactiveBrush;
                FilterRunningButton.Background = inactiveBrush;
                FilterStoppedButton.Background = inactiveBrush;
                FilterAgentButton.Background   = inactiveBrush;

                button.Background = HpBr("AccentBrush");

                ApplyFilter();
            }
        }

        private void SearchTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (SearchTextBox.Text == "Search honeypots...")
                return;

            ClearSearchButton.Visibility = string.IsNullOrWhiteSpace(SearchTextBox.Text)
                ? Visibility.Collapsed
                : Visibility.Visible;

            ApplyFilter();
        }

        private void ClearSearch_Click(object sender, RoutedEventArgs e)
        {
            SearchTextBox.Text = "Search honeypots...";
            ClearSearchButton.Visibility = Visibility.Collapsed;
            ApplyFilter();
        }

        #endregion

        #region Button Handlers

        private void AddHoneypot_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                Debug.WriteLine("AddHoneypot_Click: Starting...");

                if (_hyperVManager == null)
                {
                    AppDialog.Show(
                        "Hyper-V Manager is not available.\n\n" +
                        "Please ensure Hyper-V is properly installed and you're running as Administrator.",
                        "Hyper-V Not Available",
                        MessageBoxButton.OK,
                        MessageBoxImage.Warning);
                    return;
                }

                var osSelectionWindow = new OSSelectionWindow();
                osSelectionWindow.Owner = Window.GetWindow(this);

                if (osSelectionWindow.ShowDialog() == true)
                {
                    LoadExistingHoneypots();
                    UpdateDashboardStatistics();

                    AppDialog.Show("Honeypot deployed successfully!",
                        "Success", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"!!! ERROR in AddHoneypot_Click: {ex.Message}");
                AppDialog.Show($"Error deploying honeypot: {ex.Message}",
                    "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void RefreshDashboard_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                Debug.WriteLine("RefreshDashboard_Click: Starting...");

                RefreshButton.IsEnabled = false;
                LoadExistingHoneypots();
                UpdateDashboardStatistics();
                UpdateLastUpdateTime();

                Debug.WriteLine("RefreshDashboard_Click: Completed successfully");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"!!! ERROR in RefreshDashboard_Click: {ex.Message}");
                AppDialog.Show($"Error refreshing dashboard: {ex.Message}",
                    "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                RefreshButton.IsEnabled = true;
            }
        }

        private void ViewHoneypot_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button button && button.Tag is HoneypotVM honeypot)
            {
                try
                {
                    Debug.WriteLine($"ViewHoneypot_Click: Opening console for {honeypot.Name}");

                    var process = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "vmconnect.exe",
                        Arguments = $"localhost \"{honeypot.Name}\"",
                        UseShellExecute = true
                    };

                    System.Diagnostics.Process.Start(process);
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"!!! ERROR in ViewHoneypot_Click: {ex.Message}");
                    AppDialog.Show($"Error opening VM console: {ex.Message}\n\n" +
                        "Make sure Hyper-V tools are installed.",
                        "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        // ✨ NEW: TERMINAL BUTTON HANDLER ✨
        private void TerminalHoneypot_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button button && button.Tag is HoneypotVM honeypot)
            {
                try
                {
                    Debug.WriteLine($"TerminalHoneypot_Click: Opening terminal for {honeypot.Name}");

                    var terminalWindow = new VMTerminalWindow(honeypot);
                    terminalWindow.Owner = Window.GetWindow(this);
                    terminalWindow.Show();
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"!!! ERROR in TerminalHoneypot_Click: {ex.Message}");
                    AppDialog.Show($"Error opening terminal: {ex.Message}",
                        "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private async void StartStopHoneypot_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button button && button.Tag is HoneypotVM honeypot)
            {
                try
                {
                    Debug.WriteLine($"StartStopHoneypot_Click: Toggling state for {honeypot.Name}");

                    if (_hyperVManager == null)
                    {
                        AppDialog.Show("Hyper-V Manager is not available.",
                            "Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                        return;
                    }

                    button.IsEnabled = false;

                    if (honeypot.Status == HoneypotStatus.Running)
                    {
                        await _hyperVManager.StopVM(honeypot.HyperVVMId);
                        honeypot.Status = HoneypotStatus.Stopped;
                        AppDialog.Show($"Honeypot '{honeypot.Name}' stopped successfully.",
                            "Success", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                    else
                    {
                        await _hyperVManager.StartVM(honeypot.HyperVVMId);
                        honeypot.Status = HoneypotStatus.Running;
                        honeypot.LastStarted = DateTime.Now;
                        AppDialog.Show($"Honeypot '{honeypot.Name}' started successfully.",
                            "Success", MessageBoxButton.OK, MessageBoxImage.Information);
                    }

                    UpdateDashboardStatistics();
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"!!! ERROR in StartStopHoneypot_Click: {ex.Message}");
                    AppDialog.Show($"Error controlling VM: {ex.Message}",
                        "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
                finally
                {
                    button.IsEnabled = true;
                }
            }
        }

        private void SettingsHoneypot_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button button && button.Tag is HoneypotVM honeypot)
            {
                try
                {
                    Debug.WriteLine($"SettingsHoneypot_Click: Opening settings for {honeypot.Name}");

                    if (_hyperVManager == null)
                    {
                        AppDialog.Show("Hyper-V Manager is not available.",
                            "Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                        return;
                    }

                    var settingsWindow = new VMSettingsWindow(honeypot, _hyperVManager);
                    settingsWindow.Owner = Window.GetWindow(this);

                    if (settingsWindow.ShowDialog() == true)
                    {
                        LoadExistingHoneypots();
                        UpdateDashboardStatistics();
                        AppDialog.Show("Settings updated successfully!",
                            "Success", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"!!! ERROR in SettingsHoneypot_Click: {ex.Message}");
                    AppDialog.Show($"Error opening settings: {ex.Message}",
                        "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private async void DeleteHoneypot_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button button && button.Tag is HoneypotVM honeypot)
            {
                var result = AppDialog.Show(
                    $"Are you sure you want to delete '{honeypot.Name}'?\n\n" +
                    "This will permanently delete the VM and its virtual hard disk.\n" +
                    "This action cannot be undone.",
                    "Confirm Delete",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Warning);

                if (result == MessageBoxResult.Yes)
                {
                    try
                    {
                        Debug.WriteLine($"DeleteHoneypot_Click: Deleting {honeypot.Name}");

                        if (_hyperVManager == null)
                        {
                            AppDialog.Show("Hyper-V Manager is not available.",
                                "Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                            return;
                        }

                        button.IsEnabled = false;

                        await _hyperVManager.DeleteVM(honeypot.HyperVVMId);
                        _honeypots.Remove(honeypot);
                        ApplyFilter();
                        UpdateDashboardStatistics();

                        AppDialog.Show($"Honeypot '{honeypot.Name}' deleted successfully!",
                            "Success", MessageBoxButton.OK, MessageBoxImage.Information);

                        EmptyStatePanel.Visibility = _honeypots.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"!!! ERROR in DeleteHoneypot_Click: {ex.Message}");
                        AppDialog.Show($"Error deleting honeypot: {ex.Message}",
                            "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                        button.IsEnabled = true;
                    }
                }
            }
        }

        private async void StartAllHoneypots_Click(object sender, RoutedEventArgs e)
        {
            var stoppedVMs = _honeypots.Where(h => h.Status == HoneypotStatus.Stopped).ToList();
            if (stoppedVMs.Count == 0)
            {
                AppDialog.Show("No stopped honeypots to start.", "Info",
                    MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            foreach (var vm in stoppedVMs)
            {
                try
                {
                    await _hyperVManager.StartVM(vm.HyperVVMId);
                    vm.Status = HoneypotStatus.Running;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Error starting {vm.Name}: {ex.Message}");
                }
            }

            UpdateDashboardStatistics();
            AppDialog.Show($"Started {stoppedVMs.Count} honeypot(s).", "Success",
                MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private async void StopAllHoneypots_Click(object sender, RoutedEventArgs e)
        {
            var runningVMs = _honeypots.Where(h => h.Status == HoneypotStatus.Running).ToList();
            if (runningVMs.Count == 0)
            {
                AppDialog.Show("No running honeypots to stop.", "Info",
                    MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            foreach (var vm in runningVMs)
            {
                try
                {
                    await _hyperVManager.StopVM(vm.HyperVVMId);
                    vm.Status = HoneypotStatus.Stopped;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Error stopping {vm.Name}: {ex.Message}");
                }
            }

            UpdateDashboardStatistics();
            AppDialog.Show($"Stopped {runningVMs.Count} honeypot(s).", "Success",
                MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void ViewAlerts_Click(object sender, RoutedEventArgs e)
        {
            AppDialog.Show("Alerts panel - Coming in Phase 2", "Not Implemented",
                MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void AgentDashboard_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button button && button.Tag is HoneypotVM honeypot)
            {
                AppDialog.Show($"Agent dashboard for '{honeypot.Name}' - Coming in Phase 2",
                    "Not Implemented", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        #endregion
    }
}


