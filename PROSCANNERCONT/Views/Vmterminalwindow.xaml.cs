using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Services;
using PROSCANNERCONT.Utils;

namespace PROSCANNERCONT.Views
{
    public partial class VMTerminalWindow : Window
    {
        private readonly HoneypotVM _vm;
        private readonly SSHConnectionManager _ssh;
        private List<string> _commandHistory;
        private int _historyIndex;
        private CancellationTokenSource? _cts;
        private ObservableCollection<ProcessInfo> _processes;
        private ObservableCollection<ConnectionInfo> _connections;

        public VMTerminalWindow(HoneypotVM vm)
        {
            InitializeComponent();

            _vm = vm ?? throw new ArgumentNullException(nameof(vm));
            _ssh = new SSHConnectionManager();
            _commandHistory = new List<string>();
            _historyIndex = -1;
            _processes = new ObservableCollection<ProcessInfo>();
            _connections = new ObservableCollection<ConnectionInfo>();

            if (ProcessesGrid != null) ProcessesGrid.ItemsSource = _processes;
            if (NetworkGrid != null) NetworkGrid.ItemsSource = _connections;

            Title = "VM Terminal - " + _vm.Name;
            VMNameText.Text = "🖥️ " + _vm.Name;
            VMIdText.Text = "VM ID: " + _vm.HyperVVMId;

            UpdateConnectionStatus();
            ShowWelcomeMessage();

            if (_vm.HasSSHConfigured)
                _ = ConnectSSHAsync();

            Debug.WriteLine("Terminal window opened for VM: " + _vm.Name);
        }

        private async Task ConnectSSHAsync()
        {
            try
            {
                AppendOutput("Connecting via SSH...", "#DCDCAA");
                await _ssh.ConnectAsync(_vm);
                _vm.SSHConnected = true;
                _vm.LastSSHConnection = DateTime.Now;
                UpdateConnectionStatus();
                AppendOutput("SSH connected to " + _vm.SSHConnectionString, "#4EC9B0");
            }
            catch (Exception ex)
            {
                AppendOutput("SSH connection failed: " + ex.Message, "#F48771");
                AppendOutput("You can still use manual commands once connected.", "#808080");
            }
        }

        private async Task<string> RunSSHCommandAsync(string command, string? sudoPass = null)
        {
            if (!_ssh.IsConnected(_vm.HyperVVMId))
                await ConnectSSHAsync();

            Services.SSHCommandResult result;
            if (sudoPass != null)
                result = await _ssh.ExecuteSudoCommandAsync(_vm.HyperVVMId, command, sudoPass);
            else
                result = await _ssh.ExecuteCommandAsync(_vm.HyperVVMId, command);

            if (!result.Success && !string.IsNullOrEmpty(result.Error))
                return result.Output + "\n[stderr] " + result.Error;

            return result.Output;
        }

        private void ShowWelcomeMessage()
        {
            AppendOutput("VM Terminal - " + _vm.Name, "#4EC9B0");
            AppendOutput(new string('=', 60), "#808080");
            AppendOutput("VM ID: " + _vm.HyperVVMId, "#808080");
            AppendOutput("", "White");

            if (_vm.HasSSHConfigured)
            {
                AppendOutput("SSH: " + _vm.SSHConnectionString, "#4EC9B0");
                AppendOutput("Attempting SSH connection...", "#808080");
            }
            else
            {
                AppendOutput("SSH Not Configured", "#F48771");
                AppendOutput("Please configure SSH access in the dashboard first.", "#808080");
            }

            AppendOutput("", "White");
            AppendOutput(new string('=', 60), "#808080");
            AppendOutput("", "White");
        }

        private void UpdateConnectionStatus()
        {
            try
            {
                bool connected = _ssh.IsConnected(_vm.HyperVVMId);
                if (connected)
                {
                    ConnectionStatusIcon.Text = "🟢";
                    ConnectionStatusText.Text = "SSH Connected";
                    ConnectionStatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#4EC9B0"));
                    AgentVersionText.Text = "SSH";
                    LastContactText.Text = _vm.LastSSHConnection != DateTime.MinValue
                        ? _vm.LastSSHConnection.ToString("HH:mm:ss") : "Never";
                }
                else if (_vm.HasSSHConfigured)
                {
                    ConnectionStatusIcon.Text = "🟡";
                    ConnectionStatusText.Text = "SSH Configured";
                    ConnectionStatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#DCDCAA"));
                    AgentVersionText.Text = "Not Connected";
                    LastContactText.Text = "N/A";
                }
                else
                {
                    ConnectionStatusIcon.Text = "🔴";
                    ConnectionStatusText.Text = "Not Configured";
                    ConnectionStatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F48771"));
                    AgentVersionText.Text = "N/A";
                    LastContactText.Text = "Never";
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine("Error updating connection status: " + ex.Message);
            }
        }

        // ============================================================
        // SHELL TAB
        // ============================================================

        private void CommandInput_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter) { ExecuteCommand(); e.Handled = true; }
            else if (e.Key == Key.Up) { NavigateHistory(-1); e.Handled = true; }
            else if (e.Key == Key.Down) { NavigateHistory(1); e.Handled = true; }
        }

        private void NavigateHistory(int direction)
        {
            if (_commandHistory.Count == 0) return;
            _historyIndex += direction;
            if (_historyIndex < 0) _historyIndex = 0;
            else if (_historyIndex >= _commandHistory.Count) { _historyIndex = _commandHistory.Count; CommandInput.Text = ""; return; }
            CommandInput.Text = _commandHistory[_historyIndex];
            CommandInput.CaretIndex = CommandInput.Text.Length;
        }

        private void ExecuteCommand_Click(object sender, RoutedEventArgs e) => ExecuteCommand();

        private async void ExecuteCommand()
        {
            try
            {
                string command = CommandInput.Text?.Trim();
                if (string.IsNullOrEmpty(command)) return;

                _commandHistory.Add(command);
                _historyIndex = _commandHistory.Count;
                AppendOutput("$ " + command, "#4EC9B0");
                CommandInput.Clear();

                if (!_vm.HasSSHConfigured)
                {
                    AppendOutput("Error: SSH not configured. Please configure SSH access in the dashboard.", "#F48771");
                    return;
                }

                try
                {
                    string output = await RunSSHCommandAsync(command);
                    if (!string.IsNullOrEmpty(output))
                        foreach (var line in output.Split('\n'))
                            AppendOutput(line.TrimEnd('\r'), "#D4D4D4");
                    else
                        AppendOutput("(no output)", "#808080");
                }
                catch (Exception ex)
                {
                    AppendOutput("Error: " + ex.Message, "#F48771");
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine("Error executing command: " + ex.Message);
                AppendOutput("Error: " + ex.Message, "#F48771");
            }
        }

        private void ClearShell_Click(object sender, RoutedEventArgs e)
        {
            ShellOutput.Document.Blocks.Clear();
            ShowWelcomeMessage();
        }

        private void AppendOutput(string text, string color)
        {
            try
            {
                Dispatcher.InvokeAsync(() =>
                {
                    var paragraph = new Paragraph(new Run(text))
                    {
                        Margin = new Thickness(0),
                        Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(color))
                    };
                    ShellOutput.Document.Blocks.Add(paragraph);
                    ShellOutput.ScrollToEnd();
                });
            }
            catch (Exception ex) { Debug.WriteLine("Error appending output: " + ex.Message); }
        }

        // ============================================================
        // PORTS TAB
        // ============================================================

        private async void OpenPort_Click(object sender, RoutedEventArgs e)
        {
            if (!int.TryParse(PortNumberInput.Text, out int port) || port < 1 || port > 65535)
            { AppDialog.Show("Please enter a valid port number (1-65535)", "Invalid Port", MessageBoxButton.OK, MessageBoxImage.Warning); return; }
            if (!_vm.HasSSHConfigured)
            { AppDialog.Show("SSH not configured.", "SSH Not Configured", MessageBoxButton.OK, MessageBoxImage.Warning); return; }

            AppendPortLog("Opening port " + port + " (TCP+UDP)...", "#DCDCAA");
            try
            {
                string pass = new SSHConnectionManager().DecryptPassword(_vm.SSHPasswordEncrypted);
                string out1 = await RunSSHCommandAsync("ufw allow " + port + "/tcp", pass);
                string out2 = await RunSSHCommandAsync("ufw allow " + port + "/udp", pass);
                AppendPortLog(out1.Trim(), "#D4D4D4");
                AppendPortLog(out2.Trim(), "#D4D4D4");
                AppendPortLog("Port " + port + " opened.", "#4EC9B0");
            }
            catch (Exception ex) { AppendPortLog("Error: " + ex.Message, "#F48771"); }
        }

        private async void ClosePort_Click(object sender, RoutedEventArgs e)
        {
            if (!int.TryParse(PortNumberInput.Text, out int port) || port < 1 || port > 65535)
            { AppDialog.Show("Please enter a valid port number (1-65535)", "Invalid Port", MessageBoxButton.OK, MessageBoxImage.Warning); return; }
            if (!_vm.HasSSHConfigured)
            { AppDialog.Show("SSH not configured.", "SSH Not Configured", MessageBoxButton.OK, MessageBoxImage.Warning); return; }

            AppendPortLog("Closing port " + port + "...", "#DCDCAA");
            try
            {
                string pass = new SSHConnectionManager().DecryptPassword(_vm.SSHPasswordEncrypted);
                string out1 = await RunSSHCommandAsync("ufw deny " + port + "/tcp", pass);
                string out2 = await RunSSHCommandAsync("ufw deny " + port + "/udp", pass);
                AppendPortLog(out1.Trim(), "#D4D4D4");
                AppendPortLog(out2.Trim(), "#D4D4D4");
                AppendPortLog("Port " + port + " closed.", "#4EC9B0");
            }
            catch (Exception ex) { AppendPortLog("Error: " + ex.Message, "#F48771"); }
        }

        private void QuickPort_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button button && button.Tag is string portStr)
                PortNumberInput.Text = portStr;
        }

        private void AppendPortLog(string text, string color)
        {
            try
            {
                Dispatcher.InvokeAsync(() =>
                {
                    var p = new Paragraph(new Run("[" + DateTime.Now.ToString("HH:mm:ss") + "] " + text))
                    { Margin = new Thickness(0), Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(color)) };
                    PortLog.Document.Blocks.Add(p);
                    PortLog.ScrollToEnd();
                });
            }
            catch (Exception ex) { Debug.WriteLine("Error appending port log: " + ex.Message); }
        }

        // ============================================================
        // SERVICES TAB
        // ============================================================

        private async void InstallService_Click(object sender, RoutedEventArgs e)
        {
            string service = ServiceNameInput.Text?.Trim();
            if (string.IsNullOrEmpty(service)) { AppDialog.Show("Please enter a service name", "Invalid Input", MessageBoxButton.OK, MessageBoxImage.Warning); return; }
            if (!_vm.HasSSHConfigured) { AppDialog.Show("SSH not configured.", "SSH Not Configured", MessageBoxButton.OK, MessageBoxImage.Warning); return; }

            AppendServiceLog("Installing " + service + "...", "#DCDCAA");
            try
            {
                string pass = new SSHConnectionManager().DecryptPassword(_vm.SSHPasswordEncrypted);
                string output = await RunSSHCommandAsync("DEBIAN_FRONTEND=noninteractive apt-get install -y " + service, pass);
                foreach (var line in output.Split('\n')) AppendServiceLog(line.TrimEnd('\r'), "#D4D4D4");
                AppendServiceLog("Done.", "#4EC9B0");
            }
            catch (Exception ex) { AppendServiceLog("Error: " + ex.Message, "#F48771"); }
        }

        private async void StartService_Click(object sender, RoutedEventArgs e) => await ControlService("start");
        private async void StopService_Click(object sender, RoutedEventArgs e) => await ControlService("stop");
        private async void RestartService_Click(object sender, RoutedEventArgs e) => await ControlService("restart");

        private async Task ControlService(string action)
        {
            string service = ServiceNameInput.Text?.Trim();
            if (string.IsNullOrEmpty(service)) { AppDialog.Show("Please enter a service name", "Invalid Input", MessageBoxButton.OK, MessageBoxImage.Warning); return; }
            if (!_vm.HasSSHConfigured) { AppDialog.Show("SSH not configured.", "SSH Not Configured", MessageBoxButton.OK, MessageBoxImage.Warning); return; }

            AppendServiceLog(action.ToUpper() + ": " + service + "...", "#DCDCAA");
            try
            {
                string pass = new SSHConnectionManager().DecryptPassword(_vm.SSHPasswordEncrypted);
                string output = await RunSSHCommandAsync("systemctl " + action + " " + service, pass);
                string status = await RunSSHCommandAsync("systemctl is-active " + service);
                AppendServiceLog(string.IsNullOrWhiteSpace(output) ? "Command sent." : output.Trim(), "#D4D4D4");
                AppendServiceLog("Status: " + status.Trim(), "#4EC9B0");
            }
            catch (Exception ex) { AppendServiceLog("Error: " + ex.Message, "#F48771"); }
        }

        private void AppendServiceLog(string text, string color)
        {
            try
            {
                Dispatcher.InvokeAsync(() =>
                {
                    var p = new Paragraph(new Run("[" + DateTime.Now.ToString("HH:mm:ss") + "] " + text))
                    { Margin = new Thickness(0), Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(color)) };
                    ServiceLog.Document.Blocks.Add(p);
                    ServiceLog.ScrollToEnd();
                });
            }
            catch (Exception ex) { Debug.WriteLine("Error appending service log: " + ex.Message); }
        }

        // ============================================================
        // PROCESSES TAB
        // ============================================================

        private async void RefreshProcesses_Click(object sender, RoutedEventArgs e)
        {
            if (!_vm.HasSSHConfigured) { AppDialog.Show("SSH not configured.", "SSH Not Configured", MessageBoxButton.OK, MessageBoxImage.Warning); return; }

            try
            {
                string output = await RunSSHCommandAsync("ps aux --no-headers");
                Dispatcher.Invoke(() =>
                {
                    _processes.Clear();
                    foreach (var line in output.Split('\n'))
                    {
                        if (string.IsNullOrWhiteSpace(line)) continue;
                        var parts = line.Split(new[] { ' ' }, 11, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length >= 11)
                        {
                            _processes.Add(new ProcessInfo
                            {
                                User = parts[0], PID = parts[1], CPU = parts[2], Mem = parts[3],
                                VSZ = parts[4], RSS = parts[5], Stat = parts[7],
                                Command = parts[10]
                            });
                        }
                    }
                });
            }
            catch (Exception ex) { AppDialog.Show("Error: " + ex.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error); }
        }

        private async void KillProcess_Click(object sender, RoutedEventArgs e)
        {
            if (ProcessesGrid.SelectedItem is not ProcessInfo proc)
            { AppDialog.Show("Please select a process", "No Selection", MessageBoxButton.OK, MessageBoxImage.Warning); return; }

            var confirm = AppDialog.Show("Kill process " + proc.PID + " (" + proc.Command + ")?", "Confirm",
                MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (confirm != MessageBoxResult.Yes) return;

            try
            {
                string pass = new SSHConnectionManager().DecryptPassword(_vm.SSHPasswordEncrypted);
                string output = await RunSSHCommandAsync("kill -9 " + proc.PID, pass);
                AppDialog.Show("Process " + proc.PID + " killed.\n" + output, "Done", MessageBoxButton.OK, MessageBoxImage.Information);
                await Task.Delay(500);
                RefreshProcesses_Click(null, null);
            }
            catch (Exception ex) { AppDialog.Show("Error: " + ex.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error); }
        }

        // ============================================================
        // NETWORK TAB
        // ============================================================

        private async void RefreshConnections_Click(object sender, RoutedEventArgs e)
        {
            if (!_vm.HasSSHConfigured) { AppDialog.Show("SSH not configured.", "SSH Not Configured", MessageBoxButton.OK, MessageBoxImage.Warning); return; }

            try
            {
                string output = await RunSSHCommandAsync("ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null");
                Dispatcher.Invoke(() =>
                {
                    _connections.Clear();
                    bool headerSkipped = false;
                    foreach (var line in output.Split('\n'))
                    {
                        if (string.IsNullOrWhiteSpace(line)) continue;
                        if (!headerSkipped && (line.StartsWith("Netid") || line.StartsWith("Proto"))) { headerSkipped = true; continue; }
                        var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length >= 5)
                        {
                            _connections.Add(new ConnectionInfo
                            {
                                Protocol = parts[0], State = parts.Length > 3 ? parts[1] : "-",
                                LocalAddress = parts.Length > 4 ? parts[4] : parts[2],
                                ForeignAddress = parts.Length > 5 ? parts[5] : (parts.Length > 3 ? parts[3] : "-")
                            });
                        }
                    }
                });
            }
            catch (Exception ex) { AppDialog.Show("Error: " + ex.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error); }
        }

        // ============================================================
        // LOGS TAB
        // ============================================================

        private void ClearLogs_Click(object sender, RoutedEventArgs e) => LogsOutput.Document.Blocks.Clear();

        private void AppendLogEntry(string text, string color)
        {
            try
            {
                Dispatcher.InvokeAsync(() =>
                {
                    var p = new Paragraph(new Run("[" + DateTime.Now.ToString("HH:mm:ss") + "] " + text))
                    { Margin = new Thickness(0), Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(color)) };
                    LogsOutput.Document.Blocks.Add(p);
                    LogsOutput.ScrollToEnd();
                });
            }
            catch (Exception ex) { Debug.WriteLine("Error appending log: " + ex.Message); }
        }

        // ============================================================
        // WINDOW CONTROL
        // ============================================================

        private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ClickCount == 2) Maximize_Click(null, null);
            else DragMove();
        }

        private void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

        private void Maximize_Click(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
        }

        private void RefreshStatus_Click(object sender, RoutedEventArgs e)
        {
            UpdateConnectionStatus();
            bool connected = _ssh.IsConnected(_vm.HyperVVMId);
            AppDialog.Show("SSH Configured: " + _vm.HasSSHConfigured + "\nSSH Connected: " + connected,
                "Status", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void Close_Click(object sender, RoutedEventArgs e) => Close();

        protected override void OnClosed(EventArgs e)
        {
            base.OnClosed(e);
            _ssh.Disconnect(_vm.HyperVVMId);
            Debug.WriteLine("Terminal window closed for VM: " + _vm.Name);
        }
    }

    // ============================================================
    // SUPPORTING VIEW MODELS
    // ============================================================

    public class ProcessInfo
    {
        public string User { get; set; }
        public string PID { get; set; }
        public string CPU { get; set; }
        public string Mem { get; set; }
        public string VSZ { get; set; }
        public string RSS { get; set; }
        public string Stat { get; set; }
        public string Command { get; set; }
    }

    public class ConnectionInfo
    {
        public string Protocol { get; set; }
        public string State { get; set; }
        public string LocalAddress { get; set; }
        public string ForeignAddress { get; set; }
    }
}


