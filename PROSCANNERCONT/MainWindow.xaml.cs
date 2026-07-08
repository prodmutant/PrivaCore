using FontAwesome.Sharp;
using PROSCANNERCONT.Animations;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Security.Auth;
using PROSCANNERCONT.Services;
using PROSCANNERCONT.Utils;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Threading;

namespace PROSCANNERCONT
{
    public static class NavButtonHelper
    {
        public static readonly DependencyProperty IsActiveProperty =
            DependencyProperty.RegisterAttached(
                "IsActive", typeof(bool), typeof(NavButtonHelper),
                new FrameworkPropertyMetadata(false));

        public static bool GetIsActive(DependencyObject obj) => (bool)obj.GetValue(IsActiveProperty);
        public static void SetIsActive(DependencyObject obj, bool value) => obj.SetValue(IsActiveProperty, value);
    }

    public partial class MainWindow : Window
    {
        private bool _navCollapsed = false;
        private bool _chatExpanded = true;
        private bool _notifPanelOpen = false;
        private Button? _activeNavButton;

        private static readonly SolidColorBrush _activeBrush =
            new SolidColorBrush(Color.FromArgb(35, 59, 130, 246));
        private static readonly SolidColorBrush _transparentBrush =
            new SolidColorBrush(Colors.Transparent);

        private readonly ObservableCollection<ChatMessage> _messages = new();
        private readonly ObservableCollection<NotificationEntry> _notifications = new();
        private readonly HttpClient _httpClient = new();
        private const double NormalChatWidth = 280;

        // API keys now flow through SecretsManager (DPAPI-encrypted disk store
        // with env-var fallback) so the Settings UI can persist them. Kept as
        // properties so a change in Settings is picked up by callers that re-read.
        public static string ApiKey       => Services.SecretsManager.Get(Services.SecretsManager.KeyOpenAiApiKey);
        public static string AnthropicKey => Services.SecretsManager.Get(Services.SecretsManager.KeyAnthropicApiKey);
        public static readonly string ApiEndpoint = "https://api.openai.com/v1/chat/completions";

        public MainWindow()
        {
            InitializeComponent();
            SetupWindow();
            ApplyAIProviderHeader(AIProviderService.Current);
            AIProviderService.ProviderChanged += (_, tag) =>
                Dispatcher.InvokeAsync(() => ApplyAIProviderHeader(tag));
        }

        // ── Setup ─────────────────────────────────────────────────────────────

        private void SetupWindow()
        {
            ChatMessages.ItemsSource    = _messages;
            NotificationsList.ItemsSource = _notifications;

            // Modules: bind the dynamic nav list. The main app is a controller/client;
            // modules run as standalone apps and host themselves.
            ModuleNavList.ItemsSource = ModuleRegistry.Instance.Modules;

            NotificationService.NotificationAdded  += OnNotificationAdded;
            NotificationService.UnreadCountChanged  += OnUnreadCountChanged;

            AddAssistantMessage("Hello! I'm your AI security assistant. Ask me anything about your network, vulnerabilities, or scan results.");

            Loaded += (_, __) =>
            {
                RefreshSessionUi();
                ApplyRolePermissions();
                NavigateToPage("Dashboard");
                SetActiveNavButton(DashboardButton);
            };
        }

        // ── AI provider header ────────────────────────────────────────────────

        private void ApplyAIProviderHeader(string tag)
        {
            try
            {
                var (name, model, _) = AIProviderService.Info(tag);
                if (AiProviderName != null) AiProviderName.Text = name;
                if (AiModelLabel   != null) AiModelLabel.Text   = model;
                if (AiLogoIcon     != null)
                    AiLogoIcon.Icon = tag == "anthropic" ? IconChar.Brain : IconChar.Robot;
                if (AiLogoRing != null)
                    AiLogoRing.Background = tag == "anthropic"
                        ? new SolidColorBrush(Color.FromArgb(80, 224, 123, 57))
                        : new SolidColorBrush(Color.FromArgb(51, 255, 255, 255));
            }
            catch (Exception ex) { Debug.WriteLine($"[ApplyAIProviderHeader] {ex.Message}"); }
        }

        // ── Navigation ────────────────────────────────────────────────────────

        public void NavigateToPageWithState(string pageName, Dictionary<string, object>? pageState = null)
        {
            try
            {
                if (pageState?.Count > 0)
                    StateService.Instance.RestorePageState(pageName, pageState);

                NavigateToPage(pageName);

                Dispatcher.BeginInvoke(new Action(() =>
                {
                    if (GetCurrentPage() is Views.NetworkDiscoveryPage np)
                        np.RestoreUIState();
                }), DispatcherPriority.Loaded);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[NavigateToPageWithState] {ex.Message}");
                try { NavigateToPage(pageName); }
                catch (Exception navEx)
                {
                    AppDialog.Show($"Error navigating to page: {navEx.Message}",
                        "Navigation Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        public void NavigateFromScanResult(ScanResult scanResult)
        {
            if (scanResult == null)
            {
                AppDialog.Show("Invalid scan result.", "Navigation Error",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            try
            {
                var preview = CreateScanPreviewWindow(scanResult);
                if (preview.ShowDialog() == true)
                {
                    NavigateToPageWithState(scanResult.PageType, scanResult.PageState);
                    AddAssistantMessage($"Navigated to {scanResult.PageType} with state from {scanResult.Timestamp:yyyy-MM-dd HH:mm}.");
                }
            }
            catch (Exception ex)
            {
                AppDialog.Show($"Error during navigation: {ex.Message}",
                    "Navigation Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        public Page? GetCurrentPage() => MainFrame?.Content as Page;

        public void NavigateDirect(Page page)
        {
            MainFrame.Content = null;
            ForcePageToFullSize(page);
            MainFrame.Content = page;
        }

        private void NavigateToPage(string pageName)
        {
            try
            {
                // RBAC: block navigation the current role isn't permitted to open.
                var need = RequiredPermission(pageName);
                var session = SessionService.Instance;
                if (session.IsAuthenticated && !session.Can(need))
                {
                    session.Require(need, $"open {pageName}");
                    return;
                }

                MainFrame.Content = null;

                Page? newPage = pageName switch
                {
                    "Dashboard"             => new Views.DashboardPage(),
                    "Network Discovery"     => new Views.NetworkDiscoveryPage(),
                    "Network Topology"      => new Views.NetworkTopologyPage(),
                    "Traffic Analysis"      => new Views.TrafficAnalysisPage(),
                    "New Scan"              => new Views.Add(),
                    "Miscellaneous"
                    or "Port Scanner"       => new Views.MiscellaneousPage(),
                    "Gallery"               => new Views.GalleryPage(),
                    "Achievements"          => new Views.AchievementsPage(),
                    "Profile"               => new Views.ProfilePage(),
                    "Settings"              => new Views.SettingsPage(),
                    "User Management"       => new Views.UserManagementPage(),
                    "Honeypot Management"
                    or "Honeypot"           => new Views.HoneypotDashboardPage(),
                    "Intrusion Detection"   => new Views.NetworkIDSDashboardPage(),
                    "POC Explorer"          => new Views.POCExplorerPage(),
                    "Vulnerability Scanner" => new Views.VulnerabilityScannerPage(),
                    _                       => null
                };

                if (newPage != null)
                {
                    ForcePageToFullSize(newPage);
                    MainFrame.Content = newPage;
                }

                if (CurrentPageLabel != null)
                    CurrentPageLabel.Text = pageName;
            }
            catch (Exception ex)
            {
                AppDialog.Show($"Error loading page: {ex.Message}", "Navigation Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        // ── RBAC (auth/roles) ─────────────────────────────────────────────────
        /// <summary>The permission a page requires to open. Scanner tools need RunScans; the rest are viewable.</summary>
        private static Permission RequiredPermission(string pageName) => pageName switch
        {
            "Port Scanner" or "Miscellaneous" or "Vulnerability Scanner"
              or "Network Discovery" or "Network Topology" or "Traffic Analysis"
              or "New Scan" or "POC Explorer" => Permission.RunScans,
            "User Management" => Permission.ManageUsers,
            _ => Permission.ViewDashboards,
        };

        private static string RoleLabel(AppRole role) => role switch
        {
            AppRole.Admin => "Administrator",
            AppRole.SeniorAnalyst => "Senior Analyst",
            AppRole.Analyst => "Analyst",
            _ => "Viewer",
        };

        private void RefreshSessionUi()
        {
            var u = SessionService.Instance.Current;
            if (u == null) return;
            if (SessionUserText != null) SessionUserText.Text = u.DisplayName;
            if (SessionRoleText != null) SessionRoleText.Text = RoleLabel(u.Role);
        }

        /// <summary>Hide nav entries the signed-in role can't use (the NavigateToPage guard is the real gate).</summary>
        private void ApplyRolePermissions()
        {
            var s = SessionService.Instance;
            if (NavItemsPanel != null)
                foreach (var child in NavItemsPanel.Children)
                    if (child is Button b && b != AddModuleButton && b.Content is string name)
                        b.Visibility = (!s.IsAuthenticated || s.Can(RequiredPermission(name)))
                            ? Visibility.Visible : Visibility.Collapsed;

            if (AddModuleButton != null)
                AddModuleButton.Visibility = (!s.IsAuthenticated || s.Can(Permission.AddRemoveModules))
                    ? Visibility.Visible : Visibility.Collapsed;

            if (AdminNavSection != null)
                AdminNavSection.Visibility = s.Can(Permission.ManageUsers)
                    ? Visibility.Visible : Visibility.Collapsed;
        }

        private void LogoutButton_Click(object sender, RoutedEventArgs e)
        {
            var session = SessionService.Instance;
            session.SignOut();
            Hide();
            var login = new Views.LoginWindow();
            if (login.ShowDialog() == true && login.AuthenticatedUser != null)
            {
                session.SignIn(login.AuthenticatedUser);
                RefreshSessionUi();
                ApplyRolePermissions();
                NavigateToPage("Dashboard");
                SetActiveNavButton(DashboardButton);
                Show();
            }
            else
            {
                Application.Current.Shutdown();
            }
        }

        private static void ForcePageToFullSize(Page page)
        {
            if (page == null) return;
            page.Width  = double.NaN;
            page.Height = double.NaN;
            page.MinWidth  = 0;
            page.MinHeight = 0;
            page.MaxWidth  = double.MaxValue;
            page.MaxHeight = double.MaxValue;
            page.HorizontalAlignment = HorizontalAlignment.Stretch;
            page.VerticalAlignment   = VerticalAlignment.Stretch;
        }

        protected override void OnStateChanged(EventArgs e)
        {
            base.OnStateChanged(e);
            bool maximized = WindowState == WindowState.Maximized;

            if (MaximizeButton?.Content is IconBlock icon)
                icon.Icon = maximized ? IconChar.WindowRestore : IconChar.WindowMaximize;

            if (OuterBorder != null)
                OuterBorder.CornerRadius = maximized ? new CornerRadius(0) : new CornerRadius(12);
        }

        private void ProfileButton_Click(object sender, RoutedEventArgs e)
            => NavigateToPage("Profile");

        private void NavigationButton_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button button)
            {
                var pageName = button.Content is string s ? s : button.Content?.ToString() ?? string.Empty;
                NavigateToPage(pageName);
                SetActiveNavButton(button);
                CloseNotificationPanel();
            }
        }

        // ── Modules ───────────────────────────────────────────────────────────

        private void AddModule_Click(object sender, RoutedEventArgs e)
        {
            if (!SessionService.Instance.Require(Permission.AddRemoveModules, "add modules")) return;
            var win = new Views.AddModuleWindow { Owner = this };
            win.ShowDialog();
        }

        private void RemoveModule_Click(object sender, RoutedEventArgs e)
        {
            if (sender is System.Windows.Controls.MenuItem mi && mi.DataContext is Models.ManagedModule m)
            {
                if (!SessionService.Instance.Require(Permission.AddRemoveModules, "remove modules")) return;
                if (AppDialog.Show($"Remove '{m.DisplayName}' from your modules?", "Remove module",
                        MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;

                try { m.LiveClient?.Dispose(); } catch { }
                ModuleRegistry.Instance.Remove(m);
                NavigateToPage("Dashboard");
                SetActiveNavButton(DashboardButton);
            }
        }

        private void ModuleNav_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button button && button.DataContext is Models.ManagedModule module)
            {
                NavigateToModule(module);
                SetActiveNavButton(button);
                CloseNotificationPanel();
            }
        }

        /// <summary>
        /// Opening a module: if already connected, show its real page; otherwise show
        /// the connect/login gate, which hands off to the real page on success.
        /// </summary>
        private void NavigateToModule(Models.ManagedModule module)
        {
            try
            {
                if (module.IsConnected && module.LiveClient != null)
                {
                    ShowModuleLive(module, module.LiveClient);
                    return;
                }

                var connectPage = new Views.ModuleConnectPage(module, client => ShowModuleLive(module, client));
                ForcePageToFullSize(connectPage);
                MainFrame.Content = connectPage;
                if (CurrentPageLabel != null) CurrentPageLabel.Text = module.DisplayName;
            }
            catch (Exception ex)
            {
                AppDialog.Show($"Error opening module: {ex.Message}", "Module Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ShowModuleLive(Models.ManagedModule module, PrivaCore.ModuleSdk.ModuleClient client)
        {
            // Push the console's active colour theme to the module so its window matches us — and
            // keeps matching live as the operator switches themes.
            Services.ModuleThemeSync.AttachConsole(client);

            // IDS opens its REAL dashboard, two-way live: console actions drive the remote
            // sensor, and the sensor's alerts/state stream back into this same page.
            if (module.Key.Equals("IDS", StringComparison.OrdinalIgnoreCase))
            {
                Services.IdsModuleBridge.DetachConsole();
                Services.IdsModuleBridge.AttachConsole(client, a => Dispatcher.BeginInvoke(a));

                var page = new Views.NetworkIDSDashboardPage();
                ForcePageToFullSize(page);
                MainFrame.Content = page;
                if (CurrentPageLabel != null) CurrentPageLabel.Text = module.DisplayName + " (remote)";
                return;
            }

            // SIEM opens its real dashboard, fed live by the remote collector's events.
            if (module.Key.Equals("SIEM", StringComparison.OrdinalIgnoreCase))
            {
                Services.Siem.SiemModuleBridge.AttachConsole(client);
                var siem = new Views.SiemDashboardPage();
                siem.ConfigureForRemote();
                ForcePageToFullSize(siem);
                MainFrame.Content = siem;
                if (CurrentPageLabel != null) CurrentPageLabel.Text = module.DisplayName + " (remote)";
                return;
            }

            var view = new Views.ModuleLiveView(module, client);
            ForcePageToFullSize(view);
            MainFrame.Content = view;
            if (CurrentPageLabel != null) CurrentPageLabel.Text = module.DisplayName;
        }

        private void SetActiveNavButton(Button active)
        {
            if (_activeNavButton != null)
            {
                _activeNavButton.Background = _transparentBrush;
                NavButtonHelper.SetIsActive(_activeNavButton, false);
            }

            _activeNavButton = active;

            if (Application.Current.Resources["AccentBrush"] is SolidColorBrush accent)
            {
                var c = accent.Color;
                active.Background = new SolidColorBrush(Color.FromArgb(35, c.R, c.G, c.B));
            }
            else
            {
                active.Background = _activeBrush;
            }

            NavButtonHelper.SetIsActive(active, true);
        }

        private void CollapseButton_Click(object sender, RoutedEventArgs e)
        {
            CollapseButton.IsEnabled = false;
            var targetWidth = _navCollapsed ? 220 : 58;

            var slide = new GridLengthAnimation
            {
                From            = NavPanelColumn.Width,
                To              = new GridLength(targetWidth),
                Duration        = TimeSpan.FromSeconds(0.28),
                EasingFunction  = new CubicEase { EasingMode = EasingMode.EaseInOut }
            };
            slide.Completed += (_, __) => CollapseButton.IsEnabled = true;
            NavPanelColumn.BeginAnimation(ColumnDefinition.WidthProperty, slide);

            _navCollapsed = !_navCollapsed;
            SidebarToggleIcon.Icon = _navCollapsed ? IconChar.AngleRight : IconChar.AngleLeft;
        }

        // ── Camera / Gallery ─────────────────────────────────────────────────

        private void CameraButton_Click(object sender, RoutedEventArgs e)
        {
            try { TakeManualScreenshot(); }
            catch (Exception ex)
            {
                AppDialog.Show($"Error taking screenshot: {ex.Message}",
                    "Screenshot Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void TakeManualScreenshot()
        {
            var page = GetCurrentPage();
            if (page == null)
            {
                AppDialog.Show("No page is currently loaded.", "Screenshot",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var shot = ScreenshotUtility.CapturePage(page);
            if (shot == null)
            {
                AppDialog.Show("Failed to capture screenshot.", "Screenshot",
                    MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            string data = ScreenshotUtility.BitmapToBase64(shot);
            if (string.IsNullOrEmpty(data))
            {
                AppDialog.Show("Failed to convert screenshot.", "Screenshot",
                    MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            GalleryManager.AddScreenshot(new GalleryItem
            {
                Id             = Guid.NewGuid().ToString(),
                Timestamp      = DateTime.Now,
                Title          = $"Manual Screenshot – {GetCurrentPageName()}",
                Description    = $"Screenshot from {GetCurrentPageName()}",
                PageType       = GetCurrentPageName(),
                Screenshot     = shot,
                ScreenshotData = data,
                IsManual       = true
            });

            AlertToast.Success("Screenshot saved", $"Saved to Gallery from {GetCurrentPageName()}.");
            AddAssistantMessage("Screenshot saved to Gallery!");
        }

        private string GetCurrentPageName() =>
            GetCurrentPage()?.GetType().Name switch
            {
                "DashboardPage"            => "Dashboard",
                "NetworkDiscoveryPage"     => "Network Discovery",
                "NetworkTopologyPage"      => "Network Topology",
                "MiscellaneousPage"        => "Port Scanner",
                "TrafficAnalysisPage"      => "Traffic Analysis",
                "Add"                      => "New Scan",
                "VulnerabilityScannerPage" => "Vulnerability Scanner",
                "GalleryPage"              => "Gallery",
                "AchievementsPage"         => "Achievements",
                "ProfilePage"              => "Profile",
                "SettingsPage"             => "Settings",
                "HoneypotDashboardPage"    => "Honeypot Management",
                "IDSRouterPage"            => "Intrusion Detection",
                "HostIDSDashboardPage"     => "Host-Based IDS",
                "NetworkIDSDashboardPage"  => "Network-Based IDS",
                _                          => "Unknown"
            } ?? "Unknown";

        // ── Window controls ───────────────────────────────────────────────────

        private void TitleBar_MouseDown(object sender, MouseButtonEventArgs e)
        {
            if (e.LeftButton == MouseButtonState.Pressed)
            {
                try { DragMove(); }
                catch (InvalidOperationException) { }
            }
        }

        private void MinimizeButton_Click(object sender, RoutedEventArgs e)
            => WindowState = WindowState.Minimized;

        private void MaximizeButton_Click(object sender, RoutedEventArgs e)
            => WindowState = WindowState == WindowState.Maximized
                ? WindowState.Normal
                : WindowState.Maximized;

        private void CloseButton_Click(object sender, RoutedEventArgs e) => Close();

        // ── Notification panel ────────────────────────────────────────────────

        private void NotificationButton_Click(object sender, RoutedEventArgs e)
        {
            if (_notifPanelOpen) CloseNotificationPanel();
            else                 OpenNotificationPanel();
        }

        private void OpenNotificationPanel()
        {
            NotificationService.MarkAllRead();
            RefreshNotificationList();
            NotificationPanel.Visibility          = Visibility.Visible;
            NotificationDismissOverlay.Visibility = Visibility.Visible;
            _notifPanelOpen = true;
        }

        private void CloseNotificationPanel()
        {
            NotificationPanel.Visibility          = Visibility.Collapsed;
            NotificationDismissOverlay.Visibility = Visibility.Collapsed;
            _notifPanelOpen = false;
        }

        private void NotificationDismissOverlay_Click(object sender, MouseButtonEventArgs e)
            => CloseNotificationPanel();

        private void MarkAllReadButton_Click(object sender, RoutedEventArgs e)
        {
            NotificationService.MarkAllRead();
            RefreshNotificationList();
        }

        private void ClearNotificationsButton_Click(object sender, RoutedEventArgs e)
        {
            NotificationService.Clear();
            RefreshNotificationList();
        }

        private void RefreshNotificationList()
        {
            _notifications.Clear();
            foreach (var n in NotificationService.Entries)
                _notifications.Add(n);

            if (NoNotificationsText != null)
                NoNotificationsText.Visibility = _notifications.Count == 0
                    ? Visibility.Visible : Visibility.Collapsed;
        }

        private void OnNotificationAdded(object? sender, NotificationEntry e)
        {
            Dispatcher.InvokeAsync(() =>
            {
                if (_notifPanelOpen) RefreshNotificationList();
                UpdateNotificationBadge();
            });
        }

        private void OnUnreadCountChanged(object? sender, EventArgs e)
            => Dispatcher.InvokeAsync(UpdateNotificationBadge);

        private void UpdateNotificationBadge()
        {
            int count = NotificationService.UnreadCount;
            if (count == 0)
            {
                NotificationBadge.Visibility = Visibility.Collapsed;
            }
            else
            {
                NotificationBadgeText.Text   = count > 99 ? "99+" : count.ToString();
                NotificationBadge.Visibility = Visibility.Visible;
            }
        }

        // ── Chat panel ────────────────────────────────────────────────────────

        private void ChatHandle_MouseDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ButtonState == MouseButtonState.Pressed)
                ToggleChat();
        }

        private void ToggleChat()
        {
            if (ChatHandleBorder == null) return;
            ChatHandleBorder.IsHitTestVisible = false;

            bool wasExpanded = _chatExpanded;
            double targetWidth = wasExpanded ? 0 : NormalChatWidth;

            // Animate the handle icon: 0° = ← (close), 180° = → (open)
            ChatHandleRotation.BeginAnimation(RotateTransform.AngleProperty,
                new DoubleAnimation(
                    ChatHandleRotation.Angle,
                    wasExpanded ? 180 : 0,
                    TimeSpan.FromSeconds(0.28))
                { EasingFunction = new CubicEase { EasingMode = EasingMode.EaseInOut } });

            if (wasExpanded) // collapsing — fade content out then slide shut
            {
                var fadeOut = new DoubleAnimation(1, 0, TimeSpan.FromMilliseconds(150))
                {
                    EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
                };
                fadeOut.Completed += (_, __) =>
                    ChatContentContainer.Visibility = Visibility.Collapsed;
                ChatContentContainer.BeginAnimation(UIElement.OpacityProperty, fadeOut);
            }
            else // expanding — hide content first, reveal after slide
            {
                ChatContentContainer.Visibility = Visibility.Collapsed;
                ChatContentContainer.Opacity = 0;
            }

            var slide = new GridLengthAnimation
            {
                From           = ChatPanelColumn.Width,
                To             = new GridLength(targetWidth),
                Duration       = TimeSpan.FromSeconds(0.28),
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseInOut }
            };
            slide.Completed += (_, __) =>
            {
                if (!wasExpanded) // just expanded — fade content in
                {
                    ChatContentContainer.Visibility = Visibility.Visible;
                    var fadeIn = new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(180))
                    {
                        EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
                    };
                    fadeIn.Completed += (__, ___) => MessageInput?.Focus();
                    ChatContentContainer.BeginAnimation(UIElement.OpacityProperty, fadeIn);
                }
                _chatExpanded = !wasExpanded;
                ChatHandleBorder.IsHitTestVisible = true;
            };
            ChatPanelColumn.BeginAnimation(ColumnDefinition.WidthProperty, slide);
        }

        // ── AI Chat ───────────────────────────────────────────────────────────

        private async void SendMessage_Click(object sender, RoutedEventArgs e) => await SendMessageAsync();

        private async void MessageInput_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter && !e.KeyboardDevice.Modifiers.HasFlag(ModifierKeys.Shift))
            {
                await SendMessageAsync();
                e.Handled = true;
            }
        }

        private async Task SendMessageAsync()
        {
            if (string.IsNullOrWhiteSpace(MessageInput?.Text)) return;

            string userMsg = MessageInput.Text;
            AddUserMessage(userMsg);
            MessageInput.Clear();
            MessageInput.Focus();

            try
            {
                if (AIProviderService.Current == "anthropic")
                    await SendAnthropicAsync(userMsg);
                else
                    await SendOpenAIAsync(userMsg, AIProviderService.Current);
            }
            catch (HttpRequestException ex) { AddAssistantMessage($"Network error: {ex.Message}"); }
            catch (JsonException ex)        { AddAssistantMessage($"Response parse error: {ex.Message}"); }
            catch (Exception ex)            { AddAssistantMessage($"Unexpected error: {ex.Message}"); }
            finally
            {
                await Task.Delay(60);
                Dispatcher.Invoke(() =>
                    ChatScroller?.ScrollToVerticalOffset(ChatScroller.ExtentHeight));
            }
        }

        private async Task SendOpenAIAsync(string userMessage, string providerTag)
        {
            if (string.IsNullOrEmpty(ApiKey))
            {
                AddAssistantMessage("No OpenAI API key configured. Set OPENAI_API_KEY or enter it in Settings.");
                return;
            }

            string model = providerTag == "openai-gpt4" ? "gpt-4" : "gpt-3.5-turbo";
            var payload = new
            {
                model,
                messages = new[]
                {
                    new { role = "system", content = "You are a cybersecurity expert assistant. Provide detailed and actionable security recommendations. Keep responses natural and concise — no markdown formatting, no asterisks." },
                    new { role = "user",   content = userMessage }
                },
                temperature = 0.7
            };

            using var req = new HttpRequestMessage(HttpMethod.Post, "https://api.openai.com/v1/chat/completions")
            {
                Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json")
            };
            req.Headers.TryAddWithoutValidation("Authorization", $"Bearer {ApiKey}");

            var resp = await _httpClient.SendAsync(req);
            var body = await resp.Content.ReadAsStringAsync();

            if (resp.IsSuccessStatusCode)
            {
                using var doc = JsonDocument.Parse(body);
                var msg = doc.RootElement
                    .GetProperty("choices")[0]
                    .GetProperty("message")
                    .GetProperty("content").GetString();
                AddAssistantMessage(msg ?? "No response received.");
            }
            else
            {
                AddAssistantMessage($"API error {(int)resp.StatusCode}. Check your API key in Settings.");
            }
        }

        private async Task SendAnthropicAsync(string userMessage)
        {
            if (string.IsNullOrEmpty(AnthropicKey))
            {
                AddAssistantMessage("No Anthropic API key configured. Set ANTHROPIC_API_KEY to use Claude.");
                return;
            }

            var payload = new
            {
                model      = "claude-3-5-sonnet-20241022",
                max_tokens = 1024,
                system     = "You are a cybersecurity expert assistant. Provide detailed and actionable security recommendations. Keep responses natural and concise.",
                messages   = new[] { new { role = "user", content = userMessage } }
            };

            using var req = new HttpRequestMessage(HttpMethod.Post, "https://api.anthropic.com/v1/messages")
            {
                Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json")
            };
            req.Headers.TryAddWithoutValidation("x-api-key", AnthropicKey);
            req.Headers.TryAddWithoutValidation("anthropic-version", "2023-06-01");

            var resp = await _httpClient.SendAsync(req);
            var body = await resp.Content.ReadAsStringAsync();

            if (resp.IsSuccessStatusCode)
            {
                using var doc = JsonDocument.Parse(body);
                var msg = doc.RootElement
                    .GetProperty("content")[0]
                    .GetProperty("text").GetString();
                AddAssistantMessage(msg ?? "No response received.");
            }
            else
            {
                AddAssistantMessage($"Anthropic API error {(int)resp.StatusCode}. Check your ANTHROPIC_API_KEY.");
            }
        }

        public void AddAssistantMessage(string message)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                _messages.Add(new ChatMessage(message, false));
                ChatScroller?.ScrollToVerticalOffset(ChatScroller.ExtentHeight);
            });
        }

        private void AddUserMessage(string message) =>
            Application.Current.Dispatcher.Invoke(() =>
                _messages.Add(new ChatMessage(message, true)));

        // ── Stub handlers (XAML binding compat) ───────────────────────────────

        private void InterfaceSelector_SelectionChanged(object sender, SelectionChangedEventArgs e) { }

        // ── Scan preview window ───────────────────────────────────────────────

        private Window CreateScanPreviewWindow(ScanResult scanResult)
        {
            var window = new Window
            {
                Title                 = "Scan Result Preview",
                Width                 = 600,
                Height                = 500,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Owner                 = this,
                Background            = new SolidColorBrush(Color.FromRgb(26, 26, 26)),
                ResizeMode            = ResizeMode.CanResize
            };

            var grid = new Grid();
            grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            var scroll = new ScrollViewer
            {
                VerticalScrollBarVisibility   = ScrollBarVisibility.Auto,
                HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
                Padding = new Thickness(20)
            };

            var stack = new StackPanel();
            stack.Children.Add(new TextBlock
            {
                Text = $"Preview: {scanResult.Type}", FontSize = 20,
                FontWeight = FontWeights.Bold, Foreground = Brushes.White,
                Margin = new Thickness(0, 0, 0, 15)
            });

            var infoGrid = new Grid();
            infoGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            infoGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            var labels = new[] { "Date:", "Page:", "Status:", "Description:" };
            var values = new[]
            {
                scanResult.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"),
                scanResult.PageType, scanResult.Status, scanResult.Description
            };

            for (int i = 0; i < labels.Length; i++)
            {
                infoGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
                var lbl = new TextBlock { Text = labels[i], FontWeight = FontWeights.SemiBold, Foreground = Brushes.LightGray, Margin = new Thickness(0, 5, 10, 5) };
                Grid.SetRow(lbl, i); Grid.SetColumn(lbl, 0); infoGrid.Children.Add(lbl);
                var val = new TextBlock { Text = values[i], Foreground = Brushes.White, Margin = new Thickness(0, 5, 0, 5), TextWrapping = TextWrapping.Wrap };
                Grid.SetRow(val, i); Grid.SetColumn(val, 1); infoGrid.Children.Add(val);
            }
            stack.Children.Add(infoGrid);

            if (scanResult.HasSnapshot)
            {
                stack.Children.Add(new TextBlock
                {
                    Text = "Page Screenshot:", FontSize = 16, FontWeight = FontWeights.SemiBold,
                    Foreground = Brushes.White, Margin = new Thickness(0, 20, 0, 10)
                });
                var imgBorder = new Border
                {
                    BorderBrush = Brushes.Gray, BorderThickness = new Thickness(1),
                    Background = Brushes.Black, MaxHeight = 300, Margin = new Thickness(0, 0, 0, 15)
                };
                imgBorder.Child = new System.Windows.Controls.Image
                {
                    Source = scanResult.PageSnapshot, Stretch = System.Windows.Media.Stretch.Uniform,
                    HorizontalAlignment = HorizontalAlignment.Center,
                    VerticalAlignment   = VerticalAlignment.Center
                };
                stack.Children.Add(imgBorder);
            }

            scroll.Content = stack;
            Grid.SetRow(scroll, 0);
            grid.Children.Add(scroll);

            var btnRow = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Right,
                Margin = new Thickness(20, 10, 20, 20)
            };
            var cancel = new Button { Content = "Cancel", Width = 80, Height = 30, Margin = new Thickness(0, 0, 10, 0), Background = Brushes.Gray, Foreground = Brushes.White, BorderThickness = new Thickness(0) };
            cancel.Click += (_, __) => { window.DialogResult = false; window.Close(); };
            var navigate = new Button { Content = "Navigate", Width = 80, Height = 30, Background = new SolidColorBrush(Color.FromRgb(0, 122, 204)), Foreground = Brushes.White, BorderThickness = new Thickness(0) };
            navigate.Click += (_, __) => { window.DialogResult = true; window.Close(); };
            btnRow.Children.Add(cancel);
            btnRow.Children.Add(navigate);
            Grid.SetRow(btnRow, 1);
            grid.Children.Add(btnRow);

            window.Content = grid;
            return window;
        }
    }
}
