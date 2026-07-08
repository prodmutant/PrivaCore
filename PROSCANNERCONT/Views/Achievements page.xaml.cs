using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using FontAwesome.WPF;
using PROSCANNERCONT.Utils;

namespace PROSCANNERCONT.Views
{
    public partial class AchievementsPage : Page, INotifyPropertyChanged
    {
        #region Properties and Fields

        private ObservableCollection<Achievement> _allAchievements;
        private ObservableCollection<Achievement> _filteredAchievements;
        private string _currentFilter = "All";

        // Progress tracking
        private int _securityExpertEarned = 0;
        private int _networkScoutEarned = 0;
        private int _bugHunterEarned = 0;
        private int _performanceExpertEarned = 0;

        public event PropertyChangedEventHandler? PropertyChanged;

        #endregion

        #region Constructor and Initialization

        public AchievementsPage()
        {
            InitializeComponent();
            InitializeAchievements();
            LoadAchievementProgress();
            UpdateUI();
            DataContext = this;
        }

        private void InitializeAchievements()
        {
            _allAchievements = new ObservableCollection<Achievement>();
            _filteredAchievements = new ObservableCollection<Achievement>();

            // Initialize all achievements
            CreateSecurityExpertAchievements();
            CreateNetworkScoutAchievements();
            CreateBugHunterAchievements();
            CreatePerformanceExpertAchievements();

            // Set initial filter to show all
            FilterAchievements("All");
        }

        #endregion

        #region Achievement Creation Methods

        private void CreateSecurityExpertAchievements()
        {
            var securityAchievements = new List<Achievement>
            {
                new Achievement
                {
                    Id = "security_first_steps",
                    Title = "First Steps",
                    Description = "Complete your first network scan",
                    Category = AchievementCategory.SecurityExpert,
                    Icon = FontAwesomeIcon.Play,
                    IconColor = "#FF4CAF50",
                    RequiredValue = 1,
                    CurrentValue = 0,
                    IsEarned = false
                },
                new Achievement
                {
                    Id = "security_conscious",
                    Title = "Security Conscious",
                    Description = "Achieve a security score above 80",
                    Category = AchievementCategory.SecurityExpert,
                    Icon = FontAwesomeIcon.Shield,
                    IconColor = "#FF2196F3",
                    RequiredValue = 80,
                    CurrentValue = 0,
                    IsEarned = false
                },
                new Achievement
                {
                    Id = "fortress_builder",
                    Title = "Fortress Builder",
                    Description = "Maintain 95+ security score for 30 days",
                    Category = AchievementCategory.SecurityExpert,
                    Icon = FontAwesomeIcon.Home,
                    IconColor = "#FF9C27B0",
                    RequiredValue = 30,
                    CurrentValue = 0,
                    IsEarned = false
                },
                new Achievement
                {
                    Id = "vulnerability_vanquisher",
                    Title = "Vulnerability Vanquisher",
                    Description = "Fix 25 security vulnerabilities",
                    Category = AchievementCategory.SecurityExpert,
                    Icon = FontAwesomeIcon.CheckCircle,
                    IconColor = "#FF4CAF50",
                    RequiredValue = 25,
                    CurrentValue = 0,
                    IsEarned = false
                },
                new Achievement
                {
                    Id = "shield_master",
                    Title = "Shield Master",
                    Description = "Block 100 potential threats",
                    Category = AchievementCategory.SecurityExpert,
                    Icon = FontAwesomeIcon.Shield,
                    IconColor = "#FF607D8B",
                    RequiredValue = 100,
                    CurrentValue = 0,
                    IsEarned = false
                },
                new Achievement
                {
                    Id = "encryption_enthusiast",
                    Title = "Encryption Enthusiast",
                    Description = "Enable encryption on 50+ devices",
                    Category = AchievementCategory.SecurityExpert,
                    Icon = FontAwesomeIcon.Lock,
                    IconColor = "#FFFF9800",
                    RequiredValue = 50,
                    CurrentValue = 0,
                    IsEarned = false
                },
                new Achievement
                {
                    Id = "firewall_guardian",
                    Title = "Firewall Guardian",
                    Description = "Configure advanced firewall rules",
                    Category = AchievementCategory.SecurityExpert,
                    Icon = FontAwesomeIcon.Fire,
                    IconColor = "#FFFF5722",
                    RequiredValue = 1,
                    CurrentValue = 0,
                    IsEarned = false
                },
                new Achievement
                {
                    Id = "access_controller",
                    Title = "Access Controller",
                    Description = "Set up proper user access controls",
                    Category = AchievementCategory.SecurityExpert,
                    Icon = FontAwesomeIcon.Key,
                    IconColor = "#FF795548",
                    RequiredValue = 1,
                    CurrentValue = 0,
                    IsEarned = false
                },
                new Achievement
                {
                    Id = "security_auditor",
                    Title = "Security Auditor",
                    Description = "Complete 10 comprehensive security audits",
                    Category = AchievementCategory.SecurityExpert,
                    Icon = FontAwesomeIcon.List,
                    IconColor = "#FF3F51B5",
                    RequiredValue = 10,
                    CurrentValue = 0,
                    IsEarned = false
                },
                new Achievement
                {
                    Id = "cyber_sentinel",
                    Title = "Cyber Sentinel",
                    Description = "Achieve perfect security score (100)",
                    Category = AchievementCategory.SecurityExpert,
                    Icon = FontAwesomeIcon.Trophy,
                    IconColor = "#FFD700",
                    RequiredValue = 100,
                    CurrentValue = 0,
                    IsEarned = false
                }
            };

            foreach (var achievement in securityAchievements)
            {
                _allAchievements.Add(achievement);
            }
        }

        private void CreateNetworkScoutAchievements()
        {
            var networkAchievements = new List<Achievement>
            {
                new Achievement
                {
                    Id = "network_explorer",
                    Title = "Network Explorer",
                    Description = "Scan 50 different hosts",
                    Category = AchievementCategory.NetworkScout,
                    Icon = FontAwesomeIcon.Globe,
                    IconColor = "#FF4CAF50",
                    RequiredValue = 50,
                    CurrentValue = 0,
                    IsEarned = false
                },
                new Achievement
                {
                    Id = "device_discoverer",
                    Title = "Device Discoverer",
                    Description = "Find 100+ network devices",
                    Category = AchievementCategory.NetworkScout,
                    Icon = FontAwesomeIcon.Desktop,
                    IconColor = "#FF2196F3",
                    RequiredValue = 100,
                    CurrentValue = 0,
                    IsEarned = false
                },
                new Achievement
                {
                    Id = "port_navigator",
                    Title = "Port Navigator",
                    Description = "Scan 1000+ ports",
                    Category = AchievementCategory.NetworkScout,
                    Icon = FontAwesomeIcon.Sitemap,
                    IconColor = "#FFFF9800",
                    RequiredValue = 1000,
                    CurrentValue = 0,
                    IsEarned = false
                },
                new Achievement
                {
                    Id = "topology_master",
                    Title = "Topology Master",
                    Description = "Map complete network topology",
                    Category = AchievementCategory.NetworkScout,
                    Icon = FontAwesomeIcon.Sitemap,
                    IconColor = "#FF9C27B0",
                    RequiredValue = 1,
                    CurrentValue = 0,
                    IsEarned = false
                },
                new Achievement
                {
                    Id = "range_rider",
                    Title = "Range Rider",
                    Description = "Scan 10 different IP ranges",
                    Category = AchievementCategory.NetworkScout,
                    Icon = FontAwesomeIcon.Road,
                    IconColor = "#FF607D8B",
                    RequiredValue = 10,
                    CurrentValue = 0,
                    IsEarned = false
                },
                new Achievement
                {
                    Id = "deep_diver",
                    Title = "Deep Diver",
                    Description = "Perform 25 detailed scans",
                    Category = AchievementCategory.NetworkScout,
                    Icon = FontAwesomeIcon.Search,
                    IconColor = "#FF00BCD4",
                    RequiredValue = 25,
                    CurrentValue = 0,
                    IsEarned = false
                },
                new Achievement
                {
                    Id = "network_cartographer",
                    Title = "Network Cartographer",
                    Description = "Document entire network infrastructure",
                    Category = AchievementCategory.NetworkScout,
                    Icon = FontAwesomeIcon.Map,
                    IconColor = "#FF795548",
                    RequiredValue = 1,
                    CurrentValue = 0,
                    IsEarned = false
                },
                new Achievement
                {
                    Id = "discovery_dynamo",
                    Title = "Discovery Dynamo",
                    Description = "Find hidden or unauthorized devices",
                    Category = AchievementCategory.NetworkScout,
                    Icon = FontAwesomeIcon.Eye,
                    IconColor = "#FFFF5722",
                    RequiredValue = 5,
                    CurrentValue = 0,
                    IsEarned = false
                }
            };

            foreach (var achievement in networkAchievements)
            {
                _allAchievements.Add(achievement);
            }
        }

        private void CreateBugHunterAchievements()
        {
            var bugHunterAchievements = new List<Achievement>
            {
                new Achievement
                {
                    Id = "bug_finder",
                    Title = "Bug Finder",
                    Description = "Discover your first vulnerability",
                    Category = AchievementCategory.BugHunter,
                    Icon = FontAwesomeIcon.Bug,
                    IconColor = "#FFFF5722",
                    RequiredValue = 1,
                    CurrentValue = 0,
                    IsEarned = false
                },
                new Achievement
                {
                    Id = "critical_hunter",
                    Title = "Critical Hunter",
                    Description = "Find a critical severity vulnerability",
                    Category = AchievementCategory.BugHunter,
                    Icon = FontAwesomeIcon.ExclamationTriangle,
                    IconColor = "#FFF44336",
                    RequiredValue = 1,
                    CurrentValue = 0,
                    IsEarned = false
                },
                new Achievement
                {
                    Id = "exploit_expert",
                    Title = "Exploit Expert",
                    Description = "Identify 10 exploitable vulnerabilities",
                    Category = AchievementCategory.BugHunter,
                    Icon = FontAwesomeIcon.Crosshairs,
                    IconColor = "#FF9C27B0",
                    RequiredValue = 10,
                    CurrentValue = 0,
                    IsEarned = false
                },
                new Achievement
                {
                    Id = "zero_day_detector",
                    Title = "Zero Day Detector",
                    Description = "Discover unknown vulnerability",
                    Category = AchievementCategory.BugHunter,
                    Icon = FontAwesomeIcon.Star,
                    IconColor = "#FF3F51B5",
                    RequiredValue = 1,
                    CurrentValue = 0,
                    IsEarned = false
                },
                new Achievement
                {
                    Id = "patch_master",
                    Title = "Patch Master",
                    Description = "Help resolve 50 vulnerabilities",
                    Category = AchievementCategory.BugHunter,
                    Icon = FontAwesomeIcon.Wrench,
                    IconColor = "#FF4CAF50",
                    RequiredValue = 50,
                    CurrentValue = 0,
                    IsEarned = false
                },
                new Achievement
                {
                    Id = "security_researcher",
                    Title = "Security Researcher",
                    Description = "Document detailed vulnerability reports",
                    Category = AchievementCategory.BugHunter,
                    Icon = FontAwesomeIcon.File,
                    IconColor = "#FF607D8B",
                    RequiredValue = 10,
                    CurrentValue = 0,
                    IsEarned = false
                }
            };

            foreach (var achievement in bugHunterAchievements)
            {
                _allAchievements.Add(achievement);
            }
        }

        private void CreatePerformanceExpertAchievements()
        {
            var performanceAchievements = new List<Achievement>
            {
                new Achievement
                {
                    Id = "speed_demon",
                    Title = "Speed Demon",
                    Description = "Complete 10 scans under 5 minutes each",
                    Category = AchievementCategory.PerformanceExpert,
                    Icon = FontAwesomeIcon.Bolt,
                    IconColor = "#FFFF9800",
                    RequiredValue = 10,
                    CurrentValue = 0,
                    IsEarned = false
                },
                new Achievement
                {
                    Id = "efficiency_expert",
                    Title = "Efficiency Expert",
                    Description = "Optimize scan performance by 50%",
                    Category = AchievementCategory.PerformanceExpert,
                    Icon = FontAwesomeIcon.Tachometer,
                    IconColor = "#FF4CAF50",
                    RequiredValue = 50,
                    CurrentValue = 0,
                    IsEarned = false
                },
                new Achievement
                {
                    Id = "bulk_scanner",
                    Title = "Bulk Scanner",
                    Description = "Scan 500+ hosts in single session",
                    Category = AchievementCategory.PerformanceExpert,
                    Icon = FontAwesomeIcon.Database,
                    IconColor = "#FF2196F3",
                    RequiredValue = 500,
                    CurrentValue = 0,
                    IsEarned = false
                },
                new Achievement
                {
                    Id = "marathon_runner",
                    Title = "Marathon Runner",
                    Description = "Complete 24-hour continuous monitoring",
                    Category = AchievementCategory.PerformanceExpert,
                    Icon = FontAwesomeIcon.ClockOutline,
                    IconColor = "#FF9C27B0",
                    RequiredValue = 24,
                    CurrentValue = 0,
                    IsEarned = false
                },
                new Achievement
                {
                    Id = "resource_manager",
                    Title = "Resource Manager",
                    Description = "Minimize system resource usage below 10%",
                    Category = AchievementCategory.PerformanceExpert,
                    Icon = FontAwesomeIcon.Microchip,
                    IconColor = "#FF607D8B",
                    RequiredValue = 10,
                    CurrentValue = 0,
                    IsEarned = false
                },
                new Achievement
                {
                    Id = "automation_master",
                    Title = "Automation Master",
                    Description = "Set up automated scanning schedules",
                    Category = AchievementCategory.PerformanceExpert,
                    Icon = FontAwesomeIcon.Cogs,
                    IconColor = "#FF795548",
                    RequiredValue = 5,
                    CurrentValue = 0,
                    IsEarned = false
                }
            };

            foreach (var achievement in performanceAchievements)
            {
                _allAchievements.Add(achievement);
            }
        }

        #endregion

        #region Achievement Progress Methods

        public void UpdateAchievementProgress(string achievementId, int newValue)
        {
            var achievement = _allAchievements.FirstOrDefault(a => a.Id == achievementId);
            if (achievement != null)
            {
                achievement.CurrentValue = newValue;

                // Check if achievement is now earned
                if (!achievement.IsEarned && newValue >= achievement.RequiredValue)
                {
                    achievement.IsEarned = true;
                    achievement.EarnedDate = DateTime.Now.ToString("MMM dd, yyyy");

                    // Show achievement notification
                    ShowAchievementNotification(achievement);
                }

                UpdateCategoryProgress();
                UpdateUI();
            }
        }

        private void UpdateCategoryProgress()
        {
            _securityExpertEarned = _allAchievements.Count(a => a.Category == AchievementCategory.SecurityExpert && a.IsEarned);
            _networkScoutEarned = _allAchievements.Count(a => a.Category == AchievementCategory.NetworkScout && a.IsEarned);
            _bugHunterEarned = _allAchievements.Count(a => a.Category == AchievementCategory.BugHunter && a.IsEarned);
            _performanceExpertEarned = _allAchievements.Count(a => a.Category == AchievementCategory.PerformanceExpert && a.IsEarned);
        }

        private void ShowAchievementNotification(Achievement achievement)
        {
            // Create a simple notification (you can enhance this with custom notification UI)
            AppDialog.Show($"🏆 Achievement Unlocked!\n\n{achievement.Title}\n{achievement.Description}",
                           "Achievement Earned!",
                           MessageBoxButton.OK,
                           MessageBoxImage.Information);
        }

        #endregion

        #region UI Update Methods

        private void UpdateUI()
        {
            // Update overall progress
            int totalEarned = _allAchievements.Count(a => a.IsEarned);
            OverallProgressText.Text = $"{totalEarned}/30";

            // Update category progress
            SecurityExpertText.Text = $"{_securityExpertEarned}/10";
            SecurityExpertProgress.Value = (_securityExpertEarned / 10.0) * 100;

            NetworkScoutText.Text = $"{_networkScoutEarned}/8";
            NetworkScoutProgress.Value = (_networkScoutEarned / 8.0) * 100;

            BugHunterText.Text = $"{_bugHunterEarned}/6";
            BugHunterProgress.Value = (_bugHunterEarned / 6.0) * 100;

            PerformanceExpertText.Text = $"{_performanceExpertEarned}/6";
            PerformanceExpertProgress.Value = (_performanceExpertEarned / 6.0) * 100;

            // Refresh achievements display
            PopulateAchievementsGrid();
        }

        private void PopulateAchievementsGrid()
        {
            // Clear existing achievements
            var leftColumn = (StackPanel)AchievementsGrid.Children[0];
            var rightColumn = (StackPanel)AchievementsGrid.Children[1];

            leftColumn.Children.Clear();
            rightColumn.Children.Clear();

            var achievementsToShow = _filteredAchievements.ToList();

            // Distribute achievements between left and right columns
            for (int i = 0; i < achievementsToShow.Count; i++)
            {
                var achievementCard = CreateAchievementCard(achievementsToShow[i]);

                if (i % 2 == 0)
                    leftColumn.Children.Add(achievementCard);
                else
                    rightColumn.Children.Add(achievementCard);
            }
        }

        private Border CreateAchievementCard(Achievement achievement)
        {
            var border = new Border
            {
                Margin = new Thickness(0, 0, 0, 15),
                Padding = new Thickness(20),
                CornerRadius = new CornerRadius(8),
                Background = achievement.IsEarned
                    ? (Brush)FindResource("BackgroundBrush")
                    : (Brush)FindResource("BackgroundBrush"),
                BorderBrush = achievement.IsEarned
                    ? (Brush)FindResource("SuccessBrush")
                    : (Brush)FindResource("BorderBrush"),
                BorderThickness = new Thickness(achievement.IsEarned ? 2 : 1),
                Opacity = achievement.IsEarned ? 1.0 : 0.6
            };

            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            // Icon
            var iconBorder = new Border
            {
                Width = 60,
                Height = 60,
                CornerRadius = new CornerRadius(30),
                Background = achievement.IsEarned
                    ? (SolidColorBrush)new BrushConverter().ConvertFrom(achievement.IconColor)
                    : new SolidColorBrush(Color.FromRgb(158, 158, 158))
            };

            var iconGrid = new Grid();

            var icon = new FontAwesome.WPF.FontAwesome
            {
                Icon = achievement.Icon,
                Foreground = Brushes.White,
                Width = 24,
                Height = 24,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center
            };

            var badge = new Border
            {
                Width = 20,
                Height = 20,
                CornerRadius = new CornerRadius(10),
                HorizontalAlignment = HorizontalAlignment.Right,
                VerticalAlignment = VerticalAlignment.Top,
                Margin = new Thickness(0, -5, -5, 0),
                Background = achievement.IsEarned
                    ? new SolidColorBrush(Color.FromRgb(255, 215, 0))
                    : new SolidColorBrush(Color.FromRgb(117, 117, 117))
            };

            var badgeIcon = new FontAwesome.WPF.FontAwesome
            {
                Icon = achievement.IsEarned ? FontAwesomeIcon.Check : FontAwesomeIcon.Lock,
                Foreground = Brushes.White,
                Width = achievement.IsEarned ? 12 : 10,
                Height = achievement.IsEarned ? 12 : 10,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center
            };

            badge.Child = badgeIcon;
            iconGrid.Children.Add(icon);
            iconGrid.Children.Add(badge);
            iconBorder.Child = iconGrid;

            // Content
            var contentPanel = new StackPanel
            {
                Margin = new Thickness(15, 0, 0, 0),
                VerticalAlignment = VerticalAlignment.Center
            };

            var titleText = new TextBlock
            {
                Text = achievement.Title,
                Foreground = (Brush)FindResource("TextBrush"),
                FontSize = 16,
                FontWeight = FontWeights.SemiBold
            };

            var descriptionText = new TextBlock
            {
                Text = achievement.Description,
                Foreground = (Brush)FindResource("TextBrush"),
                FontSize = 12,
                Opacity = 0.7,
                Margin = new Thickness(0, 4, 0, 0),
                TextWrapping = TextWrapping.Wrap
            };

            contentPanel.Children.Add(titleText);
            contentPanel.Children.Add(descriptionText);

            // Earned date or progress
            if (achievement.IsEarned)
            {
                var earnedText = new TextBlock
                {
                    Text = $"Earned: {achievement.EarnedDate}",
                    Foreground = (Brush)FindResource("SuccessBrush"),
                    FontSize = 11,
                    FontWeight = FontWeights.SemiBold,
                    Margin = new Thickness(0, 8, 0, 0)
                };
                contentPanel.Children.Add(earnedText);
            }
            else if (achievement.HasProgress)
            {
                var progressPanel = new StackPanel
                {
                    Orientation = Orientation.Horizontal,
                    Margin = new Thickness(0, 8, 0, 0)
                };

                var progressText = new TextBlock
                {
                    Text = $"Progress: {achievement.CurrentValue}/{achievement.RequiredValue}",
                    Foreground = (Brush)FindResource("TextBrush"),
                    FontSize = 11,
                    Opacity = 0.8
                };

                var progressBar = new ProgressBar
                {
                    Value = achievement.ProgressPercentage,
                    Maximum = 100,
                    Width = 60,
                    Height = 4,
                    Margin = new Thickness(8, 2, 0, 0),
                    Background = (Brush)FindResource("BorderBrush"),
                    Foreground = (Brush)FindResource("AccentBrush"),
                    BorderThickness = new Thickness(0)
                };

                progressPanel.Children.Add(progressText);
                progressPanel.Children.Add(progressBar);
                contentPanel.Children.Add(progressPanel);
            }

            Grid.SetColumn(iconBorder, 0);
            Grid.SetColumn(contentPanel, 1);

            grid.Children.Add(iconBorder);
            grid.Children.Add(contentPanel);
            border.Child = grid;

            return border;
        }

        #endregion

        #region Event Handlers

        private void FilterAchievements_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button button && button.Tag is string filter)
            {
                FilterAchievements(filter);
            }
        }

        private void FilterAchievements(string filter)
        {
            _currentFilter = filter;
            _filteredAchievements.Clear();

            IEnumerable<Achievement> achievementsToShow = _allAchievements;

            switch (filter)
            {
                case "Earned":
                    achievementsToShow = _allAchievements.Where(a => a.IsEarned);
                    break;
                case "Locked":
                    achievementsToShow = _allAchievements.Where(a => !a.IsEarned);
                    break;
                case "All":
                default:
                    achievementsToShow = _allAchievements;
                    break;
            }

            foreach (var achievement in achievementsToShow)
            {
                _filteredAchievements.Add(achievement);
            }

            PopulateAchievementsGrid();
        }

        #endregion

        #region Data Persistence (Placeholder methods)

        private void LoadAchievementProgress()
        {
            // Simple file-based persistence without external dependencies
            try
            {
                string appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                string achievementFile = System.IO.Path.Combine(appDataPath, "PROSCANNERCONT", "achievements.txt");

                if (!System.IO.File.Exists(achievementFile))
                    return;

                string[] lines = System.IO.File.ReadAllLines(achievementFile);
                foreach (string line in lines)
                {
                    if (string.IsNullOrWhiteSpace(line))
                        continue;

                    string[] parts = line.Split('|');
                    if (parts.Length >= 4)
                    {
                        string id = parts[0];
                        int currentValue = int.Parse(parts[1]);
                        bool isEarned = bool.Parse(parts[2]);
                        string earnedDate = parts[3];

                        var achievement = _allAchievements.FirstOrDefault(a => a.Id == id);
                        if (achievement != null)
                        {
                            achievement.CurrentValue = currentValue;
                            achievement.IsEarned = isEarned;
                            achievement.EarnedDate = earnedDate;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error loading achievement data: {ex.Message}");
            }
        }

        public void SaveAchievementProgress()
        {
            // Simple file-based persistence without external dependencies
            try
            {
                string appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                string achievementDir = System.IO.Path.Combine(appDataPath, "PROSCANNERCONT");
                string achievementFile = System.IO.Path.Combine(achievementDir, "achievements.txt");

                if (!System.IO.Directory.Exists(achievementDir))
                    System.IO.Directory.CreateDirectory(achievementDir);

                var lines = _allAchievements.Select(a => $"{a.Id}|{a.CurrentValue}|{a.IsEarned}|{a.EarnedDate ?? ""}").ToArray();
                System.IO.File.WriteAllLines(achievementFile, lines);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error saving achievement data: {ex.Message}");
            }
        }

        #endregion

        #region INotifyPropertyChanged Implementation

        protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        #endregion
    }

    #region Achievement Model and Enums

    public class Achievement : INotifyPropertyChanged
    {
        private string _id;
        private string _title;
        private string _description;
        private AchievementCategory _category;
        private FontAwesomeIcon _icon;
        private string _iconColor;
        private int _requiredValue;
        private int _currentValue;
        private bool _isEarned;
        private string _earnedDate;

        public string Id
        {
            get => _id;
            set { _id = value; OnPropertyChanged(); }
        }

        public string Title
        {
            get => _title;
            set { _title = value; OnPropertyChanged(); }
        }

        public string Description
        {
            get => _description;
            set { _description = value; OnPropertyChanged(); }
        }

        public AchievementCategory Category
        {
            get => _category;
            set { _category = value; OnPropertyChanged(); }
        }

        public FontAwesomeIcon Icon
        {
            get => _icon;
            set { _icon = value; OnPropertyChanged(); }
        }

        public string IconColor
        {
            get => _iconColor;
            set { _iconColor = value; OnPropertyChanged(); }
        }

        public int RequiredValue
        {
            get => _requiredValue;
            set { _requiredValue = value; OnPropertyChanged(); }
        }

        public int CurrentValue
        {
            get => _currentValue;
            set
            {
                _currentValue = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(ProgressPercentage));
                OnPropertyChanged(nameof(HasProgress));
            }
        }

        public bool IsEarned
        {
            get => _isEarned;
            set { _isEarned = value; OnPropertyChanged(); }
        }

        public string EarnedDate
        {
            get => _earnedDate;
            set { _earnedDate = value; OnPropertyChanged(); }
        }

        public double ProgressPercentage => RequiredValue > 0 ? (double)CurrentValue / RequiredValue * 100 : 0;

        public bool HasProgress => !IsEarned && CurrentValue > 0 && RequiredValue > 1;

        public event PropertyChangedEventHandler? PropertyChanged;

        protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }

    public enum AchievementCategory
    {
        SecurityExpert,
        NetworkScout,
        BugHunter,
        PerformanceExpert
    }

    #endregion

    #region Achievement Integration Helper Class

    public static class AchievementTracker
    {
        private static AchievementsPage _achievementPage;

        public static void Initialize(AchievementsPage achievementPage)
        {
            _achievementPage = achievementPage;
        }

        // Security Expert Achievement Triggers
        public static void OnNetworkScanCompleted()
        {
            _achievementPage?.UpdateAchievementProgress("security_first_steps", 1);
        }

        public static void OnSecurityScoreUpdated(int score)
        {
            if (score >= 80)
                _achievementPage?.UpdateAchievementProgress("security_conscious", score);
            if (score >= 100)
                _achievementPage?.UpdateAchievementProgress("cyber_sentinel", score);
        }

        public static void OnVulnerabilityFixed(int totalFixed)
        {
            _achievementPage?.UpdateAchievementProgress("vulnerability_vanquisher", totalFixed);
        }

        public static void OnThreatBlocked(int totalBlocked)
        {
            _achievementPage?.UpdateAchievementProgress("shield_master", totalBlocked);
        }

        public static void OnEncryptionEnabled(int totalDevices)
        {
            _achievementPage?.UpdateAchievementProgress("encryption_enthusiast", totalDevices);
        }

        public static void OnFirewallConfigured()
        {
            _achievementPage?.UpdateAchievementProgress("firewall_guardian", 1);
        }

        public static void OnAccessControlSetup()
        {
            _achievementPage?.UpdateAchievementProgress("access_controller", 1);
        }

        public static void OnSecurityAuditCompleted(int totalAudits)
        {
            _achievementPage?.UpdateAchievementProgress("security_auditor", totalAudits);
        }

        public static void OnHighSecurityScoreMaintained(int days)
        {
            _achievementPage?.UpdateAchievementProgress("fortress_builder", days);
        }

        // Network Scout Achievement Triggers
        public static void OnHostsScanned(int totalHosts)
        {
            _achievementPage?.UpdateAchievementProgress("network_explorer", totalHosts);
        }

        public static void OnDevicesDiscovered(int totalDevices)
        {
            _achievementPage?.UpdateAchievementProgress("device_discoverer", totalDevices);
        }

        public static void OnPortsScanned(int totalPorts)
        {
            _achievementPage?.UpdateAchievementProgress("port_navigator", totalPorts);
        }

        public static void OnTopologyMapped()
        {
            _achievementPage?.UpdateAchievementProgress("topology_master", 1);
        }

        public static void OnIPRangeScanned(int totalRanges)
        {
            _achievementPage?.UpdateAchievementProgress("range_rider", totalRanges);
        }

        public static void OnDetailedScanCompleted(int totalDetailedScans)
        {
            _achievementPage?.UpdateAchievementProgress("deep_diver", totalDetailedScans);
        }

        public static void OnNetworkDocumented()
        {
            _achievementPage?.UpdateAchievementProgress("network_cartographer", 1);
        }

        public static void OnHiddenDeviceFound(int totalHiddenDevices)
        {
            _achievementPage?.UpdateAchievementProgress("discovery_dynamo", totalHiddenDevices);
        }

        // Bug Hunter Achievement Triggers
        public static void OnVulnerabilityFound(int totalFound)
        {
            _achievementPage?.UpdateAchievementProgress("bug_finder", totalFound);
        }

        public static void OnCriticalVulnerabilityFound()
        {
            _achievementPage?.UpdateAchievementProgress("critical_hunter", 1);
        }

        public static void OnExploitableVulnerabilityFound(int totalExploitable)
        {
            _achievementPage?.UpdateAchievementProgress("exploit_expert", totalExploitable);
        }

        public static void OnZeroDayFound()
        {
            _achievementPage?.UpdateAchievementProgress("zero_day_detector", 1);
        }

        public static void OnVulnerabilityResolved(int totalResolved)
        {
            _achievementPage?.UpdateAchievementProgress("patch_master", totalResolved);
        }

        public static void OnVulnerabilityReportCreated(int totalReports)
        {
            _achievementPage?.UpdateAchievementProgress("security_researcher", totalReports);
        }

        // Performance Expert Achievement Triggers
        public static void OnFastScanCompleted(int fastScansCount)
        {
            _achievementPage?.UpdateAchievementProgress("speed_demon", fastScansCount);
        }

        public static void OnPerformanceOptimized(int optimizationPercentage)
        {
            _achievementPage?.UpdateAchievementProgress("efficiency_expert", optimizationPercentage);
        }

        public static void OnBulkScanCompleted(int hostsInSession)
        {
            if (hostsInSession >= 500)
                _achievementPage?.UpdateAchievementProgress("bulk_scanner", hostsInSession);
        }

        public static void OnContinuousMonitoring(int hoursMonitored)
        {
            if (hoursMonitored >= 24)
                _achievementPage?.UpdateAchievementProgress("marathon_runner", hoursMonitored);
        }

        public static void OnResourceUsageOptimized(int resourcePercentage)
        {
            if (resourcePercentage <= 10)
                _achievementPage?.UpdateAchievementProgress("resource_manager", resourcePercentage);
        }

        public static void OnAutomationScheduleCreated(int totalSchedules)
        {
            _achievementPage?.UpdateAchievementProgress("automation_master", totalSchedules);
        }
    }

    #endregion

    #region Achievement Data Persistence Helper

    #region Achievement Data Persistence Helper

    public class AchievementDataManager
    {
        public static void SaveAchievementData(ObservableCollection<Achievement> achievements)
        {
            try
            {
                string appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                string achievementDir = System.IO.Path.Combine(appDataPath, "PROSCANNERCONT");
                string achievementFile = System.IO.Path.Combine(achievementDir, "achievements_backup.txt");

                if (!System.IO.Directory.Exists(achievementDir))
                    System.IO.Directory.CreateDirectory(achievementDir);

                var lines = achievements.Select(a => $"{a.Id}|{a.CurrentValue}|{a.IsEarned}|{a.EarnedDate ?? ""}").ToArray();
                System.IO.File.WriteAllLines(achievementFile, lines);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error saving achievement data: {ex.Message}");
            }
        }

        public static void LoadAchievementData(ObservableCollection<Achievement> achievements)
        {
            try
            {
                string appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                string achievementFile = System.IO.Path.Combine(appDataPath, "PROSCANNERCONT", "achievements_backup.txt");

                if (!System.IO.File.Exists(achievementFile))
                    return;

                string[] lines = System.IO.File.ReadAllLines(achievementFile);
                foreach (string line in lines)
                {
                    if (string.IsNullOrWhiteSpace(line))
                        continue;

                    string[] parts = line.Split('|');
                    if (parts.Length >= 4)
                    {
                        string id = parts[0];
                        int currentValue = int.Parse(parts[1]);
                        bool isEarned = bool.Parse(parts[2]);
                        string earnedDate = parts[3];

                        var achievement = achievements.FirstOrDefault(a => a.Id == id);
                        if (achievement != null)
                        {
                            achievement.CurrentValue = currentValue;
                            achievement.IsEarned = isEarned;
                            achievement.EarnedDate = earnedDate;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error loading achievement data: {ex.Message}");
            }
        }

    }

    #endregion
    #endregion
}


