using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Services;
using PROSCANNERCONT.Utils;

namespace PROSCANNERCONT.Views
{
    public partial class GalleryPage : Page
    {
        private ObservableCollection<GalleryItem> _filteredItems;
        private string _currentFilter = "All";
        private bool _isUpdatingFilters = false;
        private bool _isInitialized = false;

        public GalleryPage()
        {
            try
            {
                InitializeComponent();
                InitializeGallery();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"GalleryPage constructor error: {ex.Message}");
                // Create minimal initialization to prevent crashes
                _filteredItems = new ObservableCollection<GalleryItem>();
                _currentFilter = "All";
            }
        }

        private void InitializeGallery()
        {
            try
            {
                _filteredItems = new ObservableCollection<GalleryItem>();

                // Wait for controls to be loaded before setting ItemsSource
                Loaded += GalleryPage_Loaded;
                _isInitialized = true;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Gallery initialization error: {ex.Message}");
            }
        }

        private void GalleryPage_Loaded(object sender, RoutedEventArgs e)
        {
            try
            {
                // Now that controls are loaded, set up the ItemsSource
                if (GalleryItemsControl != null && _filteredItems != null)
                {
                    GalleryItemsControl.ItemsSource = _filteredItems;
                }

                // Load initial data
                RefreshGallery();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Gallery loaded event error: {ex.Message}");
                ShowSafeEmptyState();
            }
        }

        private void RefreshGallery()
        {
            try
            {
                if (!_isInitialized) return;

                ApplyFilter(_currentFilter);
                UpdateStats();
                UpdateEmptyState();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Refresh gallery error: {ex.Message}");
                ShowSafeEmptyState();
            }
        }

        private void ApplyFilter(string filterType)
        {
            try
            {
                // Ensure _filteredItems exists
                if (_filteredItems == null)
                {
                    _filteredItems = new ObservableCollection<GalleryItem>();
                    if (GalleryItemsControl != null)
                    {
                        GalleryItemsControl.ItemsSource = _filteredItems;
                    }
                }

                _filteredItems.Clear();

                // Try to get gallery items safely
                ObservableCollection<GalleryItem> allItems = null;
                try
                {
                    allItems = GalleryManager.GalleryItems;
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"Error accessing GalleryManager: {ex.Message}");
                }

                if (allItems == null || allItems.Count == 0)
                {
                    _currentFilter = filterType ?? "All";
                    return;
                }

                // Manual filtering without LINQ to avoid issues
                foreach (var item in allItems)
                {
                    if (item == null) continue;

                    bool shouldInclude = false;

                    try
                    {
                        switch (filterType)
                        {
                            case "All":
                                shouldInclude = true;
                                break;

                            case "Manual":
                                shouldInclude = item.IsManual;
                                break;

                            case "Scan Results":
                                shouldInclude = !item.IsManual;
                                break;

                            case "Dashboard":
                                shouldInclude = string.Equals(item.PageType, "Dashboard", StringComparison.OrdinalIgnoreCase);
                                break;

                            case "Settings":
                                shouldInclude = string.Equals(item.PageType, "Settings", StringComparison.OrdinalIgnoreCase);
                                break;

                            default:
                                shouldInclude = false;
                                break;
                        }

                        if (shouldInclude)
                        {
                            _filteredItems.Add(item);
                        }
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"Error filtering item {item.Id}: {ex.Message}");
                    }
                }

                _currentFilter = filterType ?? "All";
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"ApplyFilter error: {ex.Message}");
                _currentFilter = filterType ?? "All";
            }
        }

        private void UpdateStats()
        {
            try
            {
                int totalCount = 0;
                DateTime? latestTimestamp = null;

                // Safely get total count and latest timestamp
                try
                {
                    var allItems = GalleryManager.GalleryItems;
                    if (allItems != null)
                    {
                        totalCount = allItems.Count;

                        foreach (var item in allItems)
                        {
                            if (item != null && (!latestTimestamp.HasValue || item.Timestamp > latestTimestamp.Value))
                            {
                                latestTimestamp = item.Timestamp;
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"Error getting gallery stats: {ex.Message}");
                }

                int filteredCount = _filteredItems?.Count ?? 0;

                // Update UI safely
                try
                {
                    if (ItemCountText != null)
                    {
                        if (_currentFilter == "All")
                        {
                            ItemCountText.Text = $"{totalCount} screenshot{(totalCount != 1 ? "s" : "")}";
                        }
                        else
                        {
                            ItemCountText.Text = $"{filteredCount} of {totalCount} screenshot{(totalCount != 1 ? "s" : "")}";
                        }
                    }

                    if (LastUpdatedText != null)
                    {
                        if (latestTimestamp.HasValue)
                        {
                            LastUpdatedText.Text = $"Last updated: {latestTimestamp.Value:MM/dd/yyyy HH:mm}";
                        }
                        else
                        {
                            LastUpdatedText.Text = "Last updated: Never";
                        }
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"Error updating UI stats: {ex.Message}");
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"UpdateStats error: {ex.Message}");
                ShowSafeEmptyState();
            }
        }

        private void UpdateEmptyState()
        {
            try
            {
                bool hasItems = _filteredItems?.Count > 0;

                if (GalleryItemsControl != null)
                {
                    GalleryItemsControl.Visibility = hasItems ? Visibility.Visible : Visibility.Collapsed;
                }

                if (EmptyStatePanel != null)
                {
                    EmptyStatePanel.Visibility = hasItems ? Visibility.Collapsed : Visibility.Visible;
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"UpdateEmptyState error: {ex.Message}");
            }
        }

        private void ShowSafeEmptyState()
        {
            try
            {
                if (ItemCountText != null) ItemCountText.Text = "0 screenshots";
                if (LastUpdatedText != null) LastUpdatedText.Text = "Last updated: Never";
                if (GalleryItemsControl != null) GalleryItemsControl.Visibility = Visibility.Collapsed;
                if (EmptyStatePanel != null) EmptyStatePanel.Visibility = Visibility.Visible;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"ShowSafeEmptyState error: {ex.Message}");
            }
        }

        private void FilterButton_Checked(object sender, RoutedEventArgs e)
        {
            if (!_isInitialized || _isUpdatingFilters) return;

            try
            {
                if (!(sender is ToggleButton button)) return;

                _isUpdatingFilters = true;

                // Safely uncheck all other filter buttons
                try
                {
                    if (AllFilter != null && AllFilter != button) AllFilter.IsChecked = false;
                    if (ManualFilter != null && ManualFilter != button) ManualFilter.IsChecked = false;
                    if (ScanFilter != null && ScanFilter != button) ScanFilter.IsChecked = false;
                    if (DashboardFilter != null && DashboardFilter != button) DashboardFilter.IsChecked = false;
                    if (SettingsFilter != null && SettingsFilter != button) SettingsFilter.IsChecked = false;

                    // Ensure the clicked button stays checked
                    button.IsChecked = true;
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"Error updating filter buttons: {ex.Message}");
                }

                // Apply filter
                string filterName = button.Content?.ToString() ?? "All";
                ApplyFilter(filterName);
                UpdateStats();
                UpdateEmptyState();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"FilterButton_Checked error: {ex.Message}");
            }
            finally
            {
                _isUpdatingFilters = false;
            }
        }

        private void RefreshButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                RefreshGallery();
            }
            catch (Exception ex)
            {
                AppDialog.Show($"Error refreshing gallery: {ex.Message}", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ClearAllButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var result = AppDialog.Show(
                    "Are you sure you want to delete all screenshots? This action cannot be undone.",
                    "Confirm Clear All",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Warning);

                if (result == MessageBoxResult.Yes)
                {
                    try
                    {
                        GalleryManager.ClearGallery();
                        RefreshGallery();
                        AppDialog.Show("All screenshots have been cleared.", "Success",
                            MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                    catch (Exception ex)
                    {
                        AppDialog.Show($"Error clearing gallery: {ex.Message}", "Error",
                            MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"ClearAllButton_Click error: {ex.Message}");
            }
        }

        private void TakeScreenshotButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // Navigate back to previous page
                if (NavigationService?.CanGoBack == true)
                {
                    NavigationService.GoBack();
                }
                else
                {
                    // Alternative navigation method
                    var mainWindow = Application.Current.MainWindow as MainWindow;
                    if (mainWindow != null)
                    {
                        try
                        {
                            // Try to navigate to Dashboard
                            var navMethod = mainWindow.GetType().GetMethod("NavigateToPage");
                            navMethod?.Invoke(mainWindow, new object[] { "Dashboard" });
                        }
                        catch (Exception ex)
                        {
                            System.Diagnostics.Debug.WriteLine($"Navigation error: {ex.Message}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"TakeScreenshotButton_Click error: {ex.Message}");
            }
        }

        private void GalleryCard_Click(object sender, MouseButtonEventArgs e)
        {
            try
            {
                if (sender is Border border && border.Tag is GalleryItem item)
                {
                    // Try to open ScreenshotViewer if it exists
                    try
                    {
                        var viewerType = Type.GetType("PROSCANNERCONT.Views.ScreenshotViewer");
                        if (viewerType != null)
                        {
                            var viewer = Activator.CreateInstance(viewerType, item) as Window;
                            viewer?.ShowDialog();
                        }
                        else
                        {
                            // ScreenshotViewer doesn't exist, show info message
                            AppDialog.Show(
                                $"Screenshot: {item.Title}\n" +
                                $"Date: {item.Timestamp:yyyy-MM-dd HH:mm:ss}\n" +
                                $"Type: {(item.IsManual ? "Manual" : "Automatic")}\n" +
                                $"Page: {item.PageType}\n\n" +
                                $"Create ScreenshotViewer.xaml to view full-size screenshots.",
                                "Screenshot Details",
                                MessageBoxButton.OK,
                                MessageBoxImage.Information);
                        }
                    }
                    catch (Exception ex)
                    {
                        // Fallback: show screenshot details
                        AppDialog.Show(
                            $"Screenshot: {item.Title}\n" +
                            $"Date: {item.Timestamp:yyyy-MM-dd HH:mm:ss}\n" +
                            $"Type: {(item.IsManual ? "Manual" : "Automatic")}\n" +
                            $"Page: {item.PageType}",
                            "Screenshot Details",
                            MessageBoxButton.OK,
                            MessageBoxImage.Information);
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"GalleryCard_Click error: {ex.Message}");
            }
        }
    }
}


