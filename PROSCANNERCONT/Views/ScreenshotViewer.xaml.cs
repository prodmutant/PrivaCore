using System;
using System.IO;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media.Imaging;
using Microsoft.Win32;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Services;
using PROSCANNERCONT.Utils;

namespace PROSCANNERCONT.Views
{
    public partial class ScreenshotViewer : Window
    {
        private GalleryItem _currentItem;
        private double _currentZoom = 1.0;

        public ScreenshotViewer(GalleryItem item)
        {
            InitializeComponent();
            _currentItem = item;
            LoadScreenshot();
            SetupEventHandlers();
        }

        private void LoadScreenshot()
        {
            if (_currentItem?.Screenshot != null)
            {
                MainImage.Source = _currentItem.Screenshot;
                TitleText.Text = _currentItem.Title ?? "Screenshot";
                TimestampText.Text = _currentItem.Timestamp.ToString("MMM dd, yyyy at HH:mm");

                if (_currentItem.IsManual)
                {
                    TypeBadge.Visibility = Visibility.Visible;
                    TypeText.Text = "MANUAL";
                }
                else
                {
                    TypeBadge.Visibility = Visibility.Collapsed;
                }

                // Set window title
                Title = $"Screenshot Viewer - {_currentItem.Title}";
            }
        }

        private void SetupEventHandlers()
        {
            // Mouse wheel for zooming
            MainImage.MouseWheel += MainImage_MouseWheel;

            // Double-click to fit/actual size toggle
            MainImage.MouseLeftButtonDown += MainImage_MouseLeftButtonDown;

            // Auto-hide panels on mouse movement
            MouseMove += ScreenshotViewer_MouseMove;

            // Auto-fit on load
            Loaded += (s, e) => ZoomToFit();
        }

        private void MainImage_MouseWheel(object sender, MouseWheelEventArgs e)
        {
            if (Keyboard.Modifiers == ModifierKeys.Control)
            {
                if (e.Delta > 0)
                {
                    ZoomIn();
                }
                else
                {
                    ZoomOut();
                }
                e.Handled = true;
            }
        }

        private void MainImage_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ClickCount == 2)
            {
                if (Math.Abs(_currentZoom - 1.0) < 0.1)
                {
                    ZoomToFit();
                }
                else
                {
                    ZoomToActualSize();
                }
            }
        }

        private void ScreenshotViewer_MouseMove(object sender, MouseEventArgs e)
        {
            // Show panels when mouse moves
            InfoPanel.Visibility = Visibility.Visible;
            ControlPanel.Visibility = Visibility.Visible;
        }

        private void Window_KeyDown(object sender, KeyEventArgs e)
        {
            switch (e.Key)
            {
                case Key.Escape:
                    Close();
                    break;
                case Key.OemPlus:
                case Key.Add:
                    ZoomIn();
                    break;
                case Key.OemMinus:
                case Key.Subtract:
                    ZoomOut();
                    break;
                case Key.D0:
                    ZoomToFit();
                    break;
                case Key.D1:
                    ZoomToActualSize();
                    break;
                case Key.S:
                    if (Keyboard.Modifiers == ModifierKeys.Control)
                        SaveScreenshot();
                    break;
                case Key.Delete:
                    DeleteScreenshot();
                    break;
            }
        }

        private void ZoomIn()
        {
            _currentZoom = Math.Min(_currentZoom * 1.2, 5.0);
            ImageScale.ScaleX = _currentZoom;
            ImageScale.ScaleY = _currentZoom;
        }

        private void ZoomOut()
        {
            _currentZoom = Math.Max(_currentZoom / 1.2, 0.1);
            ImageScale.ScaleX = _currentZoom;
            ImageScale.ScaleY = _currentZoom;
        }

        private void ZoomToFit()
        {
            _currentZoom = 1.0;
            ImageScale.ScaleX = _currentZoom;
            ImageScale.ScaleY = _currentZoom;
        }

        private void ZoomToActualSize()
        {
            if (_currentItem?.Screenshot != null)
            {
                var imageWidth = _currentItem.Screenshot.PixelWidth;
                var imageHeight = _currentItem.Screenshot.PixelHeight;
                var viewerWidth = ImageScrollViewer.ActualWidth;
                var viewerHeight = ImageScrollViewer.ActualHeight;

                if (viewerWidth > 0 && viewerHeight > 0)
                {
                    var scaleX = viewerWidth / imageWidth;
                    var scaleY = viewerHeight / imageHeight;
                    _currentZoom = Math.Min(scaleX, scaleY);
                }
                else
                {
                    _currentZoom = 1.0;
                }

                ImageScale.ScaleX = _currentZoom;
                ImageScale.ScaleY = _currentZoom;
            }
        }

        private void SaveScreenshot()
        {
            try
            {
                if (_currentItem?.Screenshot == null)
                {
                    AppDialog.Show("No screenshot to save.", "Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                var saveFileDialog = new SaveFileDialog
                {
                    Title = "Save Screenshot",
                    Filter = "PNG Image|*.png|JPEG Image|*.jpg|Bitmap Image|*.bmp",
                    DefaultExt = "png",
                    FileName = $"Screenshot_{_currentItem.Timestamp:yyyy-MM-dd_HH-mm-ss}"
                };

                if (saveFileDialog.ShowDialog() == true)
                {
                    var encoder = new PngBitmapEncoder();
                    encoder.Frames.Add(BitmapFrame.Create(_currentItem.Screenshot));

                    using (var fileStream = new FileStream(saveFileDialog.FileName, FileMode.Create))
                    {
                        encoder.Save(fileStream);
                    }

                    AppDialog.Show("Screenshot saved successfully!", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                AppDialog.Show($"Error saving screenshot: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void DeleteScreenshot()
        {
            var result = AppDialog.Show(
                "Are you sure you want to delete this screenshot?",
                "Confirm Delete",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (result == MessageBoxResult.Yes)
            {
                try
                {
                    GalleryManager.RemoveScreenshot(_currentItem);
                    AppDialog.Show("Screenshot deleted successfully.", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
                    Close();
                }
                catch (Exception ex)
                {
                    AppDialog.Show($"Error deleting screenshot: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        // Button Event Handlers
        private void SaveButton_Click(object sender, RoutedEventArgs e)
        {
            SaveScreenshot();
        }

        private void DeleteButton_Click(object sender, RoutedEventArgs e)
        {
            DeleteScreenshot();
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private void ZoomInButton_Click(object sender, RoutedEventArgs e)
        {
            ZoomIn();
        }

        private void ZoomOutButton_Click(object sender, RoutedEventArgs e)
        {
            ZoomOut();
        }

        private void ZoomFitButton_Click(object sender, RoutedEventArgs e)
        {
            ZoomToFit();
        }

        private void Zoom100Button_Click(object sender, RoutedEventArgs e)
        {
            ZoomToActualSize();
        }
    }
}


