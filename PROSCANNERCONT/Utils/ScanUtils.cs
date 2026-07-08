using System;
using System.Collections.Generic;
using System.Windows.Controls;
using System.Windows;
using System.Windows.Media;
using PROSCANNERCONT.Models;
using System.Windows.Controls.Primitives;
using PROSCANNERCONT.Utils;

namespace PROSCANNERCONT.Utils
{
    public static class CalendarExtensions
    {
        public static CalendarDayButton FindDayButton(this Calendar calendar, DateTime date)
        {
            if (calendar == null) return null;

            foreach (var child in GetVisualDescendants(calendar))
            {
                if (child is CalendarDayButton button)
                {
                    if (button.DataContext is DateTime buttonDate &&
                        buttonDate.Date == date.Date)
                    {
                        return button;
                    }
                }
            }
            return null;
        }

        private static IEnumerable<DependencyObject> GetVisualDescendants(DependencyObject root)
        {
            if (root == null) yield break;

            int count = VisualTreeHelper.GetChildrenCount(root);
            for (int i = 0; i < count; i++)
            {
                var child = VisualTreeHelper.GetChild(root, i);
                yield return child;

                foreach (var descendant in GetVisualDescendants(child))
                {
                    yield return descendant;
                }
            }
        }
    }

    public static class ScanHistoryManager
    {
        private const string SAVE_FILE_PATH = "scanHistory.json";
        private static readonly System.Text.Json.JsonSerializerOptions _jsonOptions = new System.Text.Json.JsonSerializerOptions
        {
            WriteIndented = true
        };

        public static void SaveScanHistory(Dictionary<DateTime, List<ScanResult>> history)
        {
            try
            {
                string jsonString = System.Text.Json.JsonSerializer.Serialize(history, _jsonOptions);
                System.IO.File.WriteAllText(SAVE_FILE_PATH, jsonString);
            }
            catch (Exception ex)
            {
                AppDialog.Show($"Error saving scan history: {ex.Message}", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        public static Dictionary<DateTime, List<ScanResult>> LoadScanHistory()
        {
            try
            {
                if (System.IO.File.Exists(SAVE_FILE_PATH))
                {
                    string jsonString = System.IO.File.ReadAllText(SAVE_FILE_PATH);
                    return System.Text.Json.JsonSerializer.Deserialize<Dictionary<DateTime, List<ScanResult>>>(
                        jsonString, _jsonOptions) ?? new Dictionary<DateTime, List<ScanResult>>();
                }
            }
            catch (Exception ex)
            {
                AppDialog.Show($"Error loading scan history: {ex.Message}", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
            return new Dictionary<DateTime, List<ScanResult>>();
        }
    }
}


