using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Windows;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Utils;

namespace PROSCANNERCONT.Utils
{
    public static class NotificationUtils
    {
        // Shows a toast notification for network change detections
        public static void ShowChangeDetected(NetworkChangeSummary summary)
        {
            if (!summary.HasChanges) return;

            var message = BuildChangeMessage(summary);

            try
            {
                ShowInAppToast($"Network Change Detected ({summary.TotalChanges} changes)", message, "#F4C247");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[NotificationUtils.ShowChangeDetected] {ex.Message}");
            }
        }

        public static void ShowScanComplete(string target, int openPorts, int devices)
        {
            try
            {
                var message = devices > 0
                    ? $"Found {devices} devices, {openPorts} open ports"
                    : $"Found {openPorts} open ports on {target}";
                ShowInAppToast("Scan Complete", message, "#4EC9B0");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[NotificationUtils.ShowScanComplete] {ex.Message}");
            }
        }

        private static void ShowInAppToast(string title, string message, string hexColor)
        {
            // AlertToast.Show dispatches to the UI thread internally, so call directly
            try
            {
                AlertToast.Show(title, message, hexColor);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[Toast] {title}: {message} â€” {ex.Message}");
            }
        }

        private static string BuildChangeMessage(NetworkChangeSummary summary)
        {
            var parts = new List<string>();
            if (summary.NewDevices.Count > 0)
                parts.Add($"{summary.NewDevices.Count} new device(s)");
            if (summary.DisappearedDevices.Count > 0)
                parts.Add($"{summary.DisappearedDevices.Count} device(s) went offline");
            if (summary.NewOpenPorts.Count > 0)
                parts.Add($"{summary.NewOpenPorts.Count} new open port(s)");
            if (summary.ClosedPorts.Count > 0)
                parts.Add($"{summary.ClosedPorts.Count} port(s) closed");
            if (summary.ServiceChanges.Count > 0)
                parts.Add($"{summary.ServiceChanges.Count} service change(s)");
            return string.Join(", ", parts);
        }
    }
}
