using System;
using System.Diagnostics;
using System.IO;
using Microsoft.Win32;

namespace PROSCANNERCONT.Services
{
    /// <summary>
    /// Detects whether Npcap is installed on the host. Traffic Analysis and the
    /// NIDS engine depend on Npcap (or WinPcap-compat mode); previously the app
    /// would crash on first packet-capture attempt with no clear diagnosis.
    /// Now the App startup checks for it and shows a friendly install prompt
    /// before the user hits the broken path.
    /// </summary>
    public static class NpcapDetector
    {
        public const string DownloadUrl = "https://npcap.com/#download";

        public sealed class Result
        {
            public bool Installed { get; init; }
            public string? Version { get; init; }
            public bool WinPcapCompat { get; init; }
            public string? Reason { get; init; }
        }

        public static Result Detect()
        {
            try
            {
                // Method 1: Registry key check (preferred — works without
                // requiring SharpPcap to be loaded).
                using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\WOW6432Node\Npcap")
                              ?? Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Npcap"))
                {
                    if (key != null)
                    {
                        var ver = key.GetValue("(default)") as string
                               ?? key.GetValue("InstallVersion") as string;
                        var compatFlag = key.GetValue("WinPcapCompatible");
                        bool compat = compatFlag is int i ? i != 0 : false;
                        return new Result
                        {
                            Installed = true,
                            Version = ver,
                            WinPcapCompat = compat
                        };
                    }
                }

                // Method 2: Driver file check.
                var systemRoot = Environment.GetFolderPath(Environment.SpecialFolder.System);
                string[] candidates =
                {
                    Path.Combine(systemRoot, "Npcap", "npcap.sys"),
                    Path.Combine(systemRoot, "drivers", "npcap.sys"),
                    Path.Combine(systemRoot, "drivers", "npf.sys"),
                };
                foreach (var p in candidates)
                    if (File.Exists(p)) return new Result { Installed = true, Reason = $"Found driver at {p}" };

                return new Result { Installed = false, Reason = "Npcap registry key and driver files not found." };
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[NpcapDetector] {ex.Message}");
                return new Result { Installed = false, Reason = $"Detection failed: {ex.Message}" };
            }
        }
    }
}
