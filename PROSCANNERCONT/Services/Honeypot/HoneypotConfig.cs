using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Services.Honeypot
{
    /// <summary>One persisted decoy: which service to emulate on which port, and how it presents.</summary>
    public sealed class DecoySpec
    {
        public HoneypotServiceKind Kind { get; set; }
        public int Port { get; set; }
        /// <summary>Custom banner for Telnet/SSH/FTP (null = realistic default).</summary>
        public string? Banner { get; set; }
        /// <summary>Custom HTML the HTTP decoy serves as a website (null/empty = a fake login/401 prompt).</summary>
        public string? HttpHtml { get; set; }
    }

    /// <summary>
    /// Persisted honeypot configuration so decoys survive restarts and the honeypot behaves like a
    /// real always-on sensor (auto-started at launch) instead of something reconfigured every session.
    /// Stored in %APPDATA%\PrivaCore\honeypot.json.
    /// </summary>
    public sealed class HoneypotConfig
    {
        public List<DecoySpec> Decoys { get; set; } = new();
        /// <summary>Forward captured hits into the SIEM (and promote attacker IPs to threat-intel IOCs).</summary>
        public bool FeedSiem { get; set; }

        private static readonly string Path_ = System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PrivaCore", "honeypot.json");

        private static readonly JsonSerializerOptions Pretty = new() { WriteIndented = true };

        public static HoneypotConfig Load()
        {
            try
            {
                if (File.Exists(Path_))
                    return JsonSerializer.Deserialize<HoneypotConfig>(File.ReadAllText(Path_)) ?? new();
            }
            catch { }
            return new HoneypotConfig();
        }

        public void Save()
        {
            try
            {
                Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path_)!);
                File.WriteAllText(Path_, JsonSerializer.Serialize(this, Pretty));
            }
            catch { }
        }
    }
}
