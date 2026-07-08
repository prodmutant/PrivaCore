using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace PROSCANNERCONT.Services
{
    public class RememberedConnection
    {
        public string Host { get; set; } = "127.0.0.1";
        public int Port { get; set; }
        public string Username { get; set; } = "";
        public string Password { get; set; } = "";
        public string Pairing { get; set; } = "";
        public DateTime ExpiryUtc { get; set; }
    }

    /// <summary>
    /// Optional "remember me" store for module logins. Encrypted at rest with Windows
    /// DPAPI (current user only) and auto-expiring, so the console can reconnect to a
    /// module without re-entering credentials until the entry lapses.
    /// </summary>
    public static class RememberedConnections
    {
        private static readonly string FilePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PrivaCore", "remembered.dat");

        private static Dictionary<string, RememberedConnection>? _cache;

        public static void Save(string key, string host, int port, string user, string pass, string pairing, int days)
        {
            Load();
            _cache![key] = new RememberedConnection
            {
                Host = host, Port = port, Username = user, Password = pass, Pairing = pairing,
                ExpiryUtc = DateTime.UtcNow.AddDays(days),
            };
            Persist();
        }

        public static RememberedConnection? TryGet(string key)
        {
            Load();
            if (_cache!.TryGetValue(key, out var e))
            {
                if (e.ExpiryUtc > DateTime.UtcNow) return e;
                _cache.Remove(key); Persist();   // lapsed
            }
            return null;
        }

        public static void Remove(string key)
        {
            Load();
            if (_cache!.Remove(key)) Persist();
        }

        private static void Load()
        {
            if (_cache != null) return;
            _cache = new(StringComparer.OrdinalIgnoreCase);
            try
            {
                if (File.Exists(FilePath))
                {
                    var enc = Convert.FromBase64String(File.ReadAllText(FilePath));
                    var json = Encoding.UTF8.GetString(ProtectedData.Unprotect(enc, null, DataProtectionScope.CurrentUser));
                    _cache = JsonSerializer.Deserialize<Dictionary<string, RememberedConnection>>(json)
                             ?? new(StringComparer.OrdinalIgnoreCase);
                }
            }
            catch { _cache = new(StringComparer.OrdinalIgnoreCase); }
        }

        private static void Persist()
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
                var json = JsonSerializer.Serialize(_cache);
                var enc = ProtectedData.Protect(Encoding.UTF8.GetBytes(json), null, DataProtectionScope.CurrentUser);
                File.WriteAllText(FilePath, Convert.ToBase64String(enc));
            }
            catch { }
        }
    }
}
