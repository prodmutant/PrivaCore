using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using PROSCANNERCONT.Utils;

namespace PROSCANNERCONT.Services
{
    /// <summary>
    /// Centralised secret storage. Reads from a DPAPI-encrypted file under
    /// %APPDATA%\PrivaCore\secrets.dat, falls back to optional environment
    /// variables, and finally to a built-in default for non-sensitive defaults
    /// (e.g. the free public NVD demo key) so the app keeps working out of the
    /// box without any secrets configured.
    ///
    /// This replaces the historical pattern of hardcoded API keys baked directly
    /// into source files (e.g. NVDChecker.cs).
    /// </summary>
    public static class SecretsManager
    {
        public const string KeyNvdApiKey       = "NVD_API_KEY";
        public const string KeyOpenAiApiKey    = "OPENAI_API_KEY";
        public const string KeyAnthropicApiKey = "ANTHROPIC_API_KEY";
        public const string KeyShodanApiKey    = "SHODAN_API_KEY";
        public const string KeyCensysApiId     = "CENSYS_API_ID";
        public const string KeyCensysApiSecret = "CENSYS_API_SECRET";
        public const string KeyVirusTotalKey   = "VIRUSTOTAL_API_KEY";
        public const string KeyOtxApiKey       = "OTX_API_KEY";

        // Built-in defaults.  Intentionally EMPTY in the open-source build — no
        // API keys are shipped in source.  Configure keys at runtime through the
        // API Keys page (or the matching environment variables, e.g. NVD_API_KEY).
        // NVD CVE lookups work without a key at a lower rate limit.
        private static readonly System.Collections.Generic.Dictionary<string, string> _builtinDefaults =
            new(StringComparer.OrdinalIgnoreCase)
            {
            };

        private static readonly string _secretsPath = Path.Combine(
            AppConstants.Paths.ConfigDir, "secrets.dat");

        private static readonly ConcurrentDictionary<string, string> _cache = new();
        private static readonly object _diskLock = new();
        private static System.Collections.Generic.Dictionary<string, string>? _diskCache;

        public static string Get(string key)
        {
            if (_cache.TryGetValue(key, out var v)) return v;

            string result =
                ReadDisk(key)
                ?? Environment.GetEnvironmentVariable(key)
                ?? (_builtinDefaults.TryGetValue(key, out var d) ? d : string.Empty);

            _cache[key] = result;
            return result;
        }

        public static void Set(string key, string value)
        {
            _cache[key] = value;
            lock (_diskLock)
            {
                _diskCache ??= LoadDiskBlob() ?? new();
                if (string.IsNullOrEmpty(value)) _diskCache.Remove(key);
                else _diskCache[key] = value;
                SaveDiskBlob(_diskCache);
            }
        }

        public static bool Has(string key) => !string.IsNullOrEmpty(Get(key));

        public static System.Collections.Generic.IReadOnlyDictionary<string, string> ListConfigured()
        {
            lock (_diskLock)
            {
                _diskCache ??= LoadDiskBlob() ?? new();
                return new System.Collections.Generic.Dictionary<string, string>(_diskCache);
            }
        }

        // ── Disk I/O (DPAPI-protected) ──────────────────────────────────────
        private static string? ReadDisk(string key)
        {
            lock (_diskLock)
            {
                _diskCache ??= LoadDiskBlob();
                if (_diskCache != null && _diskCache.TryGetValue(key, out var v)) return v;
                return null;
            }
        }

        private static System.Collections.Generic.Dictionary<string, string>? LoadDiskBlob()
        {
            try
            {
                if (!File.Exists(_secretsPath)) return null;
                var encrypted = File.ReadAllBytes(_secretsPath);
                if (encrypted.Length == 0) return null;
                var decrypted = ProtectedData.Unprotect(encrypted, null, DataProtectionScope.CurrentUser);
                var json = Encoding.UTF8.GetString(decrypted);
                return JsonSerializer.Deserialize<System.Collections.Generic.Dictionary<string, string>>(json)
                    ?? new();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[SecretsManager.LoadDiskBlob] {ex.Message}");
                return null;
            }
        }

        private static void SaveDiskBlob(System.Collections.Generic.Dictionary<string, string> data)
        {
            try
            {
                Directory.CreateDirectory(AppConstants.Paths.ConfigDir);
                var json = JsonSerializer.Serialize(data);
                var encrypted = ProtectedData.Protect(
                    Encoding.UTF8.GetBytes(json), null, DataProtectionScope.CurrentUser);
                File.WriteAllBytes(_secretsPath, encrypted);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[SecretsManager.SaveDiskBlob] {ex.Message}");
            }
        }
    }
}
