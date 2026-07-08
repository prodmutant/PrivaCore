using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using PROSCANNERCONT.Utils;

namespace PROSCANNERCONT.Services
{
    public sealed class VaultEntry
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string Name { get; set; } = "";
        /// <summary>Type tag: ssh, http, smb, ldap, web, api, other.</summary>
        public string Type { get; set; } = "ssh";
        public string Host { get; set; } = "";
        public int Port { get; set; }
        public string Username { get; set; } = "";
        /// <summary>Either a plaintext password or PEM private key contents.</summary>
        public string Secret { get; set; } = "";
        public string Notes { get; set; } = "";
        public DateTime Created { get; set; } = DateTime.UtcNow;
        public DateTime LastUsed { get; set; }
    }

    /// <summary>
    /// DPAPI-encrypted credential vault, file at
    /// %APPDATA%\PrivaCore\Config\vault.dat.
    ///
    /// Scope: any module that needs to authenticate against a target — SSH
    /// (now shared with the SSH manager), HTTP basic auth (web scanner),
    /// AD/LDAP (recon module), SMB. Backups intentionally exclude this file
    /// by default; opt-in with --include-vault on the backup CLI.
    /// </summary>
    public sealed class CredentialVault
    {
        private static readonly Lazy<CredentialVault> _instance = new(() => new CredentialVault());
        public static CredentialVault Instance => _instance.Value;

        private readonly string _path = Path.Combine(AppConstants.Paths.ConfigDir, "vault.dat");
        private readonly object _lock = new();
        private List<VaultEntry> _entries = new();

        private CredentialVault() => Load();

        public IReadOnlyList<VaultEntry> Entries
        {
            get { lock (_lock) return _entries.ToList(); }
        }

        public VaultEntry Add(VaultEntry e)
        {
            lock (_lock) { _entries.Add(e); Save(); }
            return e;
        }

        public void Update(VaultEntry e)
        {
            lock (_lock)
            {
                var i = _entries.FindIndex(x => x.Id == e.Id);
                if (i >= 0) _entries[i] = e;
                Save();
            }
        }

        public void Remove(Guid id)
        {
            lock (_lock) { _entries.RemoveAll(e => e.Id == id); Save(); }
        }

        public VaultEntry? GetByName(string name)
        {
            lock (_lock) return _entries.FirstOrDefault(e =>
                string.Equals(e.Name, name, StringComparison.OrdinalIgnoreCase));
        }

        public IEnumerable<VaultEntry> ByType(string type)
        {
            lock (_lock) return _entries
                .Where(e => string.Equals(e.Type, type, StringComparison.OrdinalIgnoreCase))
                .ToList();
        }

        // ── Persistence (DPAPI CurrentUser scope) ──────────────────────────
        private void Save()
        {
            try
            {
                Directory.CreateDirectory(AppConstants.Paths.ConfigDir);
                var json = JsonSerializer.Serialize(_entries);
                var enc  = ProtectedData.Protect(Encoding.UTF8.GetBytes(json), null, DataProtectionScope.CurrentUser);
                File.WriteAllBytes(_path, enc);
            }
            catch (Exception ex) { AppLogger.Log.Warning(ex, "[Vault] save failed"); }
        }

        private void Load()
        {
            try
            {
                if (!File.Exists(_path)) return;
                var enc = File.ReadAllBytes(_path);
                if (enc.Length == 0) return;
                var json = Encoding.UTF8.GetString(
                    ProtectedData.Unprotect(enc, null, DataProtectionScope.CurrentUser));
                _entries = JsonSerializer.Deserialize<List<VaultEntry>>(json) ?? new();
            }
            catch (Exception ex)
            {
                AppLogger.Log.Warning(ex, "[Vault] load failed — vault file may be corrupt or from another Windows user");
                _entries = new();
            }
        }
    }
}
