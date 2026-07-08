using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using PrivaCore.ModuleSdk;

namespace PROSCANNERCONT.Security.Auth
{
    /// <summary>
    /// Persists console user accounts, DPAPI-encrypted at rest (CurrentUser scope) in
    /// <c>%APPDATA%\PrivaCore\users.dat</c> — the same at-rest protection the console already uses
    /// for "remember me" (<see cref="Services.RememberedConnections"/>). Passwords are stored only as
    /// PBKDF2 verifiers via <see cref="ModuleAuth"/>; the DPAPI layer protects the whole record.
    ///
    /// The store is deliberately path-injectable (default = the %APPDATA% file) so it is unit-testable.
    /// </summary>
    public sealed class UserStore
    {
        public static UserStore Instance { get; } = new();

        private static string DefaultPath => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PrivaCore", "users.dat");

        private readonly string _path;
        private readonly object _lock = new();
        private Dictionary<string, AppUser>? _users;   // keyed by lower-cased username

        public UserStore() : this(DefaultPath) { }
        public UserStore(string path) { _path = path; }

        /// <summary>True when no account exists yet — the console must run first-run admin setup.</summary>
        public bool IsEmpty { get { Load(); lock (_lock) return _users!.Count == 0; } }

        public List<AppUser> All() { Load(); lock (_lock) return _users!.Values.OrderBy(u => u.Username).ToList(); }

        public AppUser? Get(string username)
        {
            if (string.IsNullOrWhiteSpace(username)) return null;
            Load();
            lock (_lock) return _users!.TryGetValue(username.Trim().ToLowerInvariant(), out var u) ? u : null;
        }

        /// <summary>Create a new account (password hashed with PBKDF2). Returns null if the name is taken.</summary>
        public AppUser? Create(string username, string password, AppRole role,
                               string? displayName = null, bool mustChangePassword = false)
        {
            username = (username ?? "").Trim();
            if (username.Length == 0) return null;
            Load();
            lock (_lock)
            {
                var key = username.ToLowerInvariant();
                if (_users!.ContainsKey(key)) return null;
                var (salt, stored) = ModuleAuth.HashSecret(password);
                var user = new AppUser
                {
                    Username = username,
                    DisplayName = string.IsNullOrWhiteSpace(displayName) ? username : displayName!.Trim(),
                    Salt = salt,
                    StoredKey = stored,
                    Iterations = ModuleAuth.DefaultIterations,
                    Role = role,
                    MustChangePassword = mustChangePassword,
                };
                _users[key] = user;
                Persist();
                return user;
            }
        }

        /// <summary>Replace a user's password (clears the must-change flag and any lockout).</summary>
        public bool SetPassword(string username, string newPassword)
        {
            var u = Get(username);
            if (u == null) return false;
            lock (_lock)
            {
                var (salt, stored) = ModuleAuth.HashSecret(newPassword);
                u.Salt = salt; u.StoredKey = stored; u.Iterations = ModuleAuth.DefaultIterations;
                u.MustChangePassword = false;
                u.FailedAttempts = 0; u.LockoutUntilUtc = null;
                Persist();
            }
            return true;
        }

        /// <summary>Persist mutations made to a user obtained from this store (role/enabled/lockout/etc.).</summary>
        public void Update(AppUser user)
        {
            if (user == null) return;
            Load();
            lock (_lock) { _users![user.Username.ToLowerInvariant()] = user; Persist(); }
        }

        public bool Remove(string username)
        {
            if (string.IsNullOrWhiteSpace(username)) return false;
            Load();
            lock (_lock)
            {
                var removed = _users!.Remove(username.Trim().ToLowerInvariant());
                if (removed) Persist();
                return removed;
            }
        }

        // ── persistence (DPAPI on Windows; see also Services/RememberedConnections.cs) ──
        private void Load()
        {
            if (_users != null) return;
            lock (_lock)
            {
                if (_users != null) return;
                var map = new Dictionary<string, AppUser>(StringComparer.OrdinalIgnoreCase);
                try
                {
                    if (File.Exists(_path))
                    {
                        var enc = Convert.FromBase64String(File.ReadAllText(_path));
                        var json = Encoding.UTF8.GetString(ProtectedData.Unprotect(enc, null, DataProtectionScope.CurrentUser));
                        var list = JsonSerializer.Deserialize<List<AppUser>>(json) ?? new();
                        foreach (var u in list)
                            if (!string.IsNullOrWhiteSpace(u.Username)) map[u.Username.ToLowerInvariant()] = u;
                    }
                }
                catch { /* unreadable / other user → treat as empty (first-run) */ }
                _users = map;
            }
        }

        private void Persist()
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
                var json = JsonSerializer.Serialize(_users!.Values.ToList());
                var enc = ProtectedData.Protect(Encoding.UTF8.GetBytes(json), null, DataProtectionScope.CurrentUser);
                File.WriteAllText(_path, Convert.ToBase64String(enc));
            }
            catch { /* best effort — mirrors RememberedConnections */ }
        }
    }
}
