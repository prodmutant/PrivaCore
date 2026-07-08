using System;
using System.Text.Json.Serialization;

namespace PROSCANNERCONT.Security.Auth
{
    /// <summary>
    /// A console user account. The password is NEVER stored — only a PBKDF2-derived key + per-user
    /// salt (produced by <see cref="PrivaCore.ModuleSdk.ModuleAuth"/>), exactly like the module
    /// credential and the agent config. The whole record is additionally DPAPI-encrypted at rest by
    /// <see cref="UserStore"/>.
    /// </summary>
    public sealed class AppUser
    {
        public string Username { get; set; } = "";
        public string DisplayName { get; set; } = "";

        // PBKDF2 verifier (base64) — see ModuleAuth.HashSecret / VerifySecret.
        public string Salt { get; set; } = "";
        public string StoredKey { get; set; } = "";
        public int Iterations { get; set; } = PrivaCore.ModuleSdk.ModuleAuth.DefaultIterations;

        public AppRole Role { get; set; } = AppRole.Viewer;
        public bool Enabled { get; set; } = true;
        public bool MustChangePassword { get; set; }

        public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
        public DateTime? LastLoginUtc { get; set; }

        // Brute-force protection state (managed by LocalIdentityProvider).
        public int FailedAttempts { get; set; }
        public DateTime? LockoutUntilUtc { get; set; }

        /// <summary>True while the account is temporarily locked after too many failed logins.</summary>
        public bool IsLockedOut => LockoutUntilUtc is { } until && until > DateTime.UtcNow;

        /// <summary>Convenience: does this user's role grant the permission?</summary>
        public bool Can(Permission permission) => Enabled && RolePolicy.Grants(Role, permission);

        // ── display helpers (not persisted) ──
        [JsonIgnore] public string RoleText => Role.ToString();
        [JsonIgnore] public string StatusText => !Enabled ? "Disabled" : IsLockedOut ? "Locked" : "Active";
        [JsonIgnore] public string LastLoginText => LastLoginUtc?.ToLocalTime().ToString("MMM dd, HH:mm") ?? "never";
    }
}
