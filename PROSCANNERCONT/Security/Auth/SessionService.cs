using System;
using PROSCANNERCONT.Services;
using PROSCANNERCONT.Services.Siem;
using PROSCANNERCONT.Utils;

namespace PROSCANNERCONT.Security.Auth
{
    /// <summary>
    /// Holds the authenticated console session and answers permission checks. Singleton (matching the
    /// codebase's <c>.Instance</c> convention) and also registered in the DI container. Every RBAC
    /// enforcement site calls <see cref="Can"/>; nothing checks a role directly.
    /// </summary>
    public sealed class SessionService
    {
        public static SessionService Instance { get; } = new();

        public AppUser? Current { get; private set; }
        public bool IsAuthenticated => Current != null;

        /// <summary>The acting user for audit / display; falls back to the OS user before sign-in.</summary>
        public string CurrentUserName => Current?.Username ?? Environment.UserName;

        /// <summary>Last username to sign in — used to pre-fill the login box on lock/logout.</summary>
        public string? LastUsername { get; private set; }

        /// <summary>Raised whenever the signed-in user changes (sign in / out) so the UI can re-gate.</summary>
        public event Action? AuthChanged;

        private SessionService()
        {
            // Make every audit entry attribute to the signed-in console user.
            SiemAudit.CurrentUser = () => CurrentUserName;
        }

        public void SignIn(AppUser user)
        {
            Current = user;
            LastUsername = user.Username;
            SafeAudit("Sign in", $"{user.Username} ({user.Role})");
            try { AppLogger.Log.Information("Console sign-in: {User} ({Role})", user.Username, user.Role); } catch { }
            AuthChanged?.Invoke();
        }

        public void SignOut()
        {
            var who = Current?.Username;
            if (who != null) SafeAudit("Sign out", who);
            Current = null;
            AuthChanged?.Invoke();
        }

        /// <summary>True if the signed-in user's role grants the permission. False when not signed in.</summary>
        public bool Can(Permission permission) => Current != null && Current.Can(permission);

        /// <summary>Convenience for enforcement sites — audits and (optionally) toasts a denial.</summary>
        public bool Require(Permission permission, string action, bool toast = true)
        {
            if (Can(permission)) return true;
            SafeAudit("Denied", $"{action} (needs {permission})");
            if (toast) { try { AlertToast.Show("Not permitted", $"Your role can't {action}.", "#FF7B72"); } catch { } }
            return false;
        }

        private static void SafeAudit(string action, string detail)
        {
            try { SiemAudit.Instance.Log("Auth", action, detail); } catch { }
        }
    }
}
