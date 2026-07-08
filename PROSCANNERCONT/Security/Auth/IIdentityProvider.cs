namespace PROSCANNERCONT.Security.Auth
{
    public enum AuthStatus
    {
        Success,
        InvalidCredentials,
        Disabled,
        LockedOut,
    }

    /// <summary>Outcome of an authentication attempt. <see cref="User"/> is set only on success.</summary>
    public sealed record AuthResult(AuthStatus Status, AppUser? User, string? Message)
    {
        public bool Ok => Status == AuthStatus.Success;
    }

    /// <summary>
    /// Pluggable authentication backend. v1 ships <see cref="LocalIdentityProvider"/> (local accounts);
    /// an AD/LDAP or SSO backend is a future drop-in behind this seam — mirroring the
    /// <c>ISiemStore</c> / <c>SiemStoreProvider</c> pattern used elsewhere in the codebase.
    /// </summary>
    public interface IIdentityProvider
    {
        AuthResult Authenticate(string username, string password);
    }
}
