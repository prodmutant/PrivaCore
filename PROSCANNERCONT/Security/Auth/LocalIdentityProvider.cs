using System;
using PrivaCore.ModuleSdk;

namespace PROSCANNERCONT.Security.Auth
{
    /// <summary>
    /// Authenticates against the local <see cref="UserStore"/>: constant-time PBKDF2 verification via
    /// <see cref="ModuleAuth.VerifySecret"/> plus brute-force lockout. Never reveals whether a username
    /// exists (unknown user and wrong password both return <see cref="AuthStatus.InvalidCredentials"/>).
    /// </summary>
    public sealed class LocalIdentityProvider : IIdentityProvider
    {
        public const int MaxFailedAttempts = 5;
        public static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(15);

        private readonly UserStore _store;

        public LocalIdentityProvider(UserStore? store = null) => _store = store ?? UserStore.Instance;

        public AuthResult Authenticate(string username, string password)
        {
            var user = _store.Get(username);
            if (user == null)
                return new AuthResult(AuthStatus.InvalidCredentials, null, "Invalid username or password.");

            if (!user.Enabled)
                return new AuthResult(AuthStatus.Disabled, null, "This account is disabled.");

            if (user.IsLockedOut)
                return new AuthResult(AuthStatus.LockedOut, null,
                    $"Account locked. Try again after {user.LockoutUntilUtc:HH:mm} UTC.");

            if (ModuleAuth.VerifySecret(password, user.Salt, user.StoredKey, user.Iterations))
            {
                user.FailedAttempts = 0;
                user.LockoutUntilUtc = null;
                user.LastLoginUtc = DateTime.UtcNow;
                _store.Update(user);
                return new AuthResult(AuthStatus.Success, user, null);
            }

            // Wrong password — count towards lockout.
            user.FailedAttempts++;
            if (user.FailedAttempts >= MaxFailedAttempts)
            {
                user.LockoutUntilUtc = DateTime.UtcNow.Add(LockoutDuration);
                user.FailedAttempts = 0;
                _store.Update(user);
                return new AuthResult(AuthStatus.LockedOut, null,
                    $"Too many failed attempts. Account locked for {LockoutDuration.TotalMinutes:N0} minutes.");
            }

            _store.Update(user);
            int left = MaxFailedAttempts - user.FailedAttempts;
            return new AuthResult(AuthStatus.InvalidCredentials, null,
                $"Invalid username or password. {left} attempt(s) left before lockout.");
        }
    }
}
