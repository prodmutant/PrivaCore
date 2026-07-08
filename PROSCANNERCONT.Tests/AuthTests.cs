using System.IO;
using System.Linq;
using FluentAssertions;
using PrivaCore.ModuleSdk;
using PROSCANNERCONT.Security.Auth;
using Xunit;

namespace PROSCANNERCONT.Tests;

/// <summary>
/// Covers the console auth/RBAC layer: role→permission policy, the DPAPI-encrypted user store,
/// and the local identity provider (verification + lockout).
/// </summary>
public class AuthTests
{
    // ── role → permission policy ──────────────────────────────────────────────
    [Fact]
    public void Admin_Has_Every_Permission()
    {
        foreach (Permission p in System.Enum.GetValues(typeof(Permission)))
            RolePolicy.Grants(AppRole.Admin, p).Should().BeTrue($"admin should have {p}");
    }

    [Fact]
    public void Viewer_Is_ReadOnly()
    {
        RolePolicy.Grants(AppRole.Viewer, Permission.ViewDashboards).Should().BeTrue();
        RolePolicy.Grants(AppRole.Viewer, Permission.Search).Should().BeTrue();
        RolePolicy.Grants(AppRole.Viewer, Permission.RunScans).Should().BeFalse();
        RolePolicy.Grants(AppRole.Viewer, Permission.DeleteEvents).Should().BeFalse();
        RolePolicy.Grants(AppRole.Viewer, Permission.ManageUsers).Should().BeFalse();
    }

    [Fact]
    public void Analyst_And_Senior_Escalate_As_Expected()
    {
        // L1 can triage + scan but not destroy or manage.
        RolePolicy.Grants(AppRole.Analyst, Permission.RunScans).Should().BeTrue();
        RolePolicy.Grants(AppRole.Analyst, Permission.DeleteEvents).Should().BeFalse();

        // L2 adds destructive/data ops but still not user management.
        RolePolicy.Grants(AppRole.SeniorAnalyst, Permission.DeleteEvents).Should().BeTrue();
        RolePolicy.Grants(AppRole.SeniorAnalyst, Permission.AddRemoveModules).Should().BeTrue();
        RolePolicy.Grants(AppRole.SeniorAnalyst, Permission.ManageUsers).Should().BeFalse();
    }

    [Fact]
    public void Disabled_User_Can_Nothing()
    {
        var u = new AppUser { Role = AppRole.Admin, Enabled = false };
        u.Can(Permission.ViewDashboards).Should().BeFalse();
    }

    // ── user store (DPAPI at rest) ────────────────────────────────────────────
    [Fact]
    public void UserStore_Persists_Encrypted_And_Reloads()
    {
        const string pw = "S3cret-Console-PW";
        var path = TempPath();
        try
        {
            var store = new UserStore(path);
            store.IsEmpty.Should().BeTrue("a fresh store triggers first-run");
            store.Create("alice", pw, AppRole.SeniorAnalyst, "Alice A.").Should().NotBeNull();

            // No plaintext password on disk (whole record is DPAPI-encrypted).
            File.ReadAllText(path).Should().NotContain(pw);

            // A fresh instance (no cache) reloads the account.
            var reloaded = new UserStore(path);
            reloaded.IsEmpty.Should().BeFalse();
            var alice = reloaded.Get("ALICE");   // case-insensitive
            alice.Should().NotBeNull();
            alice!.Role.Should().Be(AppRole.SeniorAnalyst);
            alice.Salt.Should().NotBeEmpty();
        }
        finally { Cleanup(path); }
    }

    [Fact]
    public void UserStore_Rejects_Duplicate_Username()
    {
        var path = TempPath();
        try
        {
            var store = new UserStore(path);
            store.Create("bob", "password-one", AppRole.Analyst).Should().NotBeNull();
            store.Create("bob", "password-two", AppRole.Admin).Should().BeNull();
        }
        finally { Cleanup(path); }
    }

    // ── local identity provider (verify + lockout) ────────────────────────────
    [Fact]
    public void Login_Accepts_Correct_And_Rejects_Wrong()
    {
        var path = TempPath();
        try
        {
            var store = new UserStore(path);
            store.Create("carol", "correct-horse", AppRole.Analyst);
            var idp = new LocalIdentityProvider(store);

            idp.Authenticate("carol", "correct-horse").Status.Should().Be(AuthStatus.Success);
            idp.Authenticate("nobody", "whatever").Status.Should().Be(AuthStatus.InvalidCredentials);
        }
        finally { Cleanup(path); }
    }

    [Fact]
    public void Login_Locks_Out_After_Repeated_Failures()
    {
        var path = TempPath();
        try
        {
            var store = new UserStore(path);
            store.Create("dave", "right-pass", AppRole.Analyst);
            var idp = new LocalIdentityProvider(store);

            for (int i = 1; i < LocalIdentityProvider.MaxFailedAttempts; i++)
                idp.Authenticate("dave", "wrong").Status.Should().Be(AuthStatus.InvalidCredentials);

            // The attempt that hits the threshold locks the account…
            idp.Authenticate("dave", "wrong").Status.Should().Be(AuthStatus.LockedOut);
            // …and even the correct password is now refused while locked.
            idp.Authenticate("dave", "right-pass").Status.Should().Be(AuthStatus.LockedOut);
        }
        finally { Cleanup(path); }
    }

    [Fact]
    public void Login_Rejects_Disabled_Account()
    {
        var path = TempPath();
        try
        {
            var store = new UserStore(path);
            var u = store.Create("erin", "pass-erin", AppRole.Viewer)!;
            u.Enabled = false; store.Update(u);

            new LocalIdentityProvider(store).Authenticate("erin", "pass-erin")
                .Status.Should().Be(AuthStatus.Disabled);
        }
        finally { Cleanup(path); }
    }

    // ── stored per-record iteration count is honored on verify (forward-compat) ──
    [Fact]
    public void VerifySecret_Honors_Stored_Iteration_Count()
    {
        var salt = ModuleAuth.NewRandomBytes(16);
        var saltB64 = System.Convert.ToBase64String(salt);
        const string secret = "correct-horse";

        // A verifier hashed at a NON-default iteration count (e.g. a future hardened default).
        const int iters = 12_345;
        var keyB64 = System.Convert.ToBase64String(ModuleAuth.DeriveKey(secret, salt, iters));

        // Verifying with the matching stored count succeeds…
        ModuleAuth.VerifySecret(secret, saltB64, keyB64, iters).Should().BeTrue();

        // …but the old behavior (always DefaultIterations) would have wrongly rejected it —
        // this is exactly the lockout trap the fix removes.
        ModuleAuth.VerifySecret(secret, saltB64, keyB64).Should().BeFalse();

        // A non-positive count falls back to DefaultIterations.
        var keyDefault = System.Convert.ToBase64String(
            ModuleAuth.DeriveKey(secret, salt, ModuleAuth.DefaultIterations));
        ModuleAuth.VerifySecret(secret, saltB64, keyDefault, 0).Should().BeTrue();
    }

    [Fact]
    public void Login_Verifies_Against_Account_Stored_Iteration_Count()
    {
        var path = TempPath();
        try
        {
            var store = new UserStore(path);

            // Hand-build an account whose verifier was derived at a non-default iteration count
            // (simulating one created under a different DefaultIterations than the current build).
            var salt = ModuleAuth.NewRandomBytes(16);
            const string pw = "future-proof-pw";
            const int iters = 7_777;
            store.Update(new AppUser
            {
                Username = "frank",
                Salt = System.Convert.ToBase64String(salt),
                StoredKey = System.Convert.ToBase64String(ModuleAuth.DeriveKey(pw, salt, iters)),
                Iterations = iters,
                Role = AppRole.Analyst,
                Enabled = true,
            });

            var idp = new LocalIdentityProvider(store);
            idp.Authenticate("frank", pw).Status.Should().Be(AuthStatus.Success);
            idp.Authenticate("frank", "wrong").Status.Should().Be(AuthStatus.InvalidCredentials);
        }
        finally { Cleanup(path); }
    }

    private static string TempPath() => Path.Combine(Path.GetTempPath(), $"pcusers_{System.Guid.NewGuid():N}.dat");
    private static void Cleanup(string path) { if (File.Exists(path)) File.Delete(path); }
}
