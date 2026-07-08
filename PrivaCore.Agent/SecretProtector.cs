using System;
using System.IO;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace PrivaCore.Agent;

/// <summary>
/// Encrypts agent secrets (operator password, pairing code) at rest so agent-config.json
/// never holds them in the clear. Cross-platform, matching the agent's Win/Linux/macOS target:
///  • Windows      → DPAPI (<see cref="ProtectedData"/>, CurrentUser scope) — the blob is tied
///                   to the Windows login, exactly like the console's "remember me" store.
///  • Linux/macOS  → AES-256-GCM with a key kept in a per-user key file (chmod 600). DPAPI does
///                   not exist there; this is the best at-rest protection without an OS keychain,
///                   and still keeps plaintext off disk.
/// Encrypted values are tagged with <see cref="Prefix"/> so a legacy plaintext config is detected
/// and transparently migrated on next save.
/// </summary>
public static class SecretProtector
{
    private const string Prefix = "enc:v1:";

    /// <summary>Encrypt a secret for storage. Empty in → empty out.</summary>
    public static string Protect(string? plaintext)
    {
        if (string.IsNullOrEmpty(plaintext)) return "";
        var data = Encoding.UTF8.GetBytes(plaintext);
        var blob = OperatingSystem.IsWindows() ? ProtectDpapi(data) : ProtectAes(data);
        return Prefix + Convert.ToBase64String(blob);
    }

    /// <summary>
    /// Decrypt a stored secret. A value WITHOUT the <see cref="Prefix"/> tag is treated as legacy
    /// plaintext and returned as-is (one-time migration). A tagged value that fails to decrypt
    /// (e.g. config copied to another user/machine) yields empty, forcing a clean re-setup.
    /// </summary>
    public static string Unprotect(string? stored)
    {
        if (string.IsNullOrEmpty(stored)) return "";
        if (!stored.StartsWith(Prefix, StringComparison.Ordinal)) return stored;   // legacy plaintext
        try
        {
            var blob = Convert.FromBase64String(stored[Prefix.Length..]);
            var data = OperatingSystem.IsWindows() ? UnprotectDpapi(blob) : UnprotectAes(blob);
            return Encoding.UTF8.GetString(data);
        }
        catch { return ""; }
    }

    /// <summary>True if the value is already in encrypted (tagged) form.</summary>
    public static bool IsProtected(string? value)
        => value != null && value.StartsWith(Prefix, StringComparison.Ordinal);

    // ── Windows: DPAPI ──────────────────────────────────────────────────────────
    [SupportedOSPlatform("windows")]
    private static byte[] ProtectDpapi(byte[] data)
        => ProtectedData.Protect(data, null, DataProtectionScope.CurrentUser);

    [SupportedOSPlatform("windows")]
    private static byte[] UnprotectDpapi(byte[] blob)
        => ProtectedData.Unprotect(blob, null, DataProtectionScope.CurrentUser);

    // ── Non-Windows: AES-256-GCM with a per-user key file ───────────────────────
    // blob layout: [12-byte nonce][16-byte tag][ciphertext]
    private const int NonceLen = 12, TagLen = 16;

    private static byte[] ProtectAes(byte[] data)
    {
        var key = LoadOrCreateKey();
        var nonce = RandomNumberGenerator.GetBytes(NonceLen);
        var cipher = new byte[data.Length];
        var tag = new byte[TagLen];
        using (var aes = new AesGcm(key, TagLen))
            aes.Encrypt(nonce, data, cipher, tag);

        var blob = new byte[NonceLen + TagLen + cipher.Length];
        Buffer.BlockCopy(nonce, 0, blob, 0, NonceLen);
        Buffer.BlockCopy(tag, 0, blob, NonceLen, TagLen);
        Buffer.BlockCopy(cipher, 0, blob, NonceLen + TagLen, cipher.Length);
        return blob;
    }

    private static byte[] UnprotectAes(byte[] blob)
    {
        var key = LoadOrCreateKey();
        var nonce = blob.AsSpan(0, NonceLen);
        var tag = blob.AsSpan(NonceLen, TagLen);
        var cipher = blob.AsSpan(NonceLen + TagLen);
        var plain = new byte[cipher.Length];
        using (var aes = new AesGcm(key, TagLen))
            aes.Decrypt(nonce, cipher, tag, plain);
        return plain;
    }

    private static byte[]? _key;

    private static byte[] LoadOrCreateKey()
    {
        if (_key != null) return _key;
        var path = KeyPath();
        try
        {
            if (File.Exists(path))
            {
                var existing = File.ReadAllBytes(path);
                if (existing.Length == 32) return _key = existing;
            }
        }
        catch { /* unreadable — regenerate below (old secrets become un-decryptable, forcing re-setup) */ }

        var key = RandomNumberGenerator.GetBytes(32);
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllBytes(path, key);
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);   // 0600
        }
        catch { /* best effort — key stays in-memory for this run even if it can't be persisted */ }
        return _key = key;
    }

    private static string KeyPath()
        => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                        "PrivaCore", "agent.key");
}
