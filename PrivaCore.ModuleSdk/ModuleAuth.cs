using System.Security.Cryptography;
using System.Text.Json;

namespace PrivaCore.ModuleSdk;

/// <summary>
/// Crypto helpers for module auth. Passwords/pairing codes are never stored or
/// transmitted in clear: we store a PBKDF2-derived key + per-secret salt, and
/// login proves knowledge with HMAC(key, server-nonce) (SCRAM-style).
/// </summary>
public static class ModuleAuth
{
    public const int DefaultIterations = 100_000;

    public static byte[] DeriveKey(string secret, byte[] salt, int iterations)
    {
        using var k = new Rfc2898DeriveBytes(secret, salt, iterations, HashAlgorithmName.SHA256);
        return k.GetBytes(32);
    }

    public static byte[] NewRandomBytes(int n) { var b = new byte[n]; RandomNumberGenerator.Fill(b); return b; }
    public static string NewSessionToken() => Convert.ToBase64String(NewRandomBytes(24));

    public static string ComputeProof(string password, string saltB64, int iterations, string nonceB64)
    {
        var key = DeriveKey(password, Convert.FromBase64String(saltB64), iterations);
        using var hmac = new HMACSHA256(key);
        return Convert.ToBase64String(hmac.ComputeHash(Convert.FromBase64String(nonceB64)));
    }

    public static bool VerifyProof(string storedKeyB64, string nonceB64, string proofB64)
    {
        try
        {
            using var hmac = new HMACSHA256(Convert.FromBase64String(storedKeyB64));
            var expected = hmac.ComputeHash(Convert.FromBase64String(nonceB64));
            return CryptographicOperations.FixedTimeEquals(expected, Convert.FromBase64String(proofB64));
        }
        catch { return false; }
    }

    // ── Pairing code (a hashed shared secret) ──
    public static (string salt, string key) HashSecret(string secret)
    {
        var salt = NewRandomBytes(16);
        return (Convert.ToBase64String(salt), Convert.ToBase64String(DeriveKey(secret, salt, DefaultIterations)));
    }

    public static bool VerifySecret(string secret, string saltB64, string keyB64)
        => VerifySecret(secret, saltB64, keyB64, DefaultIterations);

    /// <summary>
    /// Verify against a verifier hashed with a SPECIFIC iteration count. Callers that persist the
    /// iteration count alongside the salt/key (e.g. per-user accounts) must pass it here, so raising
    /// <see cref="DefaultIterations"/> later never invalidates already-stored credentials.
    /// A non-positive <paramref name="iterations"/> falls back to <see cref="DefaultIterations"/>.
    /// </summary>
    public static bool VerifySecret(string secret, string saltB64, string keyB64, int iterations)
    {
        try
        {
            if (iterations <= 0) iterations = DefaultIterations;
            var derived = DeriveKey(secret, Convert.FromBase64String(saltB64), iterations);
            return CryptographicOperations.FixedTimeEquals(derived, Convert.FromBase64String(keyB64));
        }
        catch { return false; }
    }
}

/// <summary>One operator credential (PBKDF2-derived key + salt; never the password).</summary>
public class ModuleCredential
{
    public string Username { get; set; } = "";
    public string Salt { get; set; } = "";
    public int Iterations { get; set; } = ModuleAuth.DefaultIterations;
    public string StoredKey { get; set; } = "";

    public static ModuleCredential Create(string username, string password)
    {
        var salt = ModuleAuth.NewRandomBytes(16);
        return new ModuleCredential
        {
            Username = username,
            Salt = Convert.ToBase64String(salt),
            Iterations = ModuleAuth.DefaultIterations,
            StoredKey = Convert.ToBase64String(ModuleAuth.DeriveKey(password, salt, ModuleAuth.DefaultIterations)),
        };
    }
}

/// <summary>
/// Persisted configuration for a module HOST: listen port, the operator credential,
/// and the deployment pairing code. Lives next to the module exe so each module
/// instance owns its own identity. Nothing here is reversible to a secret.
/// </summary>
public class ModuleHostConfig
{
    public int ListenPort { get; set; } = 9700;
    public ModuleCredential? Credential { get; set; }
    public string PairingSalt { get; set; } = "";
    public string PairingKey { get; set; } = "";

    public bool IsConfigured => Credential != null && PairingKey.Length > 0;

    public bool CheckPairing(string code)
        => PairingKey.Length > 0 && ModuleAuth.VerifySecret(code, PairingSalt, PairingKey);

    private string? _path;

    public static ModuleHostConfig Load(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                var c = JsonSerializer.Deserialize<ModuleHostConfig>(File.ReadAllText(path)) ?? new();
                c._path = path; return c;
            }
        }
        catch { }
        return new ModuleHostConfig { _path = path };
    }

    public void Configure(int port, string username, string password, string pairingCode)
    {
        ListenPort = port;
        Credential = ModuleCredential.Create(username, password);
        (PairingSalt, PairingKey) = ModuleAuth.HashSecret(pairingCode);
        Save();
    }

    /// <summary>Replace just the operator credential (username + password) without touching port/pairing.</summary>
    public void SetCredential(string username, string password)
    {
        Credential = ModuleCredential.Create(username, password);
        Save();
    }

    /// <summary>Replace just the pairing code (e.g. when the old one is forgotten).</summary>
    public void SetPairing(string pairingCode)
    {
        (PairingSalt, PairingKey) = ModuleAuth.HashSecret(pairingCode);
        Save();
    }

    public void Save()
    {
        if (_path == null) return;
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        File.WriteAllText(_path, JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
    }
}
