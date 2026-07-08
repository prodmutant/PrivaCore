using System.Text.Json;
using System.Text.Json.Serialization;

namespace PrivaCore.Agent;

/// <summary>
/// Persisted agent configuration: where the SIEM collector is, how to authenticate, and
/// which local logs to ship. Saved as agent-config.json next to the executable so the same
/// agent can be redeployed unattended.
/// </summary>
public sealed class AgentConfig
{
    public string CollectorHost { get; set; } = "127.0.0.1";
    public int CollectorPort { get; set; } = 9720;
    public string Username { get; set; } = "admin";

    /// <summary>Operator password. Plaintext in memory, but NEVER written to disk in the clear —
    /// persisted encrypted in <see cref="PasswordEnc"/> (DPAPI on Windows / AES elsewhere).</summary>
    [JsonIgnore] public string Password { get; set; } = "";

    /// <summary>Deployment pairing secret. Same at-rest protection as <see cref="Password"/>.</summary>
    [JsonIgnore] public string PairingCode { get; set; } = "";

    /// <summary>Encrypted-at-rest form of the password actually stored in agent-config.json.</summary>
    public string PasswordEnc { get; set; } = "";
    /// <summary>Encrypted-at-rest form of the pairing code actually stored in agent-config.json.</summary>
    public string PairingEnc { get; set; } = "";

    // Legacy plaintext keys from pre-encryption configs — read only, for one-time migration.
    [JsonPropertyName("Password")] public string? LegacyPassword { get; set; }
    [JsonPropertyName("PairingCode")] public string? LegacyPairing { get; set; }

    /// <summary>True when this config was loaded from a legacy plaintext file (caller should re-save to migrate).</summary>
    [JsonIgnore] public bool MigratedFromPlaintext { get; private set; }

    /// <summary>The machine name reported to the SIEM (defaults to the OS hostname).</summary>
    public string MachineName { get; set; } = Environment.MachineName;

    /// <summary>Log files to tail and forward (any OS — e.g. /var/log/auth.log, app logs).</summary>
    public List<string> TailFiles { get; set; } = new();

    /// <summary>Send a periodic heartbeat event so the collector always shows the agent as live.</summary>
    public bool Heartbeat { get; set; } = true;
    public int HeartbeatSeconds { get; set; } = 30;

    /// <summary>Emit synthetic demo events (for testing the pipeline without real logs).</summary>
    public bool DemoGenerator { get; set; }

    private static readonly JsonSerializerOptions Pretty = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,   // omit the null legacy keys
    };

    public static string DefaultPath =>
        Path.Combine(AppContext.BaseDirectory, "agent-config.json");

    public static AgentConfig? Load(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                var cfg = JsonSerializer.Deserialize<AgentConfig>(File.ReadAllText(path));
                cfg?.DecryptSecrets();
                return cfg;
            }
        }
        catch { }
        return null;
    }

    public void Save(string path)
    {
        // Encrypt secrets before they touch the disk; drop any legacy plaintext keys.
        PasswordEnc = SecretProtector.Protect(Password);
        PairingEnc = SecretProtector.Protect(PairingCode);
        LegacyPassword = null; LegacyPairing = null;
        try { File.WriteAllText(path, JsonSerializer.Serialize(this, Pretty)); }
        catch (Exception ex) { Console.WriteLine($"  ! could not save config: {ex.Message}"); }
    }

    /// <summary>Populate the in-memory plaintext secrets from the encrypted (or legacy plaintext) fields.</summary>
    private void DecryptSecrets()
    {
        bool usedLegacy = false;

        if (!string.IsNullOrEmpty(PasswordEnc)) Password = SecretProtector.Unprotect(PasswordEnc);
        else if (!string.IsNullOrEmpty(LegacyPassword)) { Password = LegacyPassword!; usedLegacy = true; }

        if (!string.IsNullOrEmpty(PairingEnc)) PairingCode = SecretProtector.Unprotect(PairingEnc);
        else if (!string.IsNullOrEmpty(LegacyPairing)) { PairingCode = LegacyPairing!; usedLegacy = true; }

        LegacyPassword = null; LegacyPairing = null;
        MigratedFromPlaintext = usedLegacy;
    }
}
