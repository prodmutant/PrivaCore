extern alias agent;
using System.IO;
using FluentAssertions;
using agent::PrivaCore.Agent;
using Xunit;

namespace PROSCANNERCONT.Tests;

/// <summary>
/// Verifies the agent no longer persists credentials in plaintext: secrets are encrypted at
/// rest (DPAPI on Windows / AES elsewhere) and legacy plaintext configs migrate on save.
/// </summary>
public class AgentSecretTests
{
    [Fact]
    public void Protect_RoundTrips_AndIsNotPlaintext()
    {
        const string secret = "S3cr3t-P@ss-DONOTSTORE";
        var blob = SecretProtector.Protect(secret);

        blob.Should().NotBe(secret);
        SecretProtector.IsProtected(blob).Should().BeTrue();
        SecretProtector.Unprotect(blob).Should().Be(secret);
    }

    [Fact]
    public void Protect_EmptyStaysEmpty()
    {
        SecretProtector.Protect("").Should().Be("");
        SecretProtector.Unprotect("").Should().Be("");
    }

    [Fact]
    public void Unprotect_PassesThroughLegacyPlaintext()
    {
        // A value without the enc tag is treated as legacy plaintext (migration path).
        SecretProtector.Unprotect("legacy-plaintext").Should().Be("legacy-plaintext");
    }

    [Fact]
    public void Save_DoesNotWritePlaintextSecrets_ButReloadRecoversThem()
    {
        const string pw = "S3cr3t-P@ss-DONOTSTORE";
        const string pairing = "PAIR-XYZ9-DONOTSTORE";
        var path = Path.Combine(Path.GetTempPath(), $"agentcfg_{System.Guid.NewGuid():N}.json");
        try
        {
            new AgentConfig { CollectorHost = "10.0.0.5", Password = pw, PairingCode = pairing }.Save(path);

            var raw = File.ReadAllText(path);
            raw.Should().NotContain(pw, "the password must never be written in the clear");
            raw.Should().NotContain(pairing, "the pairing code must never be written in the clear");
            raw.Should().Contain("PasswordEnc");

            var reloaded = AgentConfig.Load(path);
            reloaded.Should().NotBeNull();
            reloaded!.Password.Should().Be(pw);
            reloaded.PairingCode.Should().Be(pairing);
            reloaded.MigratedFromPlaintext.Should().BeFalse();
        }
        finally { if (File.Exists(path)) File.Delete(path); }
    }

    [Fact]
    public void LegacyPlaintextConfig_MigratesOnSave()
    {
        const string pw = "OldPlain-DONOTSTORE";
        var path = Path.Combine(Path.GetTempPath(), $"agentcfg_{System.Guid.NewGuid():N}.json");
        try
        {
            // A pre-encryption config: password/pairing stored under the old plaintext keys.
            File.WriteAllText(path,
                "{\"CollectorHost\":\"10.0.0.5\",\"Username\":\"admin\"," +
                $"\"Password\":\"{pw}\",\"PairingCode\":\"OLD-PAIR\"}}");

            var cfg = AgentConfig.Load(path);
            cfg.Should().NotBeNull();
            cfg!.Password.Should().Be(pw, "legacy plaintext must still be readable");
            cfg.MigratedFromPlaintext.Should().BeTrue();

            // Re-saving migrates: the plaintext is gone, the encrypted form is present.
            cfg.Save(path);
            var raw = File.ReadAllText(path);
            raw.Should().NotContain(pw);
            raw.Should().Contain("enc:v1:");

            AgentConfig.Load(path)!.Password.Should().Be(pw);
        }
        finally { if (File.Exists(path)) File.Delete(path); }
    }
}
