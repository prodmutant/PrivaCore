using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using FluentAssertions;
using PrivaCore.ModuleSdk;
using Xunit;

namespace PROSCANNERCONT.Tests;

public class ModuleSdkTests
{
    private static int FreePort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        int p = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return p;
    }

    private static ModuleHostConfig NewConfig(int port, string user, string pass, string pairing)
    {
        var path = Path.Combine(Path.GetTempPath(), "pc_" + Guid.NewGuid().ToString("N") + ".json");
        var cfg = ModuleHostConfig.Load(path);
        cfg.Configure(port, user, pass, pairing);
        return cfg;
    }

    [Fact]
    public void Pairing_code_verifies_and_rejects()
    {
        var cfg = NewConfig(9001, "admin", "secret123", "pair-9999");
        cfg.CheckPairing("pair-9999").Should().BeTrue();
        cfg.CheckPairing("wrong").Should().BeFalse();
    }

    [Fact]
    public void Login_proof_round_trips_without_sending_password()
    {
        var cred = ModuleCredential.Create("admin", "secret123");
        var salt = cred.Salt;
        var nonce = Convert.ToBase64String(ModuleAuth.NewRandomBytes(32));
        var proof = ModuleAuth.ComputeProof("secret123", salt, cred.Iterations, nonce);
        ModuleAuth.VerifyProof(cred.StoredKey, nonce, proof).Should().BeTrue();
        ModuleAuth.ComputeProof("wrong", salt, cred.Iterations, nonce)
            .Should().NotBe(proof);
    }

    [Fact]
    public async Task Host_and_client_full_flow_with_event_stream()
    {
        int port = FreePort();
        var cfg = NewConfig(port, "admin", "secret123", "pair-9999");
        var host = new ModuleHost("IDS", "TESTHOST", cfg);
        host.Start();
        try
        {
            // wrong pairing is rejected
            using (var bad = new ModuleClient())
            {
                (await bad.ConnectAndProbeAsync("127.0.0.1", port, "IDS")).Running.Should().BeTrue();
                (await bad.LoginAsync("admin", "secret123", "WRONG")).Success.Should().BeFalse();
            }

            // correct pairing + credentials, then a broadcast event is received
            using (var good = new ModuleClient())
            {
                var evt = new TaskCompletionSource<ModuleMessage>();
                good.EventReceived += m => evt.TrySetResult(m);

                var probe = await good.ConnectAndProbeAsync("127.0.0.1", port, "IDS");
                probe.Running.Should().BeTrue();

                var login = await good.LoginAsync("admin", "secret123", "pair-9999");
                login.Success.Should().BeTrue();
                login.Token.Should().NotBeNullOrEmpty();

                await Task.Delay(150);
                host.Broadcast("alert", new Dictionary<string, object> { ["severity"] = "high", ["message"] = "hi" });

                var done = await Task.WhenAny(evt.Task, Task.Delay(2000));
                done.Should().Be(evt.Task);
                evt.Task.Result.EventName.Should().Be("alert");
                evt.Task.Result.Str("severity").Should().Be("high");
            }
        }
        finally { host.Stop(); }
    }
}
