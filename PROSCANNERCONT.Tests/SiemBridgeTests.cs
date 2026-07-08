using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Threading.Tasks;
using FluentAssertions;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Services.Siem;
using PrivaCore.ModuleSdk;
using Xunit;

namespace PROSCANNERCONT.Tests;

/// <summary>End-to-end: an agent (ModuleClient) ships an event to the SIEM collector
/// (ModuleHost + SiemModuleBridge) and it lands in the shared store — the multi-machine path.</summary>
[Collection("Siem singleton")]
public class SiemBridgeTests
{
    private static int FreePort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        int p = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return p;
    }

    private static ModuleHostConfig NewConfig(int port)
    {
        var path = Path.Combine(Path.GetTempPath(), "pc_" + Guid.NewGuid().ToString("N") + ".json");
        var cfg = ModuleHostConfig.Load(path);
        cfg.Configure(port, "admin", "secret123", "pair-1234");
        return cfg;
    }

    [Fact]
    public async Task Agent_ships_event_to_collector_and_it_lands_in_the_store()
    {
        SiemStore.Instance.Clear();
        SiemStore.Instance.Pipeline = new SiemPipeline();

        int port = FreePort();
        var host = new ModuleHost("SIEM", "COLLECTOR", NewConfig(port));
        SiemModuleBridge.AttachHost(host);
        host.Start();
        try
        {
            using var agent = new ModuleClient();
            (await agent.ConnectAndProbeAsync("127.0.0.1", port, "SIEM")).Running.Should().BeTrue();
            (await agent.LoginAsync("admin", "secret123", "pair-1234")).Success.Should().BeTrue();

            var ev = new SiemEvent
            {
                Severity = SiemSeverity.High, Category = "Authentication",
                EventType = "Failed Logon", Host = "WEB07", Source = "WEB07",
                Message = "Failed logon for jdoe",
            };
            await agent.SendCommandAsync(SiemModuleBridge.CmdIngest,
                new Dictionary<string, object> { ["ev"] = JsonSerializer.Serialize(ev) });

            // give the host loop time to receive + ingest
            SiemEvent? landed = null;
            for (int i = 0; i < 40 && landed == null; i++)
            {
                await Task.Delay(50);
                landed = SiemStore.Instance.Snapshot().Find(e => e.Host == "WEB07");
            }

            landed.Should().NotBeNull();
            landed!.Category.Should().Be("Authentication");
            landed.Severity.Should().Be(SiemSeverity.High);
            SiemStore.Instance.SourceStats(null).Should().Contain(s => s.Host == "WEB07");
        }
        finally { host.Stop(); SiemStore.Instance.Clear(); }
    }
}
