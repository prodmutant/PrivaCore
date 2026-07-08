using System;
using System.Collections.Generic;
using FluentAssertions;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Services;
using Xunit;

namespace PROSCANNERCONT.Tests;

public class ScanDiffServiceTests
{
    private static PortScanResult Port(string ip, int port, bool open, string svc = "", string ver = "")
        => new PortScanResult { IPAddress = ip, Port = port, Protocol = "TCP", IsOpen = open, Service = svc, Version = ver };

    [Fact]
    public void Reports_newly_opened_ports()
    {
        var before = new List<PortScanResult> { Port("10.0.0.1", 22, true, "ssh") };
        var after  = new List<PortScanResult> { Port("10.0.0.1", 22, true, "ssh"),
                                                Port("10.0.0.1", 443, true, "https") };
        var diff = ScanDiffService.Compare(before, after, "10.0.0.1", DateTime.UtcNow.AddDays(-1), DateTime.UtcNow);
        diff.OpenedCount.Should().Be(1);
        diff.ClosedCount.Should().Be(0);
    }

    [Fact]
    public void Reports_closed_ports()
    {
        var before = new List<PortScanResult> { Port("10.0.0.1", 23, true, "telnet") };
        var after  = new List<PortScanResult> { Port("10.0.0.1", 23, false) };
        var diff = ScanDiffService.Compare(before, after, "10.0.0.1", DateTime.UtcNow.AddDays(-1), DateTime.UtcNow);
        diff.ClosedCount.Should().Be(1);
    }

    [Fact]
    public void Reports_service_change_on_same_port()
    {
        var before = new List<PortScanResult> { Port("10.0.0.1", 80, true, "apache") };
        var after  = new List<PortScanResult> { Port("10.0.0.1", 80, true, "nginx") };
        var diff = ScanDiffService.Compare(before, after, "10.0.0.1", DateTime.UtcNow.AddDays(-1), DateTime.UtcNow);
        diff.Ports.Should().ContainSingle(p => p.Change == "ServiceChanged" && p.Before == "apache" && p.After == "nginx");
    }
}
