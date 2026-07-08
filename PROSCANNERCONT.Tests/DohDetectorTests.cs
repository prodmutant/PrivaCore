using FluentAssertions;
using PROSCANNERCONT.Services;
using Xunit;

namespace PROSCANNERCONT.Tests;

public class DohDetectorTests
{
    [Theory]
    [InlineData("1.1.1.1",  443, "Cloudflare", "DoH")]
    [InlineData("1.1.1.1",  853, "Cloudflare", "DoT")]
    [InlineData("8.8.8.8",  443, "Google",     "DoH")]
    [InlineData("9.9.9.9",  443, "Quad9",      "DoH")]
    public void Detects_known_providers(string ip, int port, string expectedProvider, string expectedProto)
    {
        var hit = DohDetector.Detect(ip, port);
        hit.Should().NotBeNull();
        hit!.Provider.Should().Be(expectedProvider);
        hit.Protocol.Should().Be(expectedProto);
    }

    [Fact]
    public void Returns_null_for_unrelated_ips()
    {
        DohDetector.Detect("203.0.113.5", 443).Should().BeNull();
    }

    [Fact]
    public void Returns_null_for_non_doh_port_on_known_ip()
    {
        DohDetector.Detect("1.1.1.1", 80).Should().BeNull();
    }
}
