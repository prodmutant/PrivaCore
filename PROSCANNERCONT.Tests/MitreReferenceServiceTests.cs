using FluentAssertions;
using PROSCANNERCONT.Services;
using Xunit;

namespace PROSCANNERCONT.Tests;

public class MitreReferenceServiceTests
{
    [Theory]
    [InlineData("DoS",            "T1498",     "Impact")]
    [InlineData("Brute Force",    "T1110",     "Credential Access")]
    [InlineData("Port Scan",      "T1046",     "Discovery")]
    [InlineData("DNS Tunneling",  "T1071.004", "Command and Control")]
    [InlineData("Kerberoast",     "T1558.003", "Credential Access")]
    [InlineData("MITM",           "T1557.002", "Credential Access")]
    public void FromCategory_maps_known_categories(string cat, string expectedId, string expectedTactic)
    {
        var (id, tactic) = MitreReferenceService.FromCategory(cat);
        id.Should().Be(expectedId);
        tactic.Should().Be(expectedTactic);
    }

    [Fact]
    public void FromCategory_unknown_returns_nulls()
    {
        var (id, tactic) = MitreReferenceService.FromCategory("not-a-real-category");
        id.Should().BeNull();
        tactic.Should().BeNull();
    }

    [Fact]
    public void Get_returns_full_info_for_known_technique()
    {
        var t = MitreReferenceService.Get("T1110");
        t.Should().NotBeNull();
        t!.Tactic.Should().Be("Credential Access");
        t.Url.Should().Contain("attack.mitre.org");
    }

    [Fact]
    public void Get_unknown_returns_null()
    {
        MitreReferenceService.Get("T99999").Should().BeNull();
    }

    [Fact]
    public void TacticColour_returns_distinct_colours_per_tactic()
    {
        var creds = MitreReferenceService.TacticColour("Credential Access");
        var impact = MitreReferenceService.TacticColour("Impact");
        creds.Should().NotBe(impact);
    }
}
