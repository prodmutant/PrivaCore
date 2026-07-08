using System.Text;
using FluentAssertions;
using PROSCANNERCONT.Services;
using Xunit;

namespace PROSCANNERCONT.Tests;

public class YaraLiteScannerTests
{
    [Fact]
    public void Matches_ascii_string()
    {
        var s = new YaraLiteScanner();
        s.LoadFromText("inline", "rule test { strings: $a = \"evilstring\" condition: any of them }");
        var hits = s.Scan(Encoding.UTF8.GetBytes("hello evilstring world"));
        hits.Should().ContainSingle().Which.Name.Should().Be("test");
    }

    [Fact]
    public void Matches_hex_pattern_with_wildcard()
    {
        var s = new YaraLiteScanner();
        s.LoadFromText("inline", "rule hex { strings: $a = { 4D 5A ?? 00 } condition: any of them }");
        var data = new byte[] { 0x00, 0x4D, 0x5A, 0x90, 0x00, 0x01 };
        s.Scan(data).Should().ContainSingle();
    }

    [Fact]
    public void Misses_when_no_pattern_present()
    {
        var s = new YaraLiteScanner();
        s.LoadFromText("inline", "rule miss { strings: $a = \"never\" condition: any of them }");
        s.Scan(Encoding.UTF8.GetBytes("nothing matching here")).Should().BeEmpty();
    }
}
