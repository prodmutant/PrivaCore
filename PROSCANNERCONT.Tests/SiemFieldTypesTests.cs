using FluentAssertions;
using PROSCANNERCONT.Services.Siem;
using Xunit;

namespace PROSCANNERCONT.Tests;

/// <summary>Discover field-type inference (ES-style mapping) from name + sample values.</summary>
public class SiemFieldTypesTests
{
    [Theory]
    [InlineData("@timestamp", SiemFieldType.Date)]
    [InlineData("event.created", SiemFieldType.Date)]
    [InlineData("source.ip", SiemFieldType.Ip)]
    [InlineData("destination.port", SiemFieldType.Number)]
    [InlineData("network.bytes", SiemFieldType.Number)]
    [InlineData("source.geo.location", SiemFieldType.Geo)]
    [InlineData("threat.matched", SiemFieldType.Boolean)]
    [InlineData("host.name", SiemFieldType.Keyword)]
    public void Name_based_inference(string field, SiemFieldType expected)
        => SiemFieldTypes.FromName(field).Should().Be(expected);

    [Fact]
    public void Sample_values_refine_keyword_fields()
    {
        SiemFieldTypes.Infer("custom.value", new[] { "10", "42", "7" }).Should().Be(SiemFieldType.Number);
        SiemFieldTypes.Infer("custom.flag", new[] { "true", "false" }).Should().Be(SiemFieldType.Boolean);
        SiemFieldTypes.Infer("custom.addr", new[] { "10.0.0.1", "8.8.8.8" }).Should().Be(SiemFieldType.Ip);
        SiemFieldTypes.Infer("custom.msg", new[] { "this is a long human readable sentence about an event" }).Should().Be(SiemFieldType.Text);
        SiemFieldTypes.Infer("custom.tag", new[] { "prod", "stage" }).Should().Be(SiemFieldType.Keyword);
    }

    [Fact]
    public void Every_type_has_an_icon_and_label()
    {
        foreach (SiemFieldType t in System.Enum.GetValues(typeof(SiemFieldType)))
        {
            SiemFieldTypes.IconName(t).Should().NotBeNullOrEmpty();
            SiemFieldTypes.Label(t).Should().NotBeNullOrEmpty();
        }
    }
}
