using FluentAssertions;
using PROSCANNERCONT.Services.Siem;
using Xunit;

namespace PROSCANNERCONT.Tests;

/// <summary>The threat-map geo helpers: equirectangular projection + country centroid lookup.</summary>
public class SiemGeoMapTests
{
    [Fact]
    public void Projects_lat_lon_onto_the_canvas()
    {
        // centre of the world maps to the centre of the canvas
        SiemGeoMap.Project(0, 0, 360, 180).Should().Be((180.0, 90.0));
        // top-left corner: lon −180, lat +90
        SiemGeoMap.Project(90, -180, 360, 180).Should().Be((0.0, 0.0));
        // bottom-right corner: lon +180, lat −90
        SiemGeoMap.Project(-90, 180, 360, 180).Should().Be((360.0, 180.0));
    }

    [Fact]
    public void Longitude_and_latitude_move_the_point_the_right_way()
    {
        var (xWest, _) = SiemGeoMap.Project(0, -90, 360, 180);
        var (xEast, _) = SiemGeoMap.Project(0, 90, 360, 180);
        xEast.Should().BeGreaterThan(xWest);               // east is further right

        var (_, yNorth) = SiemGeoMap.Project(45, 0, 360, 180);
        var (_, ySouth) = SiemGeoMap.Project(-45, 0, 360, 180);
        ySouth.Should().BeGreaterThan(yNorth);             // south is further down
    }

    [Fact]
    public void Known_country_codes_resolve_to_plausible_centroids()
    {
        SiemGeoMap.TryGet("US", out var us).Should().BeTrue();
        us.lon.Should().BeLessThan(0);                     // western hemisphere
        SiemGeoMap.TryGet("ru", out var ru).Should().BeTrue();   // case-insensitive
        ru.lon.Should().BeGreaterThan(0);                  // eastern hemisphere
        SiemGeoMap.TryGet("ZZ", out _).Should().BeFalse(); // unknown code
    }
}
