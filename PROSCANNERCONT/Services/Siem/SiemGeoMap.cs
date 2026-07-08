using System.Collections.Generic;

namespace PROSCANNERCONT.Services.Siem
{
    /// <summary>
    /// Geo helpers for the threat map: approximate ISO 3166-1 alpha-2 country centroids and an
    /// equirectangular projection (lat/lon → canvas x/y). Pure + dependency-free so the map can be
    /// drawn from country codes (no map tiles / external service) and the projection can be unit-tested.
    /// </summary>
    public static class SiemGeoMap
    {
        /// <summary>Project a lat/lon onto an equirectangular canvas: lon −180..180 → 0..w, lat 90..−90 → 0..h.</summary>
        public static (double x, double y) Project(double lat, double lon, double w, double h)
            => ((lon + 180.0) / 360.0 * w, (90.0 - lat) / 180.0 * h);

        public static bool TryGet(string? iso2, out (double lat, double lon) centroid)
            => Centroids.TryGetValue(iso2 ?? "", out centroid);

        /// <summary>Approximate country centroids (lat, lon) keyed by ISO2 — enough to place a threat bubble.</summary>
        public static readonly IReadOnlyDictionary<string, (double lat, double lon)> Centroids =
            new Dictionary<string, (double lat, double lon)>(System.StringComparer.OrdinalIgnoreCase)
            {
                ["US"] = (39.8, -98.6), ["CA"] = (56.1, -106.3), ["MX"] = (23.6, -102.6), ["BR"] = (-14.2, -51.9),
                ["AR"] = (-38.4, -63.6), ["CL"] = (-35.7, -71.5), ["CO"] = (4.6, -74.3), ["PE"] = (-9.2, -75.0),
                ["VE"] = (6.4, -66.6), ["GB"] = (55.4, -3.4), ["IE"] = (53.4, -8.2), ["FR"] = (46.2, 2.2),
                ["DE"] = (51.2, 10.5), ["NL"] = (52.1, 5.3), ["BE"] = (50.5, 4.5), ["LU"] = (49.8, 6.1),
                ["ES"] = (40.5, -3.7), ["PT"] = (39.4, -8.2), ["IT"] = (41.9, 12.6), ["CH"] = (46.8, 8.2),
                ["AT"] = (47.5, 14.6), ["PL"] = (51.9, 19.1), ["CZ"] = (49.8, 15.5), ["SK"] = (48.7, 19.7),
                ["HU"] = (47.2, 19.5), ["RO"] = (45.9, 24.97), ["BG"] = (42.7, 25.5), ["GR"] = (39.1, 21.8),
                ["TR"] = (38.96, 35.2), ["UA"] = (48.4, 31.2), ["RU"] = (61.5, 105.3), ["BY"] = (53.7, 27.95),
                ["SE"] = (60.1, 18.6), ["NO"] = (60.5, 8.5), ["FI"] = (61.9, 25.7), ["DK"] = (56.3, 9.5),
                ["IS"] = (64.96, -19.0), ["EE"] = (58.6, 25.0), ["LV"] = (56.9, 24.6), ["LT"] = (55.2, 23.9),
                ["CN"] = (35.9, 104.2), ["JP"] = (36.2, 138.3), ["KR"] = (35.9, 127.8), ["KP"] = (40.3, 127.5),
                ["IN"] = (20.6, 79.0), ["PK"] = (30.4, 69.3), ["BD"] = (23.7, 90.4), ["VN"] = (14.06, 108.3),
                ["TH"] = (15.9, 100.99), ["MY"] = (4.2, 101.98), ["SG"] = (1.35, 103.8), ["ID"] = (-0.8, 113.9),
                ["PH"] = (12.9, 121.8), ["TW"] = (23.7, 121.0), ["HK"] = (22.4, 114.1), ["AU"] = (-25.3, 133.8),
                ["NZ"] = (-40.9, 174.9), ["IR"] = (32.4, 53.7), ["IQ"] = (33.2, 43.7), ["SA"] = (23.9, 45.1),
                ["AE"] = (23.4, 53.8), ["IL"] = (31.0, 34.9), ["EG"] = (26.8, 30.8), ["ZA"] = (-30.6, 22.9),
                ["NG"] = (9.1, 8.7), ["KE"] = (-0.02, 37.9), ["MA"] = (31.8, -7.1), ["DZ"] = (28.0, 1.7),
                ["ET"] = (9.1, 40.5), ["GH"] = (7.95, -1.0), ["KZ"] = (48.0, 66.9), ["UZ"] = (41.4, 64.6),
            };
    }
}
