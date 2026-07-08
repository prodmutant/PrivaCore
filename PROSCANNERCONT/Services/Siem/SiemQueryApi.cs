using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Text.Json;
using PROSCANNERCONT.Services.Siem.Elastic;

namespace PROSCANNERCONT.Services.Siem
{
    /// <summary>
    /// The external query API (Elasticsearch <c>_search</c>-style): turns a query string into a JSON
    /// result set over the active <see cref="ISiemStore"/>. Pure + static so it's unit-testable
    /// independent of the HTTP listener that hosts it.
    ///
    /// GET /api/search?q=&lt;KQL&gt;&amp;size=&lt;n&gt;&amp;minutes=&lt;m&gt;
    ///   q       — the KQL-ish query (blank = match all)
    ///   size    — max hits to return (default 100, capped at <see cref="MaxSize"/>)
    ///   minutes — rolling time window in minutes (omit / 0 = no time bound)
    /// Each hit is emitted as an ECS <c>_source</c> document (same shape as the Elasticsearch path).
    /// </summary>
    public static class SiemQueryApi
    {
        public const int DefaultSize = 100;
        public const int MaxSize = 1000;

        /// <summary>Build the JSON response for explicit parameters (the testable core).</summary>
        public static string BuildResponse(ISiemStore store, string? q, int? size, int? minutes)
        {
            var query = SiemQuery.Parse(q);
            int limit = size is int s && s > 0 ? (s > MaxSize ? MaxSize : s) : DefaultSize;
            SiemRange? range = minutes is int m && m > 0 ? SiemRange.Rolling(System.TimeSpan.FromMinutes(m)) : null;

            var hits = store.Query(query, range, limit);
            int total = store.CountMatching(query, range);

            var body = new Dictionary<string, object?>
            {
                ["query"] = query.Raw,
                ["total"] = total,
                ["count"] = hits.Count,
                ["hits"] = hits.Select(SiemEsDocument.ToSource).ToList(),
            };
            return JsonSerializer.Serialize(body);
        }

        /// <summary>Convenience overload that reads q/size/minutes from a parsed query string.</summary>
        public static string BuildResponse(ISiemStore store, NameValueCollection query)
        {
            int? Int(string key) => int.TryParse(query[key], out var v) ? v : null;
            return BuildResponse(store, query["q"], Int("size"), Int("minutes"));
        }
    }
}
