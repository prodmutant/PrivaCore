using System;

namespace PROSCANNERCONT.Services.Siem.Elastic
{
    /// <summary>
    /// Connection settings for an Elasticsearch/OpenSearch-backed <see cref="ISiemStore"/>.
    /// Kept POCO + dependency-free (no Elasticsearch.Net) so the single-exe model is preserved —
    /// <see cref="ElasticSiemStore"/> talks to the cluster over plain HTTP + JSON.
    /// </summary>
    public sealed class SiemEsConfig
    {
        /// <summary>Cluster base URL, e.g. https://es01:9200 (no trailing slash needed).</summary>
        public string BaseUrl { get; set; } = "http://localhost:9200";

        /// <summary>Index (or data stream / alias) events are written to and searched.</summary>
        public string Index { get; set; } = "privacore-siem";

        /// <summary>Optional API key (sent as <c>Authorization: ApiKey …</c>). Takes precedence over basic auth.</summary>
        public string ApiKey { get; set; } = "";

        /// <summary>Optional HTTP basic auth.</summary>
        public string Username { get; set; } = "";
        public string Password { get; set; } = "";

        /// <summary>Accept a self-signed cluster cert (dev only).</summary>
        public bool AllowInvalidCertificate { get; set; }

        /// <summary>Request timeout for cluster calls.</summary>
        public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);
    }
}
