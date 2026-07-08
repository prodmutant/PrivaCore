using System;
using System.Collections.Generic;
using System.Linq;

namespace PROSCANNERCONT.Models
{
    /// <summary>
    /// A prebuilt integration (the ELK "Integrations" catalog): a named bundle of pipeline stages
    /// that parse + normalise a well-known log source (sshd, nginx, Windows Security, …). Adding one
    /// appends its stages to the user's pipeline, so events from that source are enriched out of the box.
    /// </summary>
    public sealed class SiemIntegration
    {
        public string Key { get; set; } = "";
        public string Name { get; set; } = "";
        public string Icon { get; set; } = "PuzzlePiece";
        public string Description { get; set; } = "";
        public Func<List<SiemProcessor>> Build { get; set; } = () => new();
    }

    /// <summary>The built-in integrations catalog. Each entry yields fresh processor instances on add.</summary>
    public static class SiemIntegrations
    {
        public static IReadOnlyList<SiemIntegration> All { get; } = new List<SiemIntegration>
        {
            new()
            {
                Key = "sshd", Name = "Linux SSH (sshd)", Icon = "Linux",
                Description = "Parse OpenSSH auth log lines — user, source IP, outcome — and tag failed logins as Authentication.",
                Build = () => new()
                {
                    new() { Type = SiemProcessorType.ExtractRegex, MatchField = SiemMatchField.Message, MatchValue = "sshd",
                            Field = "message", Arg = @"(?<event_outcome>Failed|Accepted)\s+password\s+for\s+(?:invalid user\s+)?(?<user_name>\S+)\s+from\s+(?<source_ip>\d{1,3}(?:\.\d{1,3}){3})" },
                    new() { Type = SiemProcessorType.SetCategory, MatchField = SiemMatchField.Message, MatchValue = "sshd", Arg = "authentication" },
                    new() { Type = SiemProcessorType.SetSeverity, MatchField = SiemMatchField.Message, MatchValue = "Failed password", Arg = "Medium" },
                },
            },
            new()
            {
                Key = "nginx", Name = "Nginx access log", Icon = "Server",
                Description = "Grok the combined access-log format into source.ip, http.request.method, url.path and http.response.status_code.",
                Build = () => new()
                {
                    new() { Type = SiemProcessorType.ExtractRegex, MatchField = SiemMatchField.Source, MatchValue = "nginx",
                            Field = "message", Arg = @"(?<source_ip>\S+)\s+\S+\s+\S+\s+\[[^\]]+\]\s+""(?<http_request_method>\S+)\s+(?<url_path>\S+)[^""]*""\s+(?<http_response_status_code>\d{3})" },
                    new() { Type = SiemProcessorType.SetCategory, MatchField = SiemMatchField.Source, MatchValue = "nginx", Arg = "web" },
                    new() { Type = SiemProcessorType.SetSeverity, MatchField = SiemMatchField.Message, MatchValue = " 500 ", Arg = "High" },
                },
            },
            new()
            {
                Key = "apache", Name = "Apache access log", Icon = "Server",
                Description = "Grok the Apache common/combined log format into source.ip, method, path and status code.",
                Build = () => new()
                {
                    new() { Type = SiemProcessorType.ExtractRegex, MatchField = SiemMatchField.Source, MatchValue = "apache",
                            Field = "message", Arg = @"(?<source_ip>\S+)\s+\S+\s+\S+\s+\[[^\]]+\]\s+""(?<http_request_method>\S+)\s+(?<url_path>\S+)[^""]*""\s+(?<http_response_status_code>\d{3})" },
                    new() { Type = SiemProcessorType.SetCategory, MatchField = SiemMatchField.Source, MatchValue = "apache", Arg = "web" },
                },
            },
            new()
            {
                Key = "windows-security", Name = "Windows Security events", Icon = "Windows",
                Description = "Categorise common Windows Security event IDs (4624/4625 logon, 4688 process, 4720 user-created) and escalate failures.",
                Build = () => new()
                {
                    new() { Type = SiemProcessorType.SetCategory, MatchField = SiemMatchField.Message, MatchValue = "4625", Arg = "authentication" },
                    new() { Type = SiemProcessorType.SetSeverity, MatchField = SiemMatchField.Message, MatchValue = "4625", Arg = "Medium" },
                    new() { Type = SiemProcessorType.SetCategory, MatchField = SiemMatchField.Message, MatchValue = "4688", Arg = "process" },
                    new() { Type = SiemProcessorType.SetCategory, MatchField = SiemMatchField.Message, MatchValue = "4720", Arg = "iam" },
                    new() { Type = SiemProcessorType.SetSeverity, MatchField = SiemMatchField.Message, MatchValue = "4720", Arg = "High" },
                },
            },
            new()
            {
                Key = "firewall", Name = "Firewall / network deny", Icon = "Fire",
                Description = "Tag firewall DROP/DENY/BLOCK lines as network events and extract source/destination IPs.",
                Build = () => new()
                {
                    new() { Type = SiemProcessorType.ExtractRegex, MatchField = SiemMatchField.Message, MatchValue = "",
                            Field = "message", Arg = @"SRC=(?<source_ip>\d{1,3}(?:\.\d{1,3}){3}).*?DST=(?<destination_ip>\d{1,3}(?:\.\d{1,3}){3})" },
                    new() { Type = SiemProcessorType.SetCategory, MatchField = SiemMatchField.Message, MatchValue = "DENY", Arg = "network" },
                    new() { Type = SiemProcessorType.SetCategory, MatchField = SiemMatchField.Message, MatchValue = "DROP", Arg = "network" },
                },
            },
            new()
            {
                Key = "geo-threat", Name = "GeoIP + threat baseline", Icon = "EarthAmericas",
                Description = "Enrich every event's source.ip with GeoIP, then drop low-value noise — a sensible starter pipeline.",
                Build = () => new()
                {
                    new() { Type = SiemProcessorType.GeoEnrich, MatchField = SiemMatchField.Any, MatchValue = "", Field = "source.ip" },
                    new() { Type = SiemProcessorType.Dedupe, MatchField = SiemMatchField.Any, MatchValue = "", Field = "message", Arg = "30" },
                },
            },
        };

        public static SiemIntegration? Get(string key) => All.FirstOrDefault(i => i.Key == key);
    }
}
