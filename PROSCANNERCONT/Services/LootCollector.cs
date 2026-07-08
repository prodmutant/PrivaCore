using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using PROSCANNERCONT.Utils;

namespace PROSCANNERCONT.Services
{
    public sealed class LootItem
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string Source { get; set; } = ""; // e.g. "reverse-shell:10.0.0.5", "web-scanner:example.com"
        public string Description { get; set; } = "";
        public string OriginalName { get; set; } = "";
        public string StoredPath { get; set; } = "";
        public long SizeBytes { get; set; }
        public string Sha256 { get; set; } = "";
        public string Mime { get; set; } = "application/octet-stream";
        public DateTime Captured { get; set; } = DateTime.UtcNow;
        public List<string> Tags { get; set; } = new();
        /// <summary>Optional engagement scope this loot belongs to.</summary>
        public Guid? EngagementId { get; set; }
    }

    /// <summary>
    /// Structured collector for artifacts captured during an engagement —
    /// downloaded web responses, files exfilled from a reverse-shell session,
    /// credentials harvested from a honeypot, decoded payloads from packet
    /// captures.  Stores blobs on disk under
    /// %APPDATA%\PrivaCore\loot\{Id}\ and indexes metadata in loot.json.
    ///
    /// Every artifact gets a SHA-256 hash on ingest so the optional VirusTotal
    /// lookup hook (LootHashCheck) can ask "have we seen this before?" without
    /// uploading the actual content.
    /// </summary>
    public sealed class LootCollector
    {
        private static readonly Lazy<LootCollector> _instance = new(() => new LootCollector());
        public static LootCollector Instance => _instance.Value;

        private readonly string _root = Path.Combine(AppConstants.Paths.AppDataDir, "loot");
        private readonly string _index;
        private readonly object _lock = new();
        private List<LootItem> _items = new();

        private LootCollector()
        {
            Directory.CreateDirectory(_root);
            _index = Path.Combine(_root, "loot.json");
            Load();
        }

        public IReadOnlyList<LootItem> All
        {
            get { lock (_lock) return _items.ToList(); }
        }

        public LootItem Ingest(string source, string description, string originalName, byte[] content,
                                string? mime = null, IEnumerable<string>? tags = null)
        {
            var item = new LootItem
            {
                Source = source,
                Description = description,
                OriginalName = originalName,
                SizeBytes = content.Length,
                Sha256 = Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant(),
                Mime = mime ?? SniffMime(content, originalName),
                Captured = DateTime.UtcNow,
                Tags = tags?.ToList() ?? new(),
                EngagementId = EngagementService.Instance.Active?.Id,
            };

            var dir = Path.Combine(_root, item.Id.ToString("N"));
            Directory.CreateDirectory(dir);
            item.StoredPath = Path.Combine(dir, originalName);
            File.WriteAllBytes(item.StoredPath, content);

            lock (_lock) { _items.Add(item); Save(); }
            AppLogger.Log.Information("[Loot] ingested {Name} ({Bytes}B sha256={Hash}) from {Source}",
                originalName, content.Length, item.Sha256, source);
            return item;
        }

        public void Remove(Guid id)
        {
            lock (_lock)
            {
                var item = _items.FirstOrDefault(i => i.Id == id);
                if (item != null)
                {
                    try { Directory.Delete(Path.GetDirectoryName(item.StoredPath)!, true); } catch { }
                    _items.Remove(item);
                    Save();
                }
            }
        }

        private static string SniffMime(byte[] b, string name)
        {
            if (b.Length >= 4)
            {
                if (b[0] == 0x4D && b[1] == 0x5A) return "application/x-dosexec";          // MZ
                if (b[0] == 0x7F && b[1] == 0x45 && b[2] == 0x4C && b[3] == 0x46) return "application/x-elf";
                if (b[0] == 0x50 && b[1] == 0x4B) return "application/zip";                  // PK
                if (b[0] == 0x25 && b[1] == 0x50 && b[2] == 0x44 && b[3] == 0x46) return "application/pdf";
                if (b[0] == 0x89 && b[1] == 0x50 && b[2] == 0x4E && b[3] == 0x47) return "image/png";
                if (b[0] == 0xFF && b[1] == 0xD8 && b[2] == 0xFF) return "image/jpeg";
                if (b[0] == 0x1F && b[1] == 0x8B) return "application/gzip";
            }
            var ext = Path.GetExtension(name).ToLowerInvariant();
            return ext switch
            {
                ".txt" or ".log" => "text/plain",
                ".html" or ".htm" => "text/html",
                ".json" => "application/json",
                ".xml" => "application/xml",
                ".sh"   => "application/x-sh",
                ".ps1"  => "application/x-powershell",
                _       => "application/octet-stream",
            };
        }

        private void Save()
        {
            try
            {
                File.WriteAllText(_index,
                    JsonSerializer.Serialize(_items, new JsonSerializerOptions { WriteIndented = true }));
            }
            catch (Exception ex) { AppLogger.Log.Warning(ex, "[Loot] save failed"); }
        }

        private void Load()
        {
            try
            {
                if (!File.Exists(_index)) return;
                _items = JsonSerializer.Deserialize<List<LootItem>>(File.ReadAllText(_index)) ?? new();
            }
            catch (Exception ex) { AppLogger.Log.Warning(ex, "[Loot] load failed"); }
        }
    }
}
