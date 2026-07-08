using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Threading.Tasks;
using PROSCANNERCONT.Utils;

namespace PROSCANNERCONT.Services
{
    public sealed class BackupOptions
    {
        public bool IncludeVault { get; set; } = false;
        public bool IncludeSecrets { get; set; } = false;
        public bool IncludeLogs { get; set; } = false;
        public bool IncludeLootBlobs { get; set; } = true;
    }

    public sealed class BackupResult
    {
        public string Path { get; set; } = "";
        public int FileCount { get; set; }
        public long Bytes { get; set; }
    }

    /// <summary>
    /// Single-file zipped export of the PrivaCore configuration tree.  Used
    /// for "move my profile to a new laptop" and "preserve engagement state
    /// before doing something risky".  Vault and secrets are EXCLUDED by
    /// default — moving them across machines breaks DPAPI anyway.
    /// </summary>
    public static class BackupService
    {
        public static async Task<BackupResult> CreateAsync(string destZip, BackupOptions? opts = null)
        {
            opts ??= new BackupOptions();
            var src = AppConstants.Paths.AppDataDir;

            return await Task.Run(() =>
            {
                if (File.Exists(destZip)) File.Delete(destZip);
                using var fs = new FileStream(destZip, FileMode.Create, FileAccess.Write);
                using var zip = new ZipArchive(fs, ZipArchiveMode.Create);

                int files = 0; long bytes = 0;
                foreach (var path in Directory.EnumerateFiles(src, "*", SearchOption.AllDirectories))
                {
                    var rel = Path.GetRelativePath(src, path).Replace('\\', '/');
                    // Exclusions
                    if (!opts.IncludeVault && rel.EndsWith("vault.dat", StringComparison.OrdinalIgnoreCase)) continue;
                    if (!opts.IncludeSecrets && rel.EndsWith("secrets.dat", StringComparison.OrdinalIgnoreCase)) continue;
                    if (!opts.IncludeLogs && rel.StartsWith("logs/", StringComparison.OrdinalIgnoreCase)) continue;
                    if (!opts.IncludeLootBlobs && rel.StartsWith("loot/", StringComparison.OrdinalIgnoreCase)
                        && !rel.EndsWith("loot.json", StringComparison.OrdinalIgnoreCase)) continue;

                    try
                    {
                        zip.CreateEntryFromFile(path, rel, CompressionLevel.Optimal);
                        files++;
                        bytes += new FileInfo(path).Length;
                    }
                    catch (Exception ex)
                    {
                        AppLogger.Log.Warning(ex, "[Backup] skipping {Path}", rel);
                    }
                }

                AppLogger.Log.Information("[Backup] wrote {File} ({Count} files, {KB} KB)",
                    destZip, files, new FileInfo(destZip).Length / 1024);

                return new BackupResult { Path = destZip, FileCount = files, Bytes = bytes };
            });
        }

        /// <summary>Restore a previously-created backup. Overwrites existing files.</summary>
        public static async Task RestoreAsync(string zipPath, bool overwrite = true)
        {
            var dst = AppConstants.Paths.AppDataDir;
            Directory.CreateDirectory(dst);
            await Task.Run(() =>
            {
                using var fs = File.OpenRead(zipPath);
                using var zip = new ZipArchive(fs, ZipArchiveMode.Read);
                foreach (var entry in zip.Entries)
                {
                    if (string.IsNullOrEmpty(entry.Name)) continue;
                    var target = Path.Combine(dst, entry.FullName.Replace('/', Path.DirectorySeparatorChar));
                    Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                    if (File.Exists(target) && !overwrite) continue;
                    entry.ExtractToFile(target, overwrite);
                }
            });
            AppLogger.Log.Information("[Backup] restored {Zip} → {Dst}", zipPath, dst);
        }
    }
}
