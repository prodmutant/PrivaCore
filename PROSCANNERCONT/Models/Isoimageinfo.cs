using System;

namespace PROSCANNERCONT.Models
{
    /// <summary>
    /// Information about an available ISO image or VM image
    /// </summary>
    public class ISOImageInfo
    {
        // ============================================================
        // BASIC INFO
        // ============================================================

        /// <summary>
        /// Display name (e.g., "Ubuntu 22.04 LTS Server")
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// OS Type (Linux, Windows, etc.)
        /// </summary>
        public string OSType { get; set; }

        /// <summary>
        /// Distribution name (Ubuntu, Debian, CentOS, etc.)
        /// </summary>
        public string Distribution { get; set; }

        /// <summary>
        /// Version number (22.04, 12, etc.)
        /// </summary>
        public string Version { get; set; }

        /// <summary>
        /// Architecture (amd64, x86_64, etc.)
        /// </summary>
        public string Architecture { get; set; }

        /// <summary>
        /// Description
        /// </summary>
        public string Description { get; set; }

        // ============================================================
        // DOWNLOAD INFO
        // ============================================================

        /// <summary>
        /// Direct download URL
        /// </summary>
        public string DownloadUrl { get; set; }

        /// <summary>
        /// File size in bytes
        /// </summary>
        public long FileSize { get; set; }

        /// <summary>
        /// File size as friendly string
        /// </summary>
        public string FileSizeText
        {
            get
            {
                if (FileSize < 1024 * 1024)
                    return $"{FileSize / 1024} KB";
                if (FileSize < 1024 * 1024 * 1024)
                    return $"{FileSize / 1024 / 1024} MB";
                return $"{FileSize / 1024 / 1024 / 1024:F2} GB";
            }
        }

        /// <summary>
        /// SHA256 checksum (optional)
        /// </summary>
        public string SHA256 { get; set; }

        // ============================================================
        // IMAGE TYPE
        // ============================================================

        /// <summary>
        /// Type of image
        /// </summary>
        public ImageSourceType ImageType { get; set; }

        /// <summary>
        /// Whether this supports unattended installation
        /// </summary>
        public bool SupportsUnattended { get; set; }

        /// <summary>
        /// VM Generation (1 = BIOS, 2 = UEFI)
        /// </summary>
        public int Generation { get; set; }

        // ============================================================
        // STATUS
        // ============================================================

        /// <summary>
        /// Whether this image is already downloaded
        /// </summary>
        public bool IsDownloaded { get; set; }

        /// <summary>
        /// Local file path if downloaded
        /// </summary>
        public string LocalPath { get; set; }

        // ============================================================
        // AGENT INFO
        // ============================================================

        /// <summary>
        /// Whether agent is pre-installed in this image
        /// </summary>
        public bool HasSSHConfiguredPreInstalled { get; set; }

        /// <summary>
        /// Whether agent can be auto-installed during deployment
        /// </summary>
        public bool SupportsAgentAutoInstall { get; set; }

        // ============================================================
        // DISPLAY PROPERTIES
        // ============================================================

        /// <summary>
        /// Icon/emoji for display
        /// </summary>
        public string Icon => OSType?.ToLower() switch
        {
            "linux" => "🐧",
            "windows" => "🪟",
            "bsd" => "😈",
            _ => "💿"
        };

        /// <summary>
        /// Category for grouping
        /// </summary>
        public string Category => ImageType switch
        {
            ImageSourceType.PreBuiltVHDX => "Pre-Built Images (Instant)",
            ImageSourceType.VagrantBox => "Vagrant Boxes (Quick)",
            ImageSourceType.ISO => "ISO Images (Custom)",
            _ => "Other"
        };

        /// <summary>
        /// Status text
        /// </summary>
        public string StatusText
        {
            get
            {
                if (HasSSHConfiguredPreInstalled)
                    return "✓ Agent Pre-Installed";
                if (SupportsAgentAutoInstall)
                    return "⚡ Auto-Install Available";
                if (SupportsUnattended)
                    return "🤖 Unattended Install";
                return "📋 Manual Install";
            }
        }

        /// <summary>
        /// Speed indicator
        /// </summary>
        public string SpeedIndicator => ImageType switch
        {
            ImageSourceType.PreBuiltVHDX => "⚡⚡⚡ Instant",
            ImageSourceType.VagrantBox => "⚡⚡ 2-5 min",
            ImageSourceType.ISO when SupportsUnattended => "⚡ 5-10 min",
            ImageSourceType.ISO => "⏱ 10-20 min",
            _ => "⏱ Variable"
        };
    }

    /// <summary>
    /// Type of image source
    /// </summary>
    public enum ImageSourceType
    {
        /// <summary>
        /// Pre-built VHDX image (instant deployment)
        /// </summary>
        PreBuiltVHDX,

        /// <summary>
        /// Vagrant box (needs conversion)
        /// </summary>
        VagrantBox,

        /// <summary>
        /// ISO file (requires installation)
        /// </summary>
        ISO,

        /// <summary>
        /// Cloud image (qcow2, etc.)
        /// </summary>
        CloudImage
    }
}