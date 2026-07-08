using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Services
{
    /// <summary>
    /// Central catalog of all available OS images and ISOs
    /// Manages downloads, conversions, and image availability
    /// </summary>
    public class ImageCatalogService
    {
        private readonly string _isoStoragePath = @"C:\HyperV\ISOs";
        private readonly string _imageStoragePath = @"C:\HyperV\BaseImages";
        private readonly HttpClient _httpClient;

        // Events
        public event EventHandler<DownloadProgressEventArgs> DownloadProgressChanged;
        public event EventHandler<DownloadCompletedEventArgs> DownloadCompleted;

        public ImageCatalogService()
        {
            _httpClient = new HttpClient { Timeout = TimeSpan.FromHours(3) };
            EnsureDirectories();
        }

        private void EnsureDirectories()
        {
            Directory.CreateDirectory(_isoStoragePath);
            Directory.CreateDirectory(_imageStoragePath);
        }

        /// <summary>
        /// Get complete catalog of available images
        /// </summary>
        public List<ISOImageInfo> GetImageCatalog()
        {
            var catalog = new List<ISOImageInfo>();

            // Add pre-built VHDX images
            catalog.AddRange(GetPreBuiltImages());

            // Add Vagrant boxes
            catalog.AddRange(GetVagrantBoxes());

            // Add ISOs
            catalog.AddRange(GetISOImages());

            // Check which ones are already downloaded
            UpdateDownloadStatus(catalog);

            return catalog;
        }

        /// <summary>
        /// Get pre-built VHDX images (instant deployment)
        /// </summary>
        private List<ISOImageInfo> GetPreBuiltImages()
        {
            return new List<ISOImageInfo>
            {
                new ISOImageInfo
                {
                    Name = "Ubuntu 22.04 Server (Agent Pre-Installed)",
                    OSType = "Linux",
                    Distribution = "Ubuntu",
                    Version = "22.04",
                    Architecture = "amd64",
                    Description = "Ubuntu 22.04 LTS cloud image (VHDX) — agent can be injected post-deployment via SSH",
                    ImageType = ImageSourceType.PreBuiltVHDX,
                    FileSize = 700000000, // ~670 MB cloud image
                    Generation = 2,
                    SupportsUnattended = false,
                    HasSSHConfiguredPreInstalled = true,
                    SupportsAgentAutoInstall = true,
                    DownloadUrl = "https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.vhd.zip"
                },

                new ISOImageInfo
                {
                    Name = "Debian 12 Minimal (Agent Pre-Installed)",
                    OSType = "Linux",
                    Distribution = "Debian",
                    Version = "12",
                    Architecture = "amd64",
                    Description = "Debian 12 genericcloud image (VHDX) — agent can be injected post-deployment via SSH",
                    ImageType = ImageSourceType.PreBuiltVHDX,
                    FileSize = 400000000, // ~380 MB cloud image
                    Generation = 2,
                    SupportsUnattended = false,
                    HasSSHConfiguredPreInstalled = true,
                    SupportsAgentAutoInstall = true,
                    DownloadUrl = "https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.tar.xz"
                }
            };
        }

        /// <summary>
        /// Get Vagrant boxes (quick deployment after conversion)
        /// </summary>
        private List<ISOImageInfo> GetVagrantBoxes()
        {
            return new List<ISOImageInfo>
            {
                new ISOImageInfo
                {
                    Name = "Ubuntu 22.04 (Vagrant)",
                    OSType = "Linux",
                    Distribution = "Ubuntu",
                    Version = "22.04",
                    Architecture = "amd64",
                    Description = "Official Ubuntu 22.04 Vagrant box",
                    ImageType = ImageSourceType.VagrantBox,
                    FileSize = 671088640, // ~640 MB
                    Generation = 2,
                    SupportsUnattended = false,
                    HasSSHConfiguredPreInstalled = false,
                    SupportsAgentAutoInstall = true, // Can inject agent during conversion
                    DownloadUrl = "https://vagrantcloud.com/ubuntu/boxes/jammy64/versions/20231215.0.0/providers/hyperv.box"
                },

                new ISOImageInfo
                {
                    Name = "Debian 12 (Vagrant)",
                    OSType = "Linux",
                    Distribution = "Debian",
                    Version = "12",
                    Architecture = "amd64",
                    Description = "Official Debian 12 Vagrant box",
                    ImageType = ImageSourceType.VagrantBox,
                    FileSize = 536870912, // ~512 MB
                    Generation = 2,
                    SupportsUnattended = false,
                    HasSSHConfiguredPreInstalled = false,
                    SupportsAgentAutoInstall = true,
                    DownloadUrl = "https://vagrantcloud.com/debian/boxes/bookworm64/versions/12.4.0/providers/hyperv.box"
                }
            };
        }

        /// <summary>
        /// Get ISO images (custom installation)
        /// </summary>
        private List<ISOImageInfo> GetISOImages()
        {
            return new List<ISOImageInfo>
            {
                // Ubuntu
                new ISOImageInfo
                {
                    Name = "Ubuntu 22.04 LTS Server",
                    OSType = "Linux",
                    Distribution = "Ubuntu",
                    Version = "22.04",
                    Architecture = "amd64",
                    Description = "Ubuntu 22.04 LTS Server with automated installation support",
                    ImageType = ImageSourceType.ISO,
                    DownloadUrl = "https://releases.ubuntu.com/22.04/ubuntu-22.04.3-live-server-amd64.iso",
                    FileSize = 1474873344, // ~1.4 GB
                    Generation = 2,
                    SupportsUnattended = true,
                    HasSSHConfiguredPreInstalled = false,
                    SupportsAgentAutoInstall = true
                },

                new ISOImageInfo
                {
                    Name = "Ubuntu 20.04 LTS Server",
                    OSType = "Linux",
                    Distribution = "Ubuntu",
                    Version = "20.04",
                    Architecture = "amd64",
                    Description = "Ubuntu 20.04 LTS Server (stable, well-tested)",
                    ImageType = ImageSourceType.ISO,
                    DownloadUrl = "https://releases.ubuntu.com/20.04/ubuntu-20.04.6-live-server-amd64.iso",
                    FileSize = 1331691520, // ~1.2 GB
                    Generation = 2,
                    SupportsUnattended = true,
                    HasSSHConfiguredPreInstalled = false,
                    SupportsAgentAutoInstall = true
                },
                
                // Debian
                new ISOImageInfo
                {
                    Name = "Debian 12 (Bookworm) Net Install",
                    OSType = "Linux",
                    Distribution = "Debian",
                    Version = "12",
                    Architecture = "amd64",
                    Description = "Debian 12 network installer (minimal download)",
                    ImageType = ImageSourceType.ISO,
                    DownloadUrl = "https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-12.4.0-amd64-netinst.iso",
                    FileSize = 660602880, // ~630 MB
                    Generation = 2,
                    SupportsUnattended = true,
                    HasSSHConfiguredPreInstalled = false,
                    SupportsAgentAutoInstall = true
                },
                
                // Alpine (Lightweight)
                new ISOImageInfo
                {
                    Name = "Alpine Linux 3.19",
                    OSType = "Linux",
                    Distribution = "Alpine",
                    Version = "3.19",
                    Architecture = "x86_64",
                    Description = "Ultra-lightweight Linux (~175MB) - perfect for honeypots",
                    ImageType = ImageSourceType.ISO,
                    DownloadUrl = "https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/x86_64/alpine-standard-3.19.0-x86_64.iso",
                    FileSize = 183500800, // ~175 MB
                    Generation = 2,
                    SupportsUnattended = false, // Alpine requires manual setup
                    HasSSHConfiguredPreInstalled = false,
                    SupportsAgentAutoInstall = false
                },
                
                // Kali Linux (Security)
                new ISOImageInfo
                {
                    Name = "Kali Linux 2024.1",
                    OSType = "Linux",
                    Distribution = "Kali",
                    Version = "2024.1",
                    Architecture = "amd64",
                    Description = "Penetration testing distribution (for advanced honeypots)",
                    ImageType = ImageSourceType.ISO,
                    DownloadUrl = "https://cdimage.kali.org/kali-2024.1/kali-linux-2024.1-installer-amd64.iso",
                    FileSize = 3900000000, // ~3.6 GB
                    Generation = 2,
                    SupportsUnattended = true,
                    HasSSHConfiguredPreInstalled = false,
                    SupportsAgentAutoInstall = true
                }
            };
        }

        /// <summary>
        /// Update download status for all images
        /// </summary>
        private void UpdateDownloadStatus(List<ISOImageInfo> images)
        {
            foreach (var image in images)
            {
                string localPath = GetLocalPath(image);
                if (File.Exists(localPath))
                {
                    image.IsDownloaded = true;
                    image.LocalPath = localPath;
                }
            }
        }

        /// <summary>
        /// Get local path where image would be/is stored
        /// </summary>
        public string GetLocalPath(ISOImageInfo image)
        {
            string directory = image.ImageType == ImageSourceType.ISO ? _isoStoragePath : _imageStoragePath;
            string extension = image.ImageType switch
            {
                ImageSourceType.ISO => ".iso",
                ImageSourceType.VagrantBox => ".box",
                ImageSourceType.PreBuiltVHDX => ".vhdx",
                _ => ".img"
            };

            string fileName = $"{image.Distribution}_{image.Version}_{image.Architecture}{extension}";
            return Path.Combine(directory, fileName);
        }

        /// <summary>
        /// Download an image with progress reporting
        /// </summary>
        public async Task<string> DownloadImageAsync(ISOImageInfo image, CancellationToken cancellationToken = default)
        {
            string localPath = GetLocalPath(image);

            // If already downloaded, return path
            if (File.Exists(localPath))
            {
                Debug.WriteLine($"Image already downloaded: {localPath}");
                return localPath;
            }

            Debug.WriteLine($"Starting download: {image.Name}");
            Debug.WriteLine($"URL: {image.DownloadUrl}");
            Debug.WriteLine($"Destination: {localPath}");

            try
            {
                var response = await _httpClient.GetAsync(image.DownloadUrl, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
                response.EnsureSuccessStatusCode();

                long? totalBytes = response.Content.Headers.ContentLength;

                using (var contentStream = await response.Content.ReadAsStreamAsync())
                using (var fileStream = new FileStream(localPath, FileMode.Create, FileAccess.Write, FileShare.None, 8192, true))
                {
                    byte[] buffer = new byte[8192];
                    long totalRead = 0;
                    int read;

                    while ((read = await contentStream.ReadAsync(buffer, 0, buffer.Length, cancellationToken)) > 0)
                    {
                        await fileStream.WriteAsync(buffer, 0, read, cancellationToken);
                        totalRead += read;

                        if (totalBytes.HasValue)
                        {
                            int percentage = (int)((totalRead * 100) / totalBytes.Value);
                            DownloadProgressChanged?.Invoke(this, new DownloadProgressEventArgs
                            {
                                ImageName = image.Name,
                                BytesDownloaded = totalRead,
                                TotalBytes = totalBytes.Value,
                                PercentComplete = percentage
                            });
                        }
                    }
                }

                Debug.WriteLine($"Download completed: {localPath}");

                image.IsDownloaded = true;
                image.LocalPath = localPath;

                DownloadCompleted?.Invoke(this, new DownloadCompletedEventArgs
                {
                    ImageName = image.Name,
                    LocalPath = localPath,
                    Success = true
                });

                return localPath;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Download failed: {ex.Message}");

                // Clean up partial download
                if (File.Exists(localPath))
                {
                    try { File.Delete(localPath); } catch { }
                }

                DownloadCompleted?.Invoke(this, new DownloadCompletedEventArgs
                {
                    ImageName = image.Name,
                    LocalPath = null,
                    Success = false,
                    Error = ex.Message
                });

                throw;
            }
        }
    }

    // ============================================================
    // EVENT ARGS
    // ============================================================

    public class DownloadProgressEventArgs : EventArgs
    {
        public string ImageName { get; set; }
        public long BytesDownloaded { get; set; }
        public long TotalBytes { get; set; }
        public int PercentComplete { get; set; }
        public double MBDownloaded => BytesDownloaded / 1024.0 / 1024.0;
        public double TotalMB => TotalBytes / 1024.0 / 1024.0;
    }

    public class DownloadCompletedEventArgs : EventArgs
    {
        public string ImageName { get; set; }
        public string LocalPath { get; set; }
        public bool Success { get; set; }
        public string Error { get; set; }
    }
}