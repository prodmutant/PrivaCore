using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Services
{
    /// <summary>
    /// Manages downloading ISO images for VM deployment
    /// </summary>
    public class ISODownloadManager
    {
        private readonly string _isoStoragePath = @"C:\HyperV\ISOs";
        private readonly HttpClient _httpClient;

        // Events for progress reporting
        public event EventHandler<DownloadProgressEventArgs> DownloadProgressChanged;
        public event EventHandler<DownloadCompletedEventArgs> DownloadCompleted;

        public ISODownloadManager()
        {
            _httpClient = new HttpClient { Timeout = TimeSpan.FromHours(2) };
            EnsureStorageDirectory();
        }

        private void EnsureStorageDirectory()
        {
            try
            {
                Directory.CreateDirectory(_isoStoragePath);
                Debug.WriteLine($"ISO storage path: {_isoStoragePath}");
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to create ISO storage directory: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Get list of available ISO images for download
        /// </summary>
        public List<ISOImageInfo> GetAvailableISOs()
        {
            return new List<ISOImageInfo>
            {
                // Ubuntu LTS
                new ISOImageInfo
                {
                    Name = "Ubuntu 22.04 LTS Server",
                    OSType = "Linux",
                    Distribution = "Ubuntu",
                    Version = "22.04",
                    Architecture = "amd64",
                    DownloadUrl = "https://releases.ubuntu.com/22.04/ubuntu-22.04.3-live-server-amd64.iso",
                    FileSize = 1474873344, // ~1.4 GB
                    SupportsUnattended = true,
                    Generation = 2,
                    ImageType = ImageSourceType.ISO
                },

                new ISOImageInfo
                {
                    Name = "Ubuntu 20.04 LTS Server",
                    OSType = "Linux",
                    Distribution = "Ubuntu",
                    Version = "20.04",
                    Architecture = "amd64",
                    DownloadUrl = "https://releases.ubuntu.com/20.04/ubuntu-20.04.6-live-server-amd64.iso",
                    FileSize = 1331691520, // ~1.2 GB
                    SupportsUnattended = true,
                    Generation = 2,
                    ImageType = ImageSourceType.ISO
                },
                
                // Debian
                new ISOImageInfo
                {
                    Name = "Debian 12 (Bookworm) Net Install",
                    OSType = "Linux",
                    Distribution = "Debian",
                    Version = "12",
                    Architecture = "amd64",
                    DownloadUrl = "https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-12.4.0-amd64-netinst.iso",
                    FileSize = 660602880, // ~630 MB
                    SupportsUnattended = true,
                    Generation = 2,
                    ImageType = ImageSourceType.ISO
                },
                
                // Alpine Linux (Lightweight)
                new ISOImageInfo
                {
                    Name = "Alpine Linux 3.19",
                    OSType = "Linux",
                    Distribution = "Alpine",
                    Version = "3.19",
                    Architecture = "x86_64",
                    DownloadUrl = "https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/x86_64/alpine-standard-3.19.0-x86_64.iso",
                    FileSize = 183500800, // ~175 MB
                    SupportsUnattended = false,
                    Generation = 2,
                    ImageType = ImageSourceType.ISO
                }
            };
        }

        /// <summary>
        /// Get list of already downloaded ISOs
        /// </summary>
        public List<string> GetDownloadedISOs()
        {
            try
            {
                var isoFiles = Directory.GetFiles(_isoStoragePath, "*.iso");
                var result = new List<string>();

                foreach (var file in isoFiles)
                {
                    result.Add(file);
                }

                return result;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error getting downloaded ISOs: {ex.Message}");
                return new List<string>();
            }
        }

        /// <summary>
        /// Check if an ISO is already downloaded
        /// </summary>
        public bool IsISODownloaded(ISOImageInfo isoInfo)
        {
            string fileName = GetISOFileName(isoInfo);
            string fullPath = Path.Combine(_isoStoragePath, fileName);
            return File.Exists(fullPath);
        }

        /// <summary>
        /// Get local path for an ISO
        /// </summary>
        public string GetISOPath(ISOImageInfo isoInfo)
        {
            string fileName = GetISOFileName(isoInfo);
            return Path.Combine(_isoStoragePath, fileName);
        }

        private string GetISOFileName(ISOImageInfo isoInfo)
        {
            // Create safe filename
            string safeName = $"{isoInfo.Distribution}_{isoInfo.Version}_{isoInfo.Architecture}.iso";
            return safeName;
        }

        /// <summary>
        /// Download an ISO with progress reporting
        /// </summary>
        public async Task<string> DownloadISOAsync(ISOImageInfo isoInfo, CancellationToken cancellationToken = default)
        {
            string fileName = GetISOFileName(isoInfo);
            string localPath = Path.Combine(_isoStoragePath, fileName);

            // Check if already downloaded
            if (File.Exists(localPath))
            {
                Debug.WriteLine($"ISO already exists: {localPath}");
                return localPath;
            }

            Debug.WriteLine($"Starting download: {isoInfo.Name}");
            Debug.WriteLine($"URL: {isoInfo.DownloadUrl}");
            Debug.WriteLine($"Destination: {localPath}");

            try
            {
                // Download with progress reporting
                var response = await _httpClient.GetAsync(isoInfo.DownloadUrl, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
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

                        // Report progress
                        if (totalBytes.HasValue)
                        {
                            int percentage = (int)((totalRead * 100) / totalBytes.Value);

                            DownloadProgressChanged?.Invoke(this, new DownloadProgressEventArgs
                            {
                                ImageName = isoInfo.Name,
                                BytesDownloaded = totalRead,
                                TotalBytes = totalBytes.Value,
                                PercentComplete = percentage
                            });
                        }
                    }
                }

                Debug.WriteLine($"Download completed: {localPath}");

                // Fire completion event
                DownloadCompleted?.Invoke(this, new DownloadCompletedEventArgs
                {
                    ImageName = isoInfo.Name,
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

                // Fire error event
                DownloadCompleted?.Invoke(this, new DownloadCompletedEventArgs
                {
                    ImageName = isoInfo.Name,
                    LocalPath = null,
                    Success = false,
                    Error = ex.Message
                });

                throw;
            }
        }
    }

    // Event args classes are in ImageCatalogService.cs
}