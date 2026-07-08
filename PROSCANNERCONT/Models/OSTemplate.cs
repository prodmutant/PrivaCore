using System;
using System.Collections.Generic;
using System.IO;

namespace PROSCANNERCONT.Models
{
    /// <summary>
    /// Operating system template for honeypot deployment
    /// </summary>
    public class OSTemplate
    {
        public string Name { get; set; }
        public string DisplayName { get; set; }
        public string Description { get; set; }
        public string Icon { get; set; }
        public int RecommendedRAM { get; set; }
        public int MinRAM { get; set; }
        public int RecommendedCPU { get; set; }
        public int RecommendedStorage { get; set; }
        public int MinStorage { get; set; }
        public bool UsePrebuiltImage { get; set; }
        public string BaseImagePath { get; set; }
        public string ISODownloadURL { get; set; }
        public string Category { get; set; } // "Lightweight", "Standard", "Security-Focused", "Custom"
        public List<string> Features { get; set; }
        public int RecommendedGeneration { get; set; } // 1 or 2

        public bool IsBaseImageAvailable()
        {
            if (!UsePrebuiltImage || string.IsNullOrEmpty(BaseImagePath))
                return false;

            return File.Exists(BaseImagePath);
        }

        /// <summary>
        /// Get all available OS templates
        /// </summary>
        public static List<OSTemplate> GetAllTemplates()
        {
            return new List<OSTemplate>
            {
                CreateTinyCoreTemplate(),
                CreateAlpineTemplate(),
                CreateUbuntuServerTemplate(),
                CreateDebianTemplate(),
                CreateKaliTemplate(),
                CreateCentOSTemplate(),
                CreateArchTemplate(),
                CreateCustomTemplate()
            };
        }

        /// <summary>
        /// TinyCore Linux - Ultra lightweight
        /// </summary>
        public static OSTemplate CreateTinyCoreTemplate()
        {
            return new OSTemplate
            {
                Name = "tinycore",
                DisplayName = "TinyCore Linux",
                Description = "Ultra-lightweight Linux (~106MB) with GUI - Perfect for honeypots",
                Icon = "🐧",
                Category = "Lightweight",
                RecommendedRAM = 256,
                MinRAM = 128,
                RecommendedCPU = 1,
                RecommendedStorage = 5,
                MinStorage = 2,
                RecommendedGeneration = 1,
                UsePrebuiltImage = false,
                BaseImagePath = @"C:\HoneypotImages\TinyCore\base.vhdx",
                ISODownloadURL = "http://www.tinycorelinux.net/downloads.html",
                Features = new List<string>
                {
                    "Minimal resource usage",
                    "Fast boot time",
                    "Built-in GUI",
                    "Easy to configure"
                }
            };
        }

        /// <summary>
        /// Alpine Linux - Security-focused lightweight
        /// </summary>
        public static OSTemplate CreateAlpineTemplate()
        {
            return new OSTemplate
            {
                Name = "alpine",
                DisplayName = "Alpine Linux",
                Description = "Security-oriented, lightweight Linux (~130MB) with musl libc",
                Icon = "⛰️",
                Category = "Lightweight",
                RecommendedRAM = 512,
                MinRAM = 256,
                RecommendedCPU = 1,
                RecommendedStorage = 8,
                MinStorage = 4,
                RecommendedGeneration = 1,
                UsePrebuiltImage = false,
                BaseImagePath = @"C:\HoneypotImages\Alpine\base.vhdx",
                ISODownloadURL = "https://alpinelinux.org/downloads/",
                Features = new List<string>
                {
                    "Security-hardened",
                    "Minimal attack surface",
                    "Docker-friendly",
                    "Fast package manager (apk)"
                }
            };
        }

        /// <summary>
        /// Ubuntu Server - Popular and well-supported
        /// </summary>
        public static OSTemplate CreateUbuntuServerTemplate()
        {
            return new OSTemplate
            {
                Name = "ubuntu",
                DisplayName = "Ubuntu Server 22.04 LTS",
                Description = "Popular server distribution with extensive package repository",
                Icon = "🎯",
                Category = "Standard",
                RecommendedRAM = 2048,
                MinRAM = 1024,
                RecommendedCPU = 2,
                RecommendedStorage = 20,
                MinStorage = 10,
                RecommendedGeneration = 2,
                UsePrebuiltImage = false,
                BaseImagePath = @"C:\HoneypotImages\Ubuntu\base.vhdx",
                ISODownloadURL = "https://ubuntu.com/download/server",
                Features = new List<string>
                {
                    "Long-term support (LTS)",
                    "Extensive documentation",
                    "Large package repository",
                    "Enterprise-ready"
                }
            };
        }

        /// <summary>
        /// Debian - Stable and reliable
        /// </summary>
        public static OSTemplate CreateDebianTemplate()
        {
            return new OSTemplate
            {
                Name = "debian",
                DisplayName = "Debian 12 (Bookworm)",
                Description = "Rock-solid stability with comprehensive package management",
                Icon = "🌀",
                Category = "Standard",
                RecommendedRAM = 1024,
                MinRAM = 512,
                RecommendedCPU = 1,
                RecommendedStorage = 15,
                MinStorage = 8,
                RecommendedGeneration = 1,
                UsePrebuiltImage = false,
                BaseImagePath = @"C:\HoneypotImages\Debian\base.vhdx",
                ISODownloadURL = "https://www.debian.org/distrib/netinst",
                Features = new List<string>
                {
                    "Maximum stability",
                    "Universal OS base",
                    "Strong security",
                    "Mature ecosystem"
                }
            };
        }

        /// <summary>
        /// Kali Linux - Penetration testing
        /// </summary>
        public static OSTemplate CreateKaliTemplate()
        {
            return new OSTemplate
            {
                Name = "kali",
                DisplayName = "Kali Linux",
                Description = "Advanced penetration testing and security auditing platform",
                Icon = "🐉",
                Category = "Security-Focused",
                RecommendedRAM = 2048,
                MinRAM = 1024,
                RecommendedCPU = 2,
                RecommendedStorage = 25,
                MinStorage = 15,
                RecommendedGeneration = 2,
                UsePrebuiltImage = false,
                BaseImagePath = @"C:\HoneypotImages\Kali\base.vhdx",
                ISODownloadURL = "https://www.kali.org/get-kali/",
                Features = new List<string>
                {
                    "600+ security tools",
                    "Forensics ready",
                    "Penetration testing",
                    "Regular updates"
                }
            };
        }

        /// <summary>
        /// CentOS Stream - Enterprise alternative
        /// </summary>
        public static OSTemplate CreateCentOSTemplate()
        {
            return new OSTemplate
            {
                Name = "centos",
                DisplayName = "CentOS Stream 9",
                Description = "Rolling-release RHEL preview for enterprise environments",
                Icon = "🏢",
                Category = "Standard",
                RecommendedRAM = 2048,
                MinRAM = 1024,
                RecommendedCPU = 2,
                RecommendedStorage = 20,
                MinStorage = 10,
                RecommendedGeneration = 2,
                UsePrebuiltImage = false,
                BaseImagePath = @"C:\HoneypotImages\CentOS\base.vhdx",
                ISODownloadURL = "https://www.centos.org/download/",
                Features = new List<string>
                {
                    "Enterprise-grade",
                    "RHEL-based",
                    "SELinux enabled",
                    "Strong security"
                }
            };
        }

        /// <summary>
        /// Arch Linux - Rolling release, minimal
        /// </summary>
        public static OSTemplate CreateArchTemplate()
        {
            return new OSTemplate
            {
                Name = "arch",
                DisplayName = "Arch Linux",
                Description = "Lightweight, flexible rolling-release distribution",
                Icon = "🏛️",
                Category = "Lightweight",
                RecommendedRAM = 1024,
                MinRAM = 512,
                RecommendedCPU = 1,
                RecommendedStorage = 15,
                MinStorage = 8,
                RecommendedGeneration = 2,
                UsePrebuiltImage = false,
                BaseImagePath = @"C:\HoneypotImages\Arch\base.vhdx",
                ISODownloadURL = "https://archlinux.org/download/",
                Features = new List<string>
                {
                    "Rolling release",
                    "Cutting-edge packages",
                    "Minimalist design",
                    "AUR repository"
                }
            };
        }

        /// <summary>
        /// Custom ISO - User provides their own
        /// </summary>
        public static OSTemplate CreateCustomTemplate()
        {
            return new OSTemplate
            {
                Name = "custom",
                DisplayName = "Custom ISO",
                Description = "Use your own ISO file for maximum flexibility",
                Icon = "💿",
                Category = "Custom",
                RecommendedRAM = 1024,
                MinRAM = 512,
                RecommendedCPU = 2,
                RecommendedStorage = 20,
                MinStorage = 10,
                RecommendedGeneration = 1,
                UsePrebuiltImage = false,
                BaseImagePath = null,
                ISODownloadURL = null,
                Features = new List<string>
                {
                    "Complete control",
                    "Any OS supported",
                    "Flexible configuration",
                    "Advanced users"
                }
            };
        }

        /// <summary>
        /// Get templates by category
        /// </summary>
        public static List<OSTemplate> GetTemplatesByCategory(string category)
        {
            var allTemplates = GetAllTemplates();
            return allTemplates.FindAll(t => t.Category == category);
        }

        /// <summary>
        /// Get template by name
        /// </summary>
        public static OSTemplate GetTemplateByName(string name)
        {
            var allTemplates = GetAllTemplates();
            return allTemplates.Find(t => t.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
        }
    }
}