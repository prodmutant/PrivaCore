using System;

namespace PROSCANNERCONT.ServiceDetection.Models
{
    /// <summary>
    /// Structure to hold information about SMB version support
    /// </summary>
    public struct SmbVersionInfo
    {
        public bool Smb1Supported;
        public bool Smb2Supported;
        public bool Smb3Supported;
        public Version HighestVersion;

        /// <summary>
        /// Helper to get the highest detected SMB version as string
        /// </summary>
        /// <returns>String representation of the highest SMB version detected</returns>
        public string GetHighestVersionString()
        {
            if (Smb3Supported) return "SMB 3.x";
            if (Smb2Supported) return "SMB 2.x";
            if (Smb1Supported) return "SMB 1.0";
            return "Unknown";
        }

        /// <summary>
        /// Gets a comprehensive version summary for display
        /// </summary>
        /// <returns>Detailed version information string</returns>
        public string GetVersionSummary()
        {
            var versions = new List<string>();

            if (Smb1Supported)
                versions.Add("SMB1");

            if (Smb2Supported)
                versions.Add("SMB2");

            if (Smb3Supported)
                versions.Add("SMB3");

            if (versions.Count == 0)
                return "No SMB support detected";

            string result = string.Join(", ", versions);

            if (HighestVersion != null)
                result += $" (highest: v{HighestVersion})";

            return result;
        }

        /// <summary>
        /// Checks if any SMB protocol is supported
        /// </summary>
        /// <returns>True if at least one SMB version is supported</returns>
        public bool HasSmbSupport => Smb1Supported || Smb2Supported || Smb3Supported;

        /// <summary>
        /// Determines if the configuration is secure (SMB1 disabled)
        /// </summary>
        /// <returns>True if SMB1 is disabled and SMB2/3 are available</returns>
        public bool IsSecureConfiguration => !Smb1Supported && (Smb2Supported || Smb3Supported);
    }
}