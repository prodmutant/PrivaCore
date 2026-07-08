using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.ServiceDetection.Utils
{
    public static class ResultTracker
    {
        private static readonly Dictionary<string, List<string>> _resultHistory = new();

        /// <summary>
        /// Track who modified a result
        /// </summary>
        public static void Track(this PortScanResult result, string action,
            [CallerMemberName] string memberName = "",
            [CallerFilePath] string sourceFilePath = "",
            [CallerLineNumber] int sourceLineNumber = 0)
        {
            var key = $"{result.IPAddress}:{result.Port}";
            var className = System.IO.Path.GetFileNameWithoutExtension(sourceFilePath);
            var timestamp = DateTime.Now.ToString("HH:mm:ss.fff");

            var entry = $"[{timestamp}] {className}.{memberName}:{sourceLineNumber} - {action} " +
                       $"Service='{result.Service}' Version='{result.Version}'";

            if (!_resultHistory.ContainsKey(key))
                _resultHistory[key] = new List<string>();

            _resultHistory[key].Add(entry);

            // Also log to console
            Console.WriteLine($"TRACK: {entry}");
        }

        /// <summary>
        /// Get the full history for a result
        /// </summary>
        public static List<string> GetHistory(string ipAddress, int port)
        {
            var key = $"{ipAddress}:{port}";
            return _resultHistory.ContainsKey(key) ? _resultHistory[key] : new List<string>();
        }

        /// <summary>
        /// Print the history for debugging
        /// </summary>
        public static void PrintHistory(string ipAddress, int port)
        {
            var history = GetHistory(ipAddress, port);
            Console.WriteLine($"\n=== RESULT HISTORY for {ipAddress}:{port} ===");
            foreach (var entry in history)
            {
                Console.WriteLine(entry);
            }
            Console.WriteLine("=== END HISTORY ===\n");
        }

        /// <summary>
        /// Clear history (call this at start of new scan)
        /// </summary>
        public static void ClearHistory()
        {
            _resultHistory.Clear();
        }
    }

    public static class PortScanResultExtensions
    {

        /// <summary>
        /// Extension method to track changes to Service property
        /// </summary>
        public static void SetService(this PortScanResult result, string service,
            [CallerMemberName] string memberName = "",
            [CallerFilePath] string sourceFilePath = "",
            [CallerLineNumber] int sourceLineNumber = 0)
        {
            var oldValue = result.Service;
            result.Service = service;

            var className = System.IO.Path.GetFileNameWithoutExtension(sourceFilePath);
            result.Track($"SetService: '{oldValue}' -> '{service}'", memberName, sourceFilePath, sourceLineNumber);
        }

        /// <summary>
        /// Extension method to track changes to Version property
        /// </summary>
        public static void SetVersion(this PortScanResult result, string version,
            [CallerMemberName] string memberName = "",
            [CallerFilePath] string sourceFilePath = "",
            [CallerLineNumber] int sourceLineNumber = 0)
        {
            var oldValue = result.Version;
            result.Version = version;

            var className = System.IO.Path.GetFileNameWithoutExtension(sourceFilePath);
            result.Track($"SetVersion: '{oldValue}' -> '{version}'", memberName, sourceFilePath, sourceLineNumber);
        }
    }
}