using System;
using System.IO;
using Serilog;
using Serilog.Events;
using PROSCANNERCONT.Utils;

namespace PROSCANNERCONT.Services
{
    /// <summary>
    /// Single static facade over Serilog. Forensic-grade logs are essential for
    /// a security tool: every IDS alert path, scan event, and config change
    /// should be traceable post-incident. Logs land in
    /// %APPDATA%\PrivaCore\logs\privacore-YYYYMMDD.log with daily rotation,
    /// 30-file retention, and structured JSON-ish output. Debug output mirrors
    /// to the IDE debug pane so existing Debug.WriteLine flows keep working.
    /// </summary>
    public static class AppLogger
    {
        private static readonly Lazy<ILogger> _logger = new(Build);
        public static ILogger Log => _logger.Value;
        public static bool IsInitialized => _logger.IsValueCreated;

        private static ILogger Build()
        {
            try
            {
                var logsDir = Path.Combine(AppConstants.Paths.AppDataDir, "logs");
                Directory.CreateDirectory(logsDir);
                var path = Path.Combine(logsDir, "privacore-.log");

                return new LoggerConfiguration()
                    .MinimumLevel.Information()
                    .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
                    .WriteTo.File(
                        path,
                        rollingInterval: RollingInterval.Day,
                        retainedFileCountLimit: 30,
                        fileSizeLimitBytes: 25_000_000,
                        outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff} [{Level:u3}] {SourceContext}: {Message:lj}{NewLine}{Exception}")
                    .WriteTo.Debug()
                    .Enrich.WithProperty("App", "PrivaCore")
                    .Enrich.WithProperty("Version", UpdateCheckerService.CurrentVersion)
                    .CreateLogger();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[AppLogger.Build] Failed to init Serilog: {ex.Message}");
                // Bare console sink keeps the API alive even if file sink fails.
                return new LoggerConfiguration().WriteTo.Debug().CreateLogger();
            }
        }

        public static ILogger For<T>() => Log.ForContext<T>();
        public static ILogger For(string source) => Log.ForContext("SourceContext", source);

        public static void Shutdown()
        {
            try { (Log as IDisposable)?.Dispose(); } catch { }
        }
    }
}
