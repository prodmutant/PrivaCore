using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.ServiceDetection.Detectors;
using PROSCANNERCONT.ServiceDetection; // Needed to recognize IServiceDetector



namespace PROSCANNERCONT.ServiceDetection
{
    public class ServiceDetectionManager
    {
        private readonly List<IServiceDetector> _detectors;
        private readonly ILogger<ServiceDetectionManager> _logger;

        public ServiceDetectionManager(ILogger<ServiceDetectionManager> logger)
        {
            _logger = logger;
            _detectors = new List<IServiceDetector>();
            var loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());

            // Register all detectors
            _detectors.Add(new HttpDetector());
            _detectors.Add(new SshDetector());
            _detectors.Add(new FtpDetector());
            _detectors.Add(new SmtpDetector(loggerFactory.CreateLogger<SmtpDetector>())); // Ensure SMTP has logging
            _detectors.Add(new TelnetDetector());
            _detectors.Add(new DnsDetector(loggerFactory.CreateLogger<DnsDetector>())); // Add DNS detector with logging
            _detectors.Add(new DatabaseDetector());
            _detectors.Add(new RpcDetector(loggerFactory.CreateLogger<RpcDetector>()));
            _detectors.Add(new NetBIOSDetector(loggerFactory.CreateLogger<NetBIOSDetector>()));
            _detectors.Add(new CcproxyDetector(loggerFactory.CreateLogger<CcproxyDetector>()));
            _detectors.Add(new MySqlDetector(loggerFactory.CreateLogger<MySqlDetector>()));
            _detectors.Add(new DistccdDetector(loggerFactory.CreateLogger<DistccdDetector>()));
            _detectors.Add(new PostgreSqlDetector(loggerFactory.CreateLogger<PostgreSqlDetector>()));
            _detectors.Add(new VncDetector(loggerFactory.CreateLogger<VncDetector>()));
            _detectors.Add(new X11Detector(loggerFactory.CreateLogger<X11Detector>()));
            _detectors.Add(new IRC6697Detector(loggerFactory.CreateLogger<IRC6697Detector>()));
            _detectors.Add(new IRCDetector(loggerFactory.CreateLogger<IRCDetector>()));



            // Add generic detector as fallback
            _detectors.Add(new GenericDetector());

            // Sort by priority (lower values first)
            _detectors = _detectors.OrderBy(d => d.Priority).ToList();
        }

        public async Task<PortScanResult> DetectServiceAsync(
            PortScanResult result,
            int timeout = 5000,
            CancellationToken cancellationToken = default)
        {
            if (!result.IsOpen && result.Status != "Open" && result.Status != "Open|Filtered")
            {
                return result;
            }

            try
            {
                var applicableDetectors = _detectors
                    .Where(d => d.CanDetect(result.Port, result))
                    .ToList();

                if (!applicableDetectors.Any())
                {
                    _logger.LogWarning($"No specific detectors found for Port {result.Port}. Using generic detector.");
                    var generic = _detectors.LastOrDefault();
                    return generic != null ? await generic.DetectAsync(result, timeout, cancellationToken) : result;
                }

                foreach (var detector in applicableDetectors)
                {
                    try
                    {
                        _logger.LogInformation($"Using {detector.ServiceName} Detector on Port {result.Port}");

                        var enhancedResult = await detector.DetectAsync(result, timeout, cancellationToken);

                        if (!string.IsNullOrEmpty(enhancedResult.Version) && enhancedResult.Version != "Unknown")
                        {
                            _logger.LogInformation($"Detection Success: {enhancedResult.Service} {enhancedResult.Version}");
                            return enhancedResult;
                        }
                        else
                        {
                            _logger.LogWarning($"Detector {detector.ServiceName} did not retrieve a version for Port {result.Port}.");
                        }

                        if (string.IsNullOrEmpty(result.Service) && !string.IsNullOrEmpty(enhancedResult.Service))
                        {
                            result.Service = enhancedResult.Service;
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, $"Error in {detector.ServiceName} detector.");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error in service detection.");
            }

            return result;
        }
    }
}