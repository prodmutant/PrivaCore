using System.Threading;
using System.Threading.Tasks;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.ServiceDetection
{
    /// <summary>
    /// Interface for service detection components
    /// Each detector specializes in identifying and fingerprinting a specific type of service
    /// </summary>
    public interface IServiceDetector
    {
        /// <summary>
        /// Name of the service this detector handles
        /// </summary>
        string ServiceName { get; }

        /// <summary>
        /// Common ports this service typically runs on
        /// </summary>
        int[] CommonPorts { get; }

        /// <summary>
        /// Priority of this detector (lower values = higher priority)
        /// </summary>
        int Priority { get; }

        /// <summary>
        /// Checks if this detector can handle detection for the given port and initial scan result
        /// </summary>
        /// <param name="port">Port number</param>
        /// <param name="initialScan">Initial port scan result</param>
        /// <returns>True if this detector can handle this service</returns>
        bool CanDetect(int port, PortScanResult initialScan);

        /// <summary>
        /// Detects service details for an open port
        /// </summary>
        /// <param name="result">The initial port scan result to enhance</param>
        /// <param name="timeout">Timeout in milliseconds</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Enhanced port scan result with service details</returns>
        Task<PortScanResult> DetectAsync(PortScanResult result, int timeout = 5000, CancellationToken cancellationToken = default);
    }
}