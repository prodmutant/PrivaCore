using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.PortScanProtocols
{
    public interface IPortScanner
    {
        Task<PortScanResult> ScanPortAsync(string ipAddress, int port, int timeout, CancellationToken cancellationToken);
        bool RequiresElevatedPrivileges { get; }
        string ScannerName { get; }
    }
}