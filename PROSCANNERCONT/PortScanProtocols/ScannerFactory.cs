using PROSCANNERCONT.PortScanProtocols;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.port_scan_protocols
{
    public class ScannerFactory
    {
        private static readonly Dictionary<string, IPortScanner> scanners = new()
    {
        { "TCP Connect Scan (-sT)", new TcpConnectScanner() },
        { "TCP SYN Scan (-sS)", new TcpSynScanner() },
        { "TCP ACK Scan (-sA)", new TcpAckScanner() },
        { "TCP FIN Scan (-sF)", new TcpFinScanner() },
        { "TCP XMAS Scan (-sX)", new TcpXmasScanner() },
        { "UDP Scan (-sU)", new UdpScanner() }
    };

        public static IPortScanner GetScanner(string scanType)
        {
            if (scanners.TryGetValue(scanType, out var scanner))
            {
                return scanner;
            }
            throw new ArgumentException($"Unknown scan type: {scanType}");
        }

        public static IEnumerable<string> AvailableScanTypes => scanners.Keys;
    }
}
