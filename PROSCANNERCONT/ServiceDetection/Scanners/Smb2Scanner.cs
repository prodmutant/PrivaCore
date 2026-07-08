using System;
using System.Net.Sockets;
using System.Text;
using PROSCANNERCONT.ServiceDetection.Utils;
using PROSCANNERCONT.ServiceDetection.Models;

namespace PROSCANNERCONT.ServiceDetection.Scanners
{
    /// <summary>
    /// Scanner specifically for SMB2 protocol detection
    /// </summary>
    public class Smb2Scanner
    {
        private readonly string _ip;
        private readonly int _port;

        public Smb2Scanner(string ip, int port)
        {
            _ip = ip;
            _port = port;
        }

        /// <summary>
        /// Tests if the target server supports SMB2 protocol
        /// </summary>
        /// <param name="versionInfo">Version information structure to update</param>
        /// <returns>True if the scan completed successfully, false if there was an error</returns>
        public bool TestSupport(ref SmbVersionInfo versionInfo)
        {
            try
            {
                Console.WriteLine("🔄 Testing for SMB2 protocol support...");

                using TcpClient client = new TcpClient();
                client.ReceiveTimeout = 5000;
                client.SendTimeout = 5000;

                // Connect with timeout
                IAsyncResult result = client.BeginConnect(_ip, _port, null, null);
                bool success = result.AsyncWaitHandle.WaitOne(3000, true);
                if (!success)
                {
                    Console.WriteLine("✖ Connection timeout during SMB2 test.");
                    return false;
                }
                client.EndConnect(result);

                using NetworkStream stream = client.GetStream();

                // NetBIOS Session Request
                byte[] sessionRequest = NetBiosUtils.BuildNetBIOSSessionRequest("MYCLIENT", "TARGET");
                stream.Write(sessionRequest, 0, sessionRequest.Length);
                byte[] sessionResp = new byte[4];

                int bytesRead = stream.Read(sessionResp, 0, sessionResp.Length);
                if (bytesRead < 4 || sessionResp[0] != 0x82)
                {
                    Console.WriteLine("✖ NetBIOS session failed in SMB2 test.");
                    return false;
                }

                // Send SMB2 Negotiate Request
                byte[] negotiateRequest = BuildSmb2NegotiateRequest();
                stream.Write(negotiateRequest, 0, negotiateRequest.Length);

                byte[] smbResp = new byte[1024];
                bytesRead = stream.Read(smbResp, 0, smbResp.Length);

                if (bytesRead < 64)
                {
                    Console.WriteLine("✖ SMB2 Negotiate test failed. Insufficient data received.");
                    return false;
                }

                // Check for SMB2 protocol signature - FE SMB
                if (smbResp[4] == 0xFE && smbResp[5] == (byte)'S' && smbResp[6] == (byte)'M' && smbResp[7] == (byte)'B')
                {
                    // Check status code
                    uint status = BitConverter.ToUInt32(smbResp, 12);

                    if (status == 0) // SUCCESS
                    {
                        Console.WriteLine("SMB2 protocol is ENABLED");
                        versionInfo.Smb2Supported = true;

                        // Try to identify the specific SMB version selected by the server
                        if (bytesRead >= 72)
                        {
                            // The dialect is at offset 70-71 in a successful SMB2 negotiate response
                            ushort dialect = BitConverter.ToUInt16(smbResp, 70);

                            switch (dialect)
                            {
                                case 0x0202:
                                    Console.WriteLine("Server selected SMB 2.0.2");
                                    versionInfo.HighestVersion = new Version(2, 0, 2);
                                    break;
                                case 0x0210:
                                    Console.WriteLine("Server selected SMB 2.1");
                                    versionInfo.HighestVersion = new Version(2, 1, 0);
                                    break;
                                case 0x0300:
                                    Console.WriteLine("Server selected SMB 3.0");
                                    versionInfo.Smb3Supported = true;
                                    versionInfo.HighestVersion = new Version(3, 0, 0);
                                    break;
                                case 0x0302:
                                    Console.WriteLine("Server selected SMB 3.0.2");
                                    versionInfo.Smb3Supported = true;
                                    versionInfo.HighestVersion = new Version(3, 0, 2);
                                    break;
                                case 0x0311:
                                    Console.WriteLine("Server selected SMB 3.1.1");
                                    versionInfo.Smb3Supported = true;
                                    versionInfo.HighestVersion = new Version(3, 1, 1);
                                    break;
                                default:
                                    Console.WriteLine($"Server selected unknown SMB dialect: 0x{dialect:X4}");
                                    break;
                            }
                        }
                    }
                    else
                    {
                        // Non-zero status means there was an error
                        Console.WriteLine($"SMB2 protocol is DISABLED (status: 0x{status:X8})");
                        versionInfo.Smb2Supported = false;
                    }

                    return true;
                }
                else
                {
                    Console.WriteLine("SMB2 protocol is DISABLED");
                    versionInfo.Smb2Supported = false;
                    return true;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error testing SMB2 support: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Builds an SMB2 Negotiate Protocol Request
        /// </summary>
        private byte[] BuildSmb2NegotiateRequest()
        {
            // Create an SMB2 Negotiate Protocol Request with dialect SMB 2.0.2, 2.1, 3.0, 3.0.2 and 3.1.1
            byte[] smb2Request = new byte[] {
                // NetBIOS Header (4 bytes)
                0x00, 0x00, 0x00, 0x9C,  // Length: 156 bytes (excluding this header)
                
                // SMB2 Header (64 bytes)
                0xFE, 0x53, 0x4D, 0x42,  // ProtocolId: 0xFE, 'S', 'M', 'B'
                0x40, 0x00,              // StructureSize: 64
                0x00, 0x00,              // CreditCharge: 0
                0x00, 0x00,              // Status: 0
                0x00, 0x00,              // Command: NEGOTIATE (0)
                0x00, 0x00,              // Credits: 0
                0x00, 0x00, 0x00, 0x00,  // Flags: 0
                0x00, 0x00, 0x00, 0x00,  // NextCommand: 0
                0x01, 0x00, 0x00, 0x00,  // MessageId: 1
                0x00, 0x00, 0x00, 0x00,  // Reserved: 0
                0x00, 0x00, 0x00, 0x00,  // TreeId: 0
                0x00, 0x00, 0x00, 0x00,  // SessionId: 0
                0x00, 0x00, 0x00, 0x00,  // Signature: All zeros
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                
                // Negotiate Request (36 bytes)
                0x24, 0x00,              // StructureSize: 36
                0x05, 0x00,              // DialectCount: 5
                0x01, 0x00,              // SecurityMode: 1 (signing enabled)
                0x00, 0x00,              // Reserved: 0
                0x7F, 0x00, 0x00, 0x00,  // Capabilities: 0x7F
                0x01, 0x02, 0xAB, 0xCD,  // ClientGuid: Random GUID (part 1)
                0x01, 0x02, 0xAB, 0xCD,  // ClientGuid: Random GUID (part 2)
                0x01, 0x02, 0xAB, 0xCD,  // ClientGuid: Random GUID (part 3)
                0x01, 0x02, 0xAB, 0xCD,  // ClientGuid: Random GUID (part 4)
                0x78, 0x00,              // NegotiateContextOffset: 120
                0x00, 0x00,              // NegotiateContextCount: 0
                0x00, 0x00,              // Reserved2: 0
                
                // Dialects (10 bytes)
                0x02, 0x02,              // Dialect: 0x0202 (SMB 2.0.2)
                0x10, 0x02,              // Dialect: 0x0210 (SMB 2.1)
                0x00, 0x03,              // Dialect: 0x0300 (SMB 3.0)
                0x02, 0x03,              // Dialect: 0x0302 (SMB 3.0.2)
                0x11, 0x03,              // Dialect: 0x0311 (SMB 3.1.1)
                
                // Padding to make dialects 8-byte aligned (6 bytes of zeros)
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            };

            return smb2Request;
        }
    }
}