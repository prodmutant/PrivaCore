using System;
using System.Net.Sockets;
using System.Text;
using PROSCANNERCONT.ServiceDetection.Utils;
using PROSCANNERCONT.ServiceDetection.Models;

namespace PROSCANNERCONT.ServiceDetection.Scanners
{
    /// <summary>
    /// Scanner specifically for SMB1 protocol detection
    /// </summary>
    public class Smb1Scanner
    {
        private readonly string _ip;
        private readonly int _port;

        public Smb1Scanner(string ip, int port)
        {
            _ip = ip;
            _port = port;
        }

        /// <summary>
        /// Tests if the target server supports SMB1 protocol with straightforward detection
        /// </summary>
        /// <param name="versionInfo">Version information structure to update</param>
        /// <returns>True if the scan completed successfully, false if there was an error</returns>
        public bool TestSupport(ref SmbVersionInfo versionInfo)
        {
            try
            {
                using TcpClient client = new TcpClient();
                client.ReceiveTimeout = 5000;
                client.SendTimeout = 5000;

                // Connect with timeout
                IAsyncResult result = client.BeginConnect(_ip, _port, null, null);
                bool success = result.AsyncWaitHandle.WaitOne(3000, true);
                if (!success)
                {
                    Console.WriteLine("✖ Connection timeout during SMB1 test.");
                    return false;
                }
                client.EndConnect(result);

                using NetworkStream stream = client.GetStream();

                // NetBIOS Session Request
                Console.WriteLine("🔄 Sending NetBIOS session request...");
                byte[] sessionRequest = NetBiosUtils.BuildNetBIOSSessionRequest("MYCLIENT", "TARGET");
                stream.Write(sessionRequest, 0, sessionRequest.Length);
                byte[] sessionResp = new byte[4];

                int bytesRead = stream.Read(sessionResp, 0, sessionResp.Length);
                if (bytesRead < 4 || sessionResp[0] != 0x82)
                {
                    Console.WriteLine("✖ NetBIOS session failed. Received bytes: " + bytesRead);
                    return false;
                }

                Console.WriteLine("✓ NetBIOS session established.");

                // Send SMB1 Negotiate Request to check SMB1 support
                Console.WriteLine("🔄 Sending SMB1 Negotiate request...");
                byte[] negotiateRequest = BuildSmb1NegotiateRequest();
                stream.Write(negotiateRequest, 0, negotiateRequest.Length);

                byte[] smbResp = new byte[1024];
                bytesRead = stream.Read(smbResp, 0, smbResp.Length);

                if (bytesRead < 10)
                {
                    Console.WriteLine("✖ SMB Negotiate failed. Insufficient data received.");
                    return false;
                }

                Console.WriteLine($"✓ SMB Negotiate response received. ({bytesRead} bytes)");

                // Verify SMB signature in response
                if (smbResp[4] != 0xFF || smbResp[5] != (byte)'S' || smbResp[6] != (byte)'M' || smbResp[7] != (byte)'B')
                {
                    Console.WriteLine("✖ Invalid SMB response signature.");
                    return false;
                }

                // Check for SMB1 support from the negotiate response status
                uint negotiateStatus = (uint)(smbResp[12] | (smbResp[11] << 8) | (smbResp[10] << 16) | (smbResp[9] << 24));

                // SIMPLIFIED LOGIC: If we get status 0, SMB1 is supported
                if (negotiateStatus == 0)
                {
                    versionInfo.Smb1Supported = true;
                    Console.WriteLine("SMB1 protocol is ENABLED");

                    // Check capabilities in the response to determine if SMB2 might also be supported
                    DetectAdditionalCapabilities(smbResp, bytesRead, ref versionInfo);
                    return true;
                }

                // If status is not 0, we treat it as SMB1 disabled
                versionInfo.Smb1Supported = false;
                Console.WriteLine("SMB1 protocol is DISABLED (status: 0x" + negotiateStatus.ToString("X8") + ")");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error testing SMB1 support: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Checks for additional SMB capabilities in the SMB1 response
        /// </summary>
        private void DetectAdditionalCapabilities(byte[] response, int length, ref SmbVersionInfo versionInfo)
        {
            try
            {
                // Check for SMB2/3 dialect announcements in the SMB1 response
                // Extract selected dialect from response
                byte wordCount = response[32];
                if (wordCount >= 17) // For an SMB1 negotiate response with dialect selection
                {
                    // The server selected a dialect - check if it suggests SMB2 capabilities
                    uint capabilities = BitConverter.ToUInt32(response, 59);

                    // Check for extended security capability flag
                    bool hasExtendedSecurity = (capabilities & 0x80000000) != 0;

                    if (hasExtendedSecurity)
                    {
                        Console.WriteLine("Extended security capability detected (may also support SMB2)");
                    }

                    // Extract server info if available
                    if (length > 100)
                    {
                        int domainOffset = 100;
                        if (domainOffset < length)
                        {
                            string domain = NetBiosUtils.ReadNullTerminatedString(response, ref domainOffset);
                            if (!string.IsNullOrEmpty(domain))
                            {
                                Console.WriteLine($"Server domain: {domain}");
                            }
                        }
                    }
                }
            }
            catch
            {
                // Just ignore errors here since this is additional info
            }
        }

        /// <summary>
        /// Builds an SMB1 Negotiate Protocol Request
        /// </summary>
        private byte[] BuildSmb1NegotiateRequest()
        {
            // Correct SMB1 Negotiate Protocol Request
            byte[] ntLmDialect = Encoding.ASCII.GetBytes("NT LM 0.12");

            // Total buffer size calculation:
            // 4 (NetBIOS) + 32 (SMB Header) + 3 (Negotiate) + ntLmDialect.Length + 3 (prefix and suffix)
            int totalLength = 42 + ntLmDialect.Length;
            byte[] request = new byte[totalLength];

            // NetBIOS Session header
            request[0] = 0x00; // Message type
            request[1] = 0x00; // Reserved
            request[2] = (byte)((totalLength - 4) >> 8); // Length high byte
            request[3] = (byte)((totalLength - 4) & 0xFF); // Length low byte

            // SMB Header
            request[4] = 0xFF; // SMB
            request[5] = (byte)'S';
            request[6] = (byte)'M';
            request[7] = (byte)'B';
            request[8] = 0x72; // Negotiate Protocol

            // Set Flags
            request[9] = 0x00; // NT Status (32-bits)
            request[10] = 0x00;
            request[11] = 0x00;
            request[12] = 0x00;
            request[13] = 0x18; // Flags
            request[14] = 0x01; // Flags2 high byte
            request[15] = 0x28; // Flags2 low byte (Unicode)

            // Process ID, User ID, Tree ID, Multiplex ID
            request[16] = 0x00; // PID High
            request[17] = 0x00;
            request[18] = 0x00; // Signature
            request[19] = 0x00;
            request[20] = 0x00;
            request[21] = 0x00;
            request[22] = 0x00; // Reserved
            request[23] = 0x00;
            request[24] = 0x00; // TID
            request[25] = 0x00;
            request[26] = 0x00; // PID low
            request[27] = 0x00;
            request[28] = 0x00; // UID
            request[29] = 0x00;
            request[30] = 0x00; // MID
            request[31] = 0x00;

            // SMB Negotiate
            request[32] = 0x00; // Word count
            int byteCount = ntLmDialect.Length + 2; // +2 for dialect prefix and null terminator
            request[33] = (byte)(byteCount & 0xFF); // Byte count low
            request[34] = (byte)(byteCount >> 8);   // Byte count high

            // Dialect: NT LM 0.12
            request[35] = 0x02; // Dialect format - null terminated
            Array.Copy(ntLmDialect, 0, request, 36, ntLmDialect.Length);
            request[36 + ntLmDialect.Length] = 0x00; // Null terminator

            return request;
        }
    }
}