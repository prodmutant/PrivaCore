using System;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PROSCANNERCONT.ServiceDetection.Utils
{
    public static class BannerGrabber
    {
        public static async Task<string?> GrabBannerAsync(
            string ipAddress,
            int port,
            int timeout = 5000,
            CancellationToken cancellationToken = default)
        {
            try
            {
                using var client = new TcpClient();

                var connectTask = client.ConnectAsync(ipAddress, port);
                if (await Task.WhenAny(connectTask, Task.Delay(timeout, cancellationToken)) != connectTask)
                    return null;

                if (!client.Connected)
                    return null;

                using var stream = client.GetStream();
                stream.ReadTimeout = timeout;

                if (port == 139)
                {
                    return await HandleNetBIOS139BannerAsync(stream, cancellationToken);
                }
                else if (port == 445)
                {
                    return await HandleSMB445BannerAsync(stream, cancellationToken);
                }

                byte[] buffer = new byte[4096];
                var readTask = stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);

                if (await Task.WhenAny(readTask, Task.Delay(timeout, cancellationToken)) != readTask)
                    return null;

                int bytesRead = await readTask;
                if (bytesRead > 0)
                {
                    if (port == 23)
                        return HandleTelnetData(buffer, bytesRead);

                    return TryDecodeBuffer(buffer, bytesRead);
                }

                return null;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error in banner grab: {ex.Message}");
                return null;
            }
        }

        public static async Task<string?> GrabBannerWithTriggerAsync(
            string ipAddress,
            int port,
            byte[] trigger,
            int timeout = 5000,
            CancellationToken cancellationToken = default)
        {
            try
            {
                using var client = new TcpClient();
                var connectTask = client.ConnectAsync(ipAddress, port);

                if (await Task.WhenAny(connectTask, Task.Delay(timeout, cancellationToken)) != connectTask)
                    return null;

                if (!client.Connected)
                    return null;

                using var stream = client.GetStream();
                stream.ReadTimeout = timeout;

                await stream.WriteAsync(trigger, 0, trigger.Length, cancellationToken);
                await stream.FlushAsync(cancellationToken);

                await Task.Delay(200, cancellationToken);

                byte[] buffer = new byte[4096];
                var readTask = stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);

                if (await Task.WhenAny(readTask, Task.Delay(timeout, cancellationToken)) != readTask)
                    return null;

                int bytesRead = await readTask;
                if (bytesRead > 0)
                {
                    if (port == 23)
                        return HandleTelnetData(buffer, bytesRead);

                    return TryDecodeBuffer(buffer, bytesRead);
                }

                return null;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error in banner grab with trigger: {ex.Message}");
                return null;
            }
        }

        private static async Task<string?> HandleNetBIOS139BannerAsync(NetworkStream stream, CancellationToken cancellationToken)
        {
            byte[] sessionRequest = new byte[]
            {
                0x81, 0x00, 0x00, 0x44,
                0x20, (byte)'A', (byte)'N', (byte)'Y', (byte)'H', (byte)'O', (byte)'S', (byte)'T',
                0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                0x00, 0x20, (byte)'S', (byte)'E', (byte)'R', (byte)'V', (byte)'I', (byte)'C', (byte)'E',
                0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                0x00
            };

            await stream.WriteAsync(sessionRequest, 0, sessionRequest.Length, cancellationToken);
            await stream.FlushAsync(cancellationToken);

            byte[] buffer = new byte[4096];
            int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);

            return ParseNetBIOSResponse(buffer, bytesRead);
        }

        private static async Task<string?> HandleSMB445BannerAsync(NetworkStream stream, CancellationToken cancellationToken)
        {
            byte[] smbNegotiate = new byte[]
            {
                0x00, 0x00, 0x00, 0x85,
                0xFF, 0x53, 0x4D, 0x42,
                0x72, 0x00, 0x00, 0x00, 0x00, 0x18, 0x53, 0xC8,
                0x00, 0x26, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x0C, 0x00, 0x02, 0x4C, 0x41, 0x4E, 0x4D, 0x41,
                0x4E, 0x31, 0x2E, 0x30, 0x00, 0x02, 0x4C, 0x4D,
                0x31, 0x2E, 0x32, 0x58, 0x30, 0x30, 0x32, 0x00,
                0x02, 0x4E, 0x54, 0x20, 0x4C, 0x4D, 0x20, 0x30,
                0x2E, 0x31, 0x32, 0x00
            };

            await stream.WriteAsync(smbNegotiate, 0, smbNegotiate.Length, cancellationToken);
            await stream.FlushAsync(cancellationToken);

            byte[] buffer = new byte[4096];
            int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);

            return ParseNetBIOSResponse(buffer, bytesRead);
        }

        private static string? ParseNetBIOSResponse(byte[] buffer, int bytesRead)
        {
            if (bytesRead == 0) return null;

            try
            {
                string raw = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                if (raw.Contains("Microsoft"))
                {
                    int start = raw.IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase);
                    int end = raw.IndexOf('\0', start);
                    string version = raw.Substring(start, end > start ? end - start : raw.Length - start);
                    return version.Trim();
                }

                return CleanBannerString(raw);
            }
            catch
            {
                return BitConverter.ToString(buffer, 0, bytesRead);
            }
        }

        private static string TryDecodeBuffer(byte[] buffer, int bytesRead)
        {
            try
            {
                return CleanBannerString(Encoding.UTF8.GetString(buffer, 0, bytesRead));
            }
            catch
            {
                try
                {
                    return CleanBannerString(Encoding.ASCII.GetString(buffer, 0, bytesRead));
                }
                catch
                {
                    return $"Binary data: {BitConverter.ToString(buffer, 0, bytesRead)}";
                }
            }
        }



        private static string HandleTelnetData(byte[] buffer, int bytesRead)
        {
            try
            {
                string cleanedData = CleanTelnetBanner(buffer, bytesRead);
                return !string.IsNullOrWhiteSpace(cleanedData) && !cleanedData.Contains("?")
                    ? cleanedData
                    : "Telnet Service";
            }
            catch
            {
                return "Telnet Service";
            }
        }

        private static string CleanTelnetBanner(byte[] buffer, int bytesRead)
        {
            var sb = new StringBuilder();

            const byte IAC = 255;
            const byte WILL = 251;
            const byte WONT = 252;
            const byte DO = 253;
            const byte DONT = 254;
            const byte SB = 250;
            const byte SE = 240;

            for (int i = 0; i < bytesRead; i++)
            {
                byte b = buffer[i];

                if (b == IAC && i + 1 < bytesRead)
                {
                    byte cmd = buffer[i + 1];
                    if (cmd == IAC) { i++; continue; }
                    if (cmd == WILL || cmd == WONT || cmd == DO || cmd == DONT) { i += 2; continue; }
                    if (cmd == SB)
                    {
                        i += 2;
                        while (i < bytesRead - 1)
                        {
                            if (buffer[i] == IAC && buffer[i + 1] == SE)
                            {
                                i++;
                                break;
                            }
                            i++;
                        }
                        continue;
                    }
                    i++;
                    continue;
                }

                if ((b >= 32 && b <= 126) || b == '*' || b == '/' || b == 13 || b == 10)
                {
                    sb.Append((char)b);
                }
            }

            string result = sb.ToString().Trim();
            while (result.Contains("  ")) result = result.Replace("  ", " ");
            while (result.Contains("\r\n\r\n")) result = result.Replace("\r\n\r\n", "\r\n");

            return result;
        }

        private static string CleanBannerString(string banner)
        {
            if (string.IsNullOrEmpty(banner)) return string.Empty;

            var sb = new StringBuilder();
            foreach (char c in banner)
            {
                if (char.IsLetterOrDigit(c) || char.IsPunctuation(c) || char.IsWhiteSpace(c) || char.IsSymbol(c))
                {
                    sb.Append(c);
                }
            }

            string result = sb.ToString().Trim();

            const int maxLength = 1024;
            if (result.Length > maxLength)
                result = result.Substring(0, maxLength) + "...";

            return result;
        }

        public static async Task<string> GrabBannerFromStreamAsync(NetworkStream stream, int timeout = 3000)
        {
            var buffer = new byte[1024];
            var sb = new StringBuilder();
            using var cts = new CancellationTokenSource(timeout);

            try
            {
                while (!cts.IsCancellationRequested && stream.DataAvailable)
                {
                    int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cts.Token);
                    if (bytesRead <= 0) break;
                    sb.Append(Encoding.ASCII.GetString(buffer, 0, bytesRead));
                }
            }
            catch
            {
                // Ignore timeout or read errors
            }

            return sb.ToString().Trim();
        }


        public static string GetFirstLine(string banner)
        {
            if (string.IsNullOrEmpty(banner))
                return string.Empty;

            var lines = banner.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            return lines.Length > 0 ? lines[0].Trim() : string.Empty;
        }
    }
}
