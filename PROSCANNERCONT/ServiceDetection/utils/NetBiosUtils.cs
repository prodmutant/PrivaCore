using System;
using System.Text;

namespace PROSCANNERCONT.ServiceDetection.Utils
{
    /// <summary>
    /// Utility class for handling NetBIOS protocol functionality
    /// </summary>
    public static class NetBiosUtils
    {
        /// <summary>
        /// Build a NetBIOS session request packet
        /// </summary>
        public static byte[] BuildNetBIOSSessionRequest(string clientName, string serverName)
        {
            byte[] calledName = EncodeNetBIOSName(serverName);
            byte[] callingName = EncodeNetBIOSName(clientName);
            byte[] payload = new byte[calledName.Length + callingName.Length + 4];
            payload[0] = 0x81; // Session Request
            payload[1] = 0x00;
            ushort length = (ushort)(payload.Length - 4);
            payload[2] = (byte)((length >> 8) & 0xFF);
            payload[3] = (byte)(length & 0xFF);
            Array.Copy(calledName, 0, payload, 4, calledName.Length);
            Array.Copy(callingName, 0, payload, 4 + calledName.Length, callingName.Length);
            return payload;
        }

        /// <summary>
        /// Encode a name for NetBIOS (using ASCII encoding + padding)
        /// </summary>
        public static byte[] EncodeNetBIOSName(string name)
        {
            // Pad to 15 characters with spaces
            name = name.PadRight(15).ToUpper();
            byte[] result = new byte[34];
            result[0] = 0x20; // NetBIOS name type
            for (int i = 0; i < 16; i++)
            {
                byte b = i < name.Length ? (byte)name[i] : (byte)' ';
                byte high = (byte)(((b >> 4) & 0x0F) + 'A');
                byte low = (byte)((b & 0x0F) + 'A');
                result[1 + (i * 2)] = high;
                result[1 + (i * 2) + 1] = low;
            }
            result[33] = 0x00; // Null terminator
            return result;
        }

        /// <summary>
        /// Reads a null-terminated string from a byte array
        /// </summary>
        public static string ReadNullTerminatedString(byte[] data, ref int offset)
        {
            int start = offset;
            while (offset < data.Length && data[offset] != 0x00)
                offset++;
            if (start >= offset) return string.Empty;
            string result = Encoding.ASCII.GetString(data, start, offset - start);
            offset++; // Skip null
            return result;
        }

        /// <summary>
        /// Gets an ASCII representation of a byte array for debugging
        /// </summary>
        public static string GetAsciiRepresentation(byte[] data, int offset, int length)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < length; i++)
            {
                byte b = data[offset + i];
                sb.Append(b >= 32 && b <= 126 ? (char)b : '.');
            }
            return sb.ToString();
        }

        /// <summary>
        /// Helper to print a hexdump of a byte array for debugging
        /// </summary>
        public static void PrintHexDump(byte[] data, int length)
        {
            Console.WriteLine("Hexdump:");
            for (int i = 0; i < length; i += 16)
            {
                int lineLength = Math.Min(16, length - i);
                Console.WriteLine($"{i:X4}: {BitConverter.ToString(data, i, lineLength).Replace("-", " ")}");
            }
        }
    }
}