using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Concurrent;

namespace PROSCANNERCONT.Views
{
    internal class Utils
    {
        public static uint IpToUint(IPAddress ip)
        {
            byte[] bytes = ip.GetAddressBytes();
            return (uint)(bytes[0] << 24) + (uint)(bytes[1] << 16) + (uint)(bytes[2] << 8) + bytes[3];
        }
        public static IPAddress UintToIp(uint ip)
        {
            byte[] bytes = new byte[4];
            bytes[0] = (byte)(ip >> 24);
            bytes[1] = (byte)(ip >> 16);
            bytes[2] = (byte)(ip >> 8);
            bytes[3] = (byte)ip;
            return new IPAddress(bytes);
        }
    }
}
