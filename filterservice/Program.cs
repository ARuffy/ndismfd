using Microsoft.Win32.SafeHandles;
using System;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

class Program
{
    const uint FILE_DEVICE_PHYSICAL_NETCARD = 0x00000017;
    const uint METHOD_BUFFERED = 0;
    const uint FILE_ANY_ACCESS = 0;

    // Replace with your driver's IOCTL code
    static uint CTL_CODE(uint deviceType, uint function, uint method, uint access) =>
        ((deviceType << 16) | (access << 14) | (function << 2) | method);

    static readonly uint IOCTL_FILTER_ENUMERATE_ALL_INSTANCES =
        CTL_CODE(FILE_DEVICE_PHYSICAL_NETCARD, 2, METHOD_BUFFERED, FILE_ANY_ACCESS);
    static readonly uint IOCTL_FILTER_MODIFY_BLOCK_TABLE =
        CTL_CODE(FILE_DEVICE_PHYSICAL_NETCARD, 8, METHOD_BUFFERED, FILE_ANY_ACCESS);
    static readonly uint IOCTL_FILTER_GET_ALL_PACKAGES =
        CTL_CODE(FILE_DEVICE_PHYSICAL_NETCARD, 9, METHOD_BUFFERED, FILE_ANY_ACCESS);

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    struct FILTER_BLOCK_TABLE_ENTRY
    {
        public uint IpAddr;
        public ushort Port;
        public ushort BlockType;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    static extern SafeFileHandle CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DeviceIoControl(
        SafeFileHandle hDevice,
        uint dwIoControlCode,
        IntPtr lpInBuffer,
        uint nInBufferSize,
        [Out] byte[] lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped);

    public static void SendBlockTableIoctl(SafeFileHandle device, string ipAddr, ushort port)
    {
        var ip = BitConverter.ToUInt32(IPAddress.Parse(ipAddr).GetAddressBytes(), 0);
        FILTER_BLOCK_TABLE_ENTRY blockEntry = new FILTER_BLOCK_TABLE_ENTRY
        {
            IpAddr = ip,
            Port = port,
            BlockType = 0
        };

        uint entryCount = 1;
        int structSize = Marshal.SizeOf<FILTER_BLOCK_TABLE_ENTRY>();
        byte[] buffer = new byte[sizeof(uint) + structSize * entryCount];
        var bufferHandle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
        var pBuffer = bufferHandle.AddrOfPinnedObject();

        Marshal.Copy(BitConverter.GetBytes(entryCount), 0, pBuffer, sizeof(uint));
        GCHandle h1 = GCHandle.Alloc(blockEntry, GCHandleType.Pinned);
        try
        {
            Marshal.Copy(h1.AddrOfPinnedObject(), buffer, sizeof(uint), structSize);
            if (!DeviceIoControl(device, IOCTL_FILTER_MODIFY_BLOCK_TABLE, pBuffer, (uint)buffer.Length, buffer, 0, out _, IntPtr.Zero))
                throw new IOException("DeviceIoControl failed", Marshal.GetLastWin32Error());
            else
                Console.WriteLine($"Block table entry sent successfully: {ipAddr}:{port}");
        }
        finally
        {
            h1.Free();
            bufferHandle.Free();
        }
    }

    static private void ReadFilterPackages(SafeFileHandle device)
    {
        const int outBufferSize = 6 * 512 + 1024;
        byte[] outBuffer = new byte[outBufferSize];
        uint bytesReturned;

        bool result = DeviceIoControl(device, IOCTL_FILTER_GET_ALL_PACKAGES, IntPtr.Zero, 0, outBuffer, (uint)outBuffer.Length, out bytesReturned, IntPtr.Zero);
        if (!result)
        {
            Console.WriteLine("DeviceIoControl failed. Error: " + Marshal.GetLastWin32Error());
            return;
        }

        int offset = 0;
        while (offset + 2 <= bytesReturned)
        {
            // Read module name length
            ushort nameLen = BitConverter.ToUInt16(outBuffer, offset);
            offset += 2;
            if (offset + nameLen > bytesReturned) break;

            // Read module name (Unicode)
            string moduleName = Encoding.Unicode.GetString(outBuffer, offset, nameLen);
            offset += nameLen;

            Console.WriteLine($"Filter Module: {moduleName}");

            if (offset + 4 > bytesReturned) break;
            // Read package data length
            uint packageDataLen = BitConverter.ToUInt32(outBuffer, offset);
            offset += 4;

            int packageIndx = 0;
            int packageOffset = offset;
            int packageEnd = offset + (int)packageDataLen;
            while (packageOffset + 6 <= packageEnd && packageEnd <= bytesReturned)
            {
                uint ip = BitConverter.ToUInt32(outBuffer, packageOffset);
                ushort port = BitConverter.ToUInt16(outBuffer, packageOffset + 4);
                packageOffset += 6;
                packageIndx++;

                Console.WriteLine($"\t{packageIndx}] IpAddr: {new System.Net.IPAddress(ip)}, Port: {port}");
            }
            offset = packageEnd;
        }
    }

    static void Main()
    {
        const string devicePath = @"\\.\ndismfd";
        const uint GENERIC_READ = 0x80000000;
        const uint GENERIC_WRITE = 0x40000000;
        const uint OPEN_EXISTING = 3;
        const uint FILE_SHARE_READ = 1;
        const uint FILE_SHARE_WRITE = 2;

        using (var device = CreateFile(
            devicePath,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            IntPtr.Zero,
            OPEN_EXISTING,
            0,
            IntPtr.Zero))
        {
            if (device.IsInvalid)
            {
                Console.WriteLine("Failed to open device: " + devicePath);
                return;
            }

            ReadFilterPackages(device);

            //SendBlockTableIoctl(device, "192.168.56.1", 5566);
        }
    }
}