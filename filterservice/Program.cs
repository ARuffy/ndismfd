using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

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

            // Allocate a buffer for output (adjust size as needed)
            byte[] outBuffer = new byte[4096];
            uint bytesReturned;

            bool result = DeviceIoControl(
                device,
                IOCTL_FILTER_ENUMERATE_ALL_INSTANCES,
                IntPtr.Zero,
                0,
                outBuffer,
                (uint)outBuffer.Length,
                out bytesReturned,
                IntPtr.Zero);

            if (!result)
            {
                Console.WriteLine("DeviceIoControl failed: " + Marshal.GetLastWin32Error());
                return;
            }

            // Parse the output buffer
            int offset = 0;
            while (offset + 2 <= bytesReturned)
            {
                ushort nameLen = BitConverter.ToUInt16(outBuffer, offset);
                offset += 2;
                if (nameLen == 0 || offset + nameLen > bytesReturned)
                    break;

                // Unicode string (UTF-16LE)
                string name = Encoding.Unicode.GetString(outBuffer, offset, nameLen);
                Console.WriteLine("Filter Instance: " + name);
                offset += nameLen;
            }
        }
    }
}