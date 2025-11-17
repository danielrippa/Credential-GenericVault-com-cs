using System;
using System.Runtime.InteropServices;

namespace Win32 {

  internal static class AdvApi32 {

    private const string Dll = "AdvApi32.dll";

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    internal struct CREDENTIAL {
        public int Flags;
        public int Type;
        public string TargetName;
        public string Comment;
        public long LastWritten;
        public int CredentialBlobSize;
        public IntPtr CredentialBlob;
        public int Persist;
        public int AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias;
        public string UserName;
    }

    [DllImport(Dll, SetLastError = true, CharSet = CharSet.Auto)]
    internal static extern bool CredWrite(ref CREDENTIAL credential, int flags);

    [DllImport(Dll, SetLastError = true, CharSet = CharSet.Auto)]
    internal static extern bool CredRead(string target, int type, int flags, out IntPtr credPtr);

    [DllImport(Dll, SetLastError = true, CharSet = CharSet.Auto)]
    internal static extern bool CredDelete(string target, int type, int flags);

    [DllImport(Dll)]
    internal static extern void CredFree(IntPtr credPtr);

  }

}