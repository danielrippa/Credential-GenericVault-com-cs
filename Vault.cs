using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Web.Script.Serialization;

namespace Credential
{
    [ComVisible(true)]
    [Guid("F0E1D2C3-B4A5-6789-8C9D-0E1F2A3B4C5D")]
    [ClassInterface(ClassInterfaceType.AutoDispatch)]
    [ProgId("Credential.CredentialResult")]
    public class CredentialResult
    {
        public bool Success { get; set; }
        public string Value { get; set; }
    }

    [ComVisible(true)]
    [Guid("A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D")]
    [ClassInterface(ClassInterfaceType.AutoDispatch)]
    [ProgId("Credential.GenericVault")]
    public class GenericVault
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct CREDUI_INFO
        {
            public int cbSize;
            public IntPtr hwndParent;
            public string pszMessageText;
            public string pszCaptionText;
            public IntPtr hbmBanner;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct CREDENTIAL
        {
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

        [Flags]
        private enum CREDUI_FLAGS
        {
            CREDUIWIN_GENERIC = 0x1,
            CREDUIWIN_CHECKBOX = 0x2,
            CREDUI_FLAGS_PERSIST = 0x1000
        }

        private const int CRED_TYPE_GENERIC = 1;
        private const int CRED_PERSIST_SESSION = 1;
        private const int CRED_PERSIST_LOCAL_MACHINE = 2;
        private const int CRED_PERSIST_ENTERPRISE = 3;
        private const int MAX_USERNAME_LENGTH = 256;
        private const int MAX_PASSWORD_LENGTH = 256;
        private const int ERROR_CANCELLED = 1223;
        private const int ERROR_NOT_FOUND = 1168;

        [DllImport("credui.dll", CharSet = CharSet.Auto)]
        private static extern int CredUIPromptForCredentialsW(
            ref CREDUI_INFO uiInfo,
            string targetName,
            IntPtr reserved,
            int errorCode,
            StringBuilder userName,
            int userNameMaxChars,
            StringBuilder password,
            int passwordMaxChars,
            ref bool save,
            CREDUI_FLAGS flags);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool CredWrite(ref CREDENTIAL credential, int flags);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool CredRead(string target, int type, int flags, out IntPtr credPtr);

        [DllImport("advapi32.dll")]
        private static extern void CredFree(IntPtr credPtr);

        public int CollectCredential(string targetName, int persistence)
        {
            if (string.IsNullOrEmpty(targetName))
                return 1;

            if (persistence < CRED_PERSIST_SESSION || persistence > CRED_PERSIST_ENTERPRISE)
                return 5;

            var uiInfo = new CREDUI_INFO
            {
                cbSize = Marshal.SizeOf(typeof(CREDUI_INFO)),
                pszCaptionText = "Enter Credentials",
                pszMessageText = string.Format("Enter credentials for {0}", targetName)
            };

            var userNameBuilder = new StringBuilder(MAX_USERNAME_LENGTH);
            var passwordBuilder = new StringBuilder(MAX_PASSWORD_LENGTH);
            bool save = true;

            int result = CredUIPromptForCredentialsW(
                ref uiInfo,
                targetName,
                IntPtr.Zero,
                0,
                userNameBuilder,
                MAX_USERNAME_LENGTH,
                passwordBuilder,
                MAX_PASSWORD_LENGTH,
                ref save,
                CREDUI_FLAGS.CREDUIWIN_GENERIC | CREDUI_FLAGS.CREDUI_FLAGS_PERSIST);

            if (result == ERROR_CANCELLED)
                return 2;

            if (result != 0)
                return 3;

            byte[] credentialBlob = Encoding.Unicode.GetBytes(passwordBuilder.ToString());
            var credential = new CREDENTIAL
            {
                Type = CRED_TYPE_GENERIC,
                TargetName = targetName,
                UserName = userNameBuilder.ToString(),
                CredentialBlob = Marshal.StringToHGlobalUni(passwordBuilder.ToString()),
                CredentialBlobSize = credentialBlob.Length,
                Persist = persistence
            };

            try
            {
                if (!CredWrite(ref credential, 0))
                    return 4;
                return 0;
            }
            finally
            {
                if (credential.CredentialBlob != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(credential.CredentialBlob);
                }
            }
        }

        public string ReadCredential(string targetName)
        {
            var serializer = new JavaScriptSerializer();

            if (string.IsNullOrEmpty(targetName))
            {
                return serializer.Serialize(new CredentialResult { Success = false, Value = "Target name cannot be empty." });
            }

            if (CredRead(targetName, CRED_TYPE_GENERIC, 0, out IntPtr credPtr))
            {
                try
                {
                    var cred = (CREDENTIAL)Marshal.PtrToStructure(credPtr, typeof(CREDENTIAL));
                    if (cred.CredentialBlobSize > 0 && cred.CredentialBlob != IntPtr.Zero)
                    {
                        string password = Marshal.PtrToStringUni(cred.CredentialBlob, cred.CredentialBlobSize / 2);
                        return serializer.Serialize(new CredentialResult { Success = true, Value = password });
                    }
                    else
                    {
                        return serializer.Serialize(new CredentialResult { Success = false, Value = "Credential found but contains no data." });
                    }
                }
                finally
                {
                    CredFree(credPtr);
                }
            }
            else
            {
                int lastError = Marshal.GetLastWin32Error();
                string errorMessage = (lastError == ERROR_NOT_FOUND)
                    ? string.Format("Credential for target '{0}' not found.", targetName)
                    : string.Format("CredRead failed with Win32 error code: {0}.", lastError);

                return serializer.Serialize(new CredentialResult { Success = false, Value = errorMessage });
            }
        }
    }
}

