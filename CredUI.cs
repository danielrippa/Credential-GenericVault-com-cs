using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Win32 {

  public static class CredUI {

    private const string Dll = "CredUI.dll";

    [DllImport(Dll, CharSet = CharSet.Auto)]
    internal static extern uint CredUIParseUserName(
      string userName,
      StringBuilder user,
      ulong userMaxChars,
      StringBuilder domain,
      ulong domainMaxChars
    );

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    internal struct CREDUI_INFO {
      public int cbSize;
      public IntPtr hwndParent;
      public string pszMessageText;
      public string pszCaptionText;
      public IntPtr hbmBanner;
    }

    [Flags]
    internal enum CREDUI_FLAGS {
      CREDUI_FLAGS_SHOW_SAVE_CHECK_BOX = 0x00040,
      CREDUI_FLAGS_INCORRECT_PASSWORD = 0x1,
      CREDUI_FLAGS_DO_NOT_PERSIST = 0x2,
      CREDUI_FLAGS_PASSWORD_ONLY_OK = 0x200,
      CREDUI_FLAGS_PERSIST = 0x1000,
      CREDUI_FLAGS_GENERIC_CREDENTIALS = 0x40000,
      CREDUI_FLAGS_ALWAYS_SHOW_UI = 0x80,
      CREDUI_FLAGS_EXCLUDE_CERTIFICATES = 0x8,
    }

    [DllImport(Dll, CharSet = CharSet.Auto)]
    internal static extern int CredUIPromptForCredentialsW(
      ref CREDUI_INFO uiInfo,
      string targetName,
      IntPtr reserved,
      int errorCode,
      StringBuilder userName,
      int userNameMaxChars,
      StringBuilder password,
      int passwordMaxChars,
      ref bool save,
      CREDUI_FLAGS flags
    );

  }
}

