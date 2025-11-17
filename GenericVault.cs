using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Web.Script.Serialization;

using static Win32.CredUI;
using static Win32.AdvApi32;

namespace Credential {

  [ComVisible(true)]
  [Guid("A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D")]
  [ClassInterface(ClassInterfaceType.AutoDispatch)]
  [ProgId("Credential.GenericVault")]
  public class GenericVault {

    private const int CRED_PERSIST_SESSION = 1;
    private const int CRED_PERSIST_LOCAL_MACHINE = 2;
    private const int CRED_PERSIST_ENTERPRISE = 3;

    private const int MAX_USERNAME_LENGTH = 256;
    private const int MAX_PASSWORD_LENGTH = 256;

    private const int ERROR_CANCELLED = 1223;
    private const int ERROR_NOT_FOUND = 1168;

    public string CollectCredential(string targetName, int persistenceType, bool persist, string caption, string message, string username = null, string comment = null, bool excludePassword = false, bool alwaysShowUI = true) {

      if (string.IsNullOrEmpty(targetName)) return Serialize(new { Error = "Target name cannot be empty." });
      if (persistenceType < CRED_PERSIST_SESSION || persistenceType > CRED_PERSIST_ENTERPRISE) return Serialize(new { Error = "Invalid persistence value." });

      var uiInfo = new CREDUI_INFO {
        cbSize = Marshal.SizeOf(typeof(CREDUI_INFO)),
        pszCaptionText = caption ?? "Enter Credentials",
        pszMessageText = message ?? $"Enter credentials for {targetName}"
      };

      var userNameBuilder = new StringBuilder(username ?? "", MAX_USERNAME_LENGTH);
      var passwordBuilder = new StringBuilder(MAX_PASSWORD_LENGTH);

      CREDUI_FLAGS flags = CREDUI_FLAGS.CREDUI_FLAGS_GENERIC_CREDENTIALS;

      if (alwaysShowUI) {
        flags |= CREDUI_FLAGS.CREDUI_FLAGS_ALWAYS_SHOW_UI;
      }

      if (persist) {
        flags |= CREDUI_FLAGS.CREDUI_FLAGS_PERSIST;
      } else {
        flags |= CREDUI_FLAGS.CREDUI_FLAGS_DO_NOT_PERSIST;
      }

      var save = persist;

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
        flags
      );

      if (result == ERROR_CANCELLED) return Serialize(new { Value = new { Cancelled = true } });

      if (result != 0) return Serialize(new { Error = $"Failed to collect credentials. Error code: {result}" });

      var collectedUsername = userNameBuilder.ToString();
      var collectedPassword = passwordBuilder.ToString();

      if (save) {
        bool persistSuccess = PersistCredential(targetName, persistenceType, collectedUsername, collectedPassword, comment);
        if (!persistSuccess) return Serialize(new { Error = "Failed to persist credentials." });
      }

      if (excludePassword) {
        return Serialize(new { 
          Value = new { 
            Username = collectedUsername,
            TargetName = targetName,
            Saved = save
          } 
        });
      } else {
        return Serialize(new { 
          Value = new { 
            Username = collectedUsername, 
            Password = collectedPassword,
            TargetName = targetName,
            Saved = save
          } 
        });
      }
    }

    private const uint Success = 0;

    private bool parseTargetName(string targetName, out string domain, out string user) {
      var domainBuilder = new StringBuilder(MAX_USERNAME_LENGTH);
      var userBuilder = new StringBuilder(MAX_USERNAME_LENGTH);

      uint success = CredUIParseUserName(
        targetName,
        domainBuilder,
        (uint)MAX_USERNAME_LENGTH,
        userBuilder,
        (uint)MAX_USERNAME_LENGTH
      );

      if (success == Success) {
          domain = domainBuilder.ToString();
          user = userBuilder.ToString();
          return true;
      } else {
          domain = string.Empty;
          user = string.Empty;
          return false;
      }

    }

    private string Serialize(object value) {
      var serializer = new JavaScriptSerializer();
      return serializer.Serialize(value);
    }

    private const int CRED_TYPE_GENERIC = 1;

    public string ReadCredential(string targetName, bool excludePassword = false) {

      if (string.IsNullOrEmpty(targetName)) return Serialize(new { Error = "Target name cannot be empty." });

      IntPtr credPtr = IntPtr.Zero;

      try {
        bool success = CredRead(targetName, CRED_TYPE_GENERIC, 0, out credPtr);

        if (!success) {
          int error = Marshal.GetLastWin32Error();
          if (error == ERROR_NOT_FOUND) {
            return Serialize(new { Error = "Credential not found." });
          }
          return Serialize(new { Error = $"Failed to read credential. Error code: {error}" });
        }

        var credential = (CREDENTIAL)Marshal.PtrToStructure(credPtr, typeof(CREDENTIAL));

        string password = null;
        if (!excludePassword && credential.CredentialBlob != IntPtr.Zero) {
          password = Marshal.PtrToStringUni(credential.CredentialBlob, credential.CredentialBlobSize / 2);
        }

        var lastWritten = DateTime.FromFileTime(credential.LastWritten).ToString("o");

        if (excludePassword) {
          return Serialize(new { 
            Value = new { 
              Username = credential.UserName,
              TargetName = credential.TargetName,
              Comment = credential.Comment,
              Type = credential.Type,
              Persist = credential.Persist,
              LastWritten = lastWritten
            } 
          });
        } else {
          return Serialize(new { 
            Value = new { 
              Username = credential.UserName,
              Password = password,
              TargetName = credential.TargetName,
              Comment = credential.Comment,
              Type = credential.Type,
              Persist = credential.Persist,
              LastWritten = lastWritten
            } 
          });
        }

      } finally {
        if (credPtr != IntPtr.Zero) CredFree(credPtr);
      }

    }

    public string DeleteCredential(string targetName) {

      if (string.IsNullOrEmpty(targetName)) return Serialize(new { Error = "Target name cannot be empty." });

      bool success = CredDelete(targetName, CRED_TYPE_GENERIC, 0);

      if (!success) {
        int error = Marshal.GetLastWin32Error();
        if (error == ERROR_NOT_FOUND) {
          return Serialize(new { Error = "Credential not found." });
        }
        return Serialize(new { Error = $"Failed to delete credential. Error code: {error}" });
      }

      return Serialize(new { Value = new { Deleted = true, TargetName = targetName } });

    }

    private bool PersistCredential(string targetName, int persistenceType, string username, string password, string comment) {

      byte[] credentialBlob = Encoding.Unicode.GetBytes(password);

      var credential = new CREDENTIAL {
        Type = CRED_TYPE_GENERIC,
        TargetName = targetName,
        UserName = username,
        CredentialBlob = Marshal.StringToHGlobalUni(password),
        CredentialBlobSize = credentialBlob.Length,
        Persist = persistenceType,
        Comment = comment
      };

      var success = false;

      try {
        success = CredWrite(ref credential, 0);
      } finally {
        if (credential.CredentialBlob != IntPtr.Zero) Marshal.FreeHGlobal(credential.CredentialBlob);
      }

      return success;

    }

  }

}