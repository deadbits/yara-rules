rule REMCOS_RAT_variants: remcos rat winmalware
{
    meta:

        Author = "Adam M. Swanda"
        Website = "https://www.deadbits.org"
        Repo = "https://github.com/deadbits/yara-rules"
        Date = "2019-07-18"
        Description = "Detects multiple variants of REMCOS seen in the wild. Created by modifying and combining several of Florian's recent REMCOS ruleset. This rule aims for broader detection than the original ruleset, which used separate rules for each variant. If you do decide to break it into individual rules, the YARA strings variable names are grouped by the REMCOS variant type."

    strings:

        $funcs1 = "autogetofflinelogs" ascii fullword
        $funcs2 = "clearlogins" ascii fullword
        $funcs3 = "getofflinelogs" ascii fullword
        $funcs4 = "execcom" ascii fullword
        $funcs5 = "deletekeylog" ascii fullword
        $funcs6 = "remscriptexecd" ascii fullword
        $funcs7 = "getwindows" ascii fullword
        $funcs8 = "fundlldata" ascii fullword
        $funcs9 = "getfunlib" ascii fullword
        $funcs10 = "autofflinelogs" ascii fullword
        $funcs11 = "getclipboard" ascii fullword
        $funcs12 = "getscrslist" ascii fullword
        $funcs13 = "offlinelogs" ascii fullword
        $funcs14 = "getcamsingleframe" ascii fullword
        $funcs15 = "listfiles" ascii fullword
        $funcs16 = "getproclist" ascii fullword
        $funcs17 = "onlinelogs" ascii fullword
        $funcs18 = "getdrives" ascii fullword
        $funcs19 = "remscriptsuccess" ascii fullword
        $funcs20 = "getcamframe" ascii fullword

        $str_a1 = "C:\\Windows\\System32\\cmd.exe" ascii fullword
        $str_a2 = "C:\\WINDOWS\\system32\\userinit.exe" ascii fullword
        $str_a3 = "/k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWOR" ascii
        $str_a4 = "/k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWOR" ascii
        $str_a5 = "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data" ascii fullword

        $str_b1 = "CreateObject(\"Scripting.FileSystemObject\").DeleteFile(Wscript.ScriptFullName)" wide fullword
        $str_b2 = "Executing file: " ascii fullword
        $str_b3 = "GetDirectListeningPort" ascii fullword
        $str_b4 = "Set fso = CreateObject(\"Scripting.FileSystemObject\")" wide fullword
        $str_b5 = "licence_code.txt" ascii fullword
        $str_b6 = "\\restart.vbs" wide fullword
        $str_b7 = "\\update.vbs" wide fullword
        $str_b8 = "\\uninstall.vbs" wide fullword
        $str_b9 = "Downloaded file: " ascii fullword
        $str_b10 = "Downloading file: " ascii fullword
        $str_b11 = "KeepAlive Enabled! Timeout: %i seconds" ascii fullword
        $str_b12 = "Failed to upload file: " ascii fullword
        $str_b13 = "StartForward" ascii fullword
        $str_b14 = "StopForward" ascii fullword
        $str_b15 = "fso.DeleteFile \"" wide fullword
        $str_b16 = "On Error Resume Next" wide fullword
        $str_b17 = "fso.DeleteFolder \"" wide fullword
        $str_b18 = "Uploaded file: " ascii fullword
        $str_b19 = "Unable to delete: " ascii fullword
        $str_b20 = "while fso.FileExists(\"" wide fullword

        $str_c0 = "[Firefox StoredLogins not found]" ascii fullword
        $str_c1 = "Software\\Classes\\mscfile\\shell\\open\\command" ascii fullword
        $str_c2 = "[Chrome StoredLogins found, cleared!]" ascii fullword
        $str_c3 = "[Chrome StoredLogins not found]" ascii fullword
        $str_c4 = "[Firefox StoredLogins cleared!]" ascii fullword
        $str_c5 = "Remcos_Mutex_Inj" ascii fullword
        $str_c6 = "\\logins.json" ascii fullword
        $str_c7 = "[Chrome Cookies found, cleared!]" ascii fullword
        $str_c8 = "[Firefox Cookies not found]" ascii fullword
        $str_c9 = "[Chrome Cookies not found]" ascii fullword
        $str_c10 = "[Firefox cookies found, cleared!]" ascii fullword
        $str_c11 = "mscfile\\shell\\open\\command" ascii fullword
        $str_c12 = "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\" ascii fullword
        $str_c13 = "eventvwr.exe" ascii fullword


    condition:
        uint16(0) == 0x5a4d and filesize < 600KB
        and
        (
            ((8 of ($funcs*)) or all of ($funcs*))
            or
            ((1 of ($str_a*) and 4 of them) or all of ($str_a*))
            or
            ((8 of ($str_b*)) or all of ($str_b*))
            or
            all of ($str_c*)
         )
}
