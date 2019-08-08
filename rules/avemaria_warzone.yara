rule AveMaria_WarZone: avemaria warzone winmalware infostealer
{

    meta:
      Author = "Adam M. Swanda"
      Website = "https://www.deadbits.org"
      Repo = "https://github.com/deadbits/yara-rules"
      Date = "2019-07-18"

   strings:
      $str1 = "cmd.exe /C ping 1.2.3.4 -n 2 -w 1000 > Nul & Del /f /q " ascii fullword
      $str2 = "MsgBox.exe" wide fullword
      $str4 = "\\System32\\cmd.exe" wide fullword
      $str6 = "Ave_Maria" wide
      $str7 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList" ascii fullword
      $str8 = "SMTP Password" wide fullword
      $str11 = "\\Google\\Chrome\\User Data\\Default\\Login Data" wide fullword
      $str12 = "\\sqlmap.dll" wide fullword
      $str14 = "SELECT * FROM logins" ascii fullword
      $str16 = "Elevation:Administrator!new" wide
      $str17 = "/n:%temp%" ascii wide

   condition:
      (
        uint16(0) == 0x5a4d and filesize < 400KB
      )
      and
      (
        5 of ($str*)
        or all of them
      )
}

