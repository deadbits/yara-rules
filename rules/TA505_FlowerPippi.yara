rule TA505_FlowerPippi: TA505 financial backdoor winmalware
{
   meta:
      Author = "Adam M. Swanda"
      Website = "https://www.deadbits.org"
      Repo = "https://github.com/deadbits/yara-rules"
      Date = "2019-07-18"

   strings:

      $pipi = "pipipipip" ascii fullword
      $pdb0  = "Loader.pdb" ascii fullword

      $str0  = "bot.php" ascii fullword
      $str1  = "%.2X" ascii fullword
      $str2  = "sd.bat" ascii fullword
      $str3  = "open" ascii fullword
      $str4  = "domain" ascii fullword
      $str5 = "proxy" ascii fullword
      $str6  = ".exe" ascii fullword
      $str7 = "Can't launch EXE file" ascii fullword
      $str8  = "Can't load file" ascii fullword
      $str9  = ".dll" ascii fullword
      $str10  = "Dll function not found" ascii fullword
      $str11  = "Can't load Dll" ascii fullword
      $str12  = "__start_session__" ascii fullword
      $str13  = "__failed__" ascii fullword
      $str14  = "RSDSG" ascii fullword
      $str15  = "ProxyServer" ascii fullword
      $str16  = ":Repeat" ascii fullword
      $str17  = "del \"%s\"" ascii fullword
      $str18  = "if exist \"%s\" goto Repeat" ascii fullword
      $str19  = "rmdir \"%s" ascii fullword
      $str20  = "del \"%s\"" ascii fullword
      $str21  = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" ascii fullword
      $str22  = "ProxyEnable" ascii fullword
      $str23 = ".00cfg" ascii fullword
      $str24 = ".idata" ascii fullword

      $api0  = "IsProcessorFeaturePresent" ascii fullword
      $api1  = "IsDebuggerPresent" ascii fullword
      $api2  = "HttpOpenRequestA" ascii fullword
      $api3  = "InternetCrackUrlA" ascii fullword
      $api4  = "InternetOpenW" ascii fullword
      $api5  = "HttpSendRequestW" ascii fullword
      $api6  = "InternetCloseHandle" ascii fullword
      $api7  = "InternetConnectA" ascii fullword
      $api8  = "InternetSetOptionW" ascii fullword
      $api9  = "InternetReadFile" ascii fullword
      $api10  = "WININET.dll" ascii fullword
      $api11 = "URLDownloadToFileA" ascii fullword

   condition:
      uint16(0) == 0x5a4d and filesize < 700KB
      and
      (
         (10 of ($str*) and $pipi)
         or
         (10 of ($str*) and $pdb0)
         or
         (10 of ($str*) and 5 of ($api*))
         or
         (all of them)
      )
}
