rule APT34_PICKPOCKET: apt apt34 infostealer winmalware
{
   meta:
      Description = "Detects the PICKPOCKET malware used by APT34, a browser credential-theft tool identified by FireEye in May 2018"
      Reference = "https://www.fireeye.com/blog/threat-research/2019/07/hard-pass-declining-apt34-invite-to-join-their-professional-network.html"

   strings:
      $s1 = "SELECT * FROM moz_logins;" ascii fullword
      $s2 = "\\nss3.dll" ascii fullword
      $s3 = "SELECT * FROM logins;" ascii fullword
      $s4 = "| %Q || substr(name,%d+18) ELSE name END WHERE tbl_name=%Q COLLATE nocase AND (type='table' OR type='index' OR type='trigger');" ascii fullword
      $s5 = "\\Login Data" ascii fullword
      $s6 = "%s\\Mozilla\\Firefox\\profiles.ini" ascii fullword
      $s7 = "Login Data" ascii fullword
      $s8 = "encryptedUsernamencryptedPasswor" ascii fullword
      $s10 = "%s\\Mozilla\\Firefox\\%s" ascii fullword
      $s11 = "encryptedUsername" ascii fullword
      $s12 = "2013-12-06 14:53:30 27392118af4c38c5203a04b8013e1afdb1cebd0d" ascii fullword // SQLITE_SOURCE_ID
      $s13 = "27392118af4c38c5203a04b8013e1afdb1cebd0d" ascii
      $s15 = "= 'table' AND name!='sqlite_sequence'   AND coalesce(rootpage,1)>0" ascii fullword
      $s18 = "[*] FireFox :" fullword wide
      $s19 = "[*] Chrome :" fullword wide
      $s20 = "username_value" ascii fullword
   condition:
      uint16(0) == 0x5a4d
      and 
      (
         8 of them or all of them
      )
}
