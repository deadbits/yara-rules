rule CrescentCore_DMG: installer macosmalware
{

    meta:
      Author = "Adam M. Swanda"
      Website = "https://www.deadbits.org"
      Repo = "https://github.com/deadbits/yara-rules"
      Date = "2019-07-18"

   strings:
      $header0 = "__PAGEZERO" ascii
      $header1 = "__TEXT" ascii

      $path0 = "/Users/mehdi/Desktop/RED MOON/Project/WaningCrescent/WaningCrescent/" ascii

      $install0 = ".app\" /Applications" ascii fullword
      $install1 = "open \"/Applications/" ascii fullword

      $str1 = /Flash_Player\dVirusMp/ ascii
      $str2 = /Flash_Player\dAntivirus33/ ascii
      $str3 = /Flash_Player\d{2}Armageddon/ ascii
      $str4 = /Flash_Player\d{2}Armageddon\w\dapocalypsyy/
      $str5 = /Flash_Player\d{2}Armageddon\w\ddoomsdayyy/

      $str6 = /SearchModel\w\dbrowser/
      $str8 = /SearchModel\w\dcountry/
      $str9 = /SearchModel\w\dhomepage/
      $str10 = /SearchModel\w\dthankyou/
      $str11 = /SearchModel\w\dinterrupt/
      $str12 = /SearchModel\w\dsearch/
      $str13 = /SearchModel\w\dsuccess/
      $str14 = /SearchModel\w\d{2}carrierURL/

   condition:
      (
        uint32(0) == 0xfeedface or
        uint32(0) == 0xcefaedfe or
        uint32(0) == 0xfeedfacf or
        uint32(0) == 0xcffaedfe or
        uint32(0) == 0xbebafeca
      ) and $header0 and $header1
      and
      (
        ($path0 and (any of ($install*)))
        or (5 of ($str*))
      )
      or all of them
}

