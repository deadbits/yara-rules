rule SilentTrinity_Delivery_Document
{
   meta:

      Description = "Attempts to detect SilentTrinity delivery documents"
      Author = "Adam M. Swanda"
      Website = "https://www.deadbits.org"
      Repo = "https://github.com/deadbits/yara-rules"
      Date = "2019-07-19"
      Reference = "https://countercept.com/blog/hunting-for-silenttrinity/"

   strings:

      $s0 = "VBE7.DLL" fullword ascii
      $s1 = "TargetPivotTable" fullword ascii
      $s2 = "DocumentUserPassword" fullword wide
      $s3 = "DocumentOwnerPassword" fullword wide
      $s4 = "Scripting.FileSystemObject" fullword wide
      $s5 = "MSXML2.ServerXMLHTTP" fullword wide
      $s6 = "Win32_ProcessStartup " fullword ascii
      $s7 = "Step 3: Start looping through all worksheets" fullword ascii
      $s8 = "Step 2: Start looping through all worksheets" fullword ascii
      $s9 = "Stringer" fullword wide
      $s10 = "-decode -f" fullword wide
      $s11 = "2. Da biste pogledali dokument, molimo kliknite \"OMOGU" fullword wide
   
   condition:
      uint16(0) == 0xcfd0 and filesize < 200KB 
      and (8 of ($s*) or all of them)
}
