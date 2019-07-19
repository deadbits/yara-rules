rule SilentTrinity
{
   meta:
      Description = "Attempts to detect the SilentTrinity malware family"
      Author = "Adam M. Swanda"
      Website = "https://www.deadbits.org"
      Repo = "https://github.com/deadbits/yara-rules"
      Date = "2019-07-19"
      Reference = "https://countercept.com/blog/hunting-for-silenttrinity/"

    strings:

        $pdb01 = "SILENTTRINITY.pdb" ascii

        $str01  = "Found {0} in zip" ascii fullword
        $str02  = "{0} not in zip file" ascii fullword
        $str03  = "Invalid HMAC: {0}" ascii fullword
        $str04  = "Attempting HTTP GET to {0}" ascii fullword
        $str05  = "Downloaded {0} bytes" ascii fullword
        $str06  = "Error downloading {0}: {1}" ascii fullword
        $str07  = "Attempting HTTP POST to {0}" ascii fullword
        $str08  = "POST" ascii fullword
        $str09  = "application/octet-stream" ascii fullword
        $str10  = "Error sending job results to {0}: {1}" ascii fullword
        $str11  = ".dll" ascii fullword
        $str12  = "Trying to resolve assemblies by staging zip" ascii fullword
        $str13  = "'{0}' loaded" ascii fullword
        $str14  = "Usage: SILENTTRINITY.exe <URL> [<STAGE_URL>]" ascii fullword
        $str15 = "IronPython.dll" ascii fullword
        $str16  = "IronPythonDLL" ascii fullword
        $str17 = "DEBUG" ascii fullword
        $str18  = "Main.py" ascii fullword
        $str19  = "Execute" ascii fullword
        $str20  = "SILENTTRINITY.Properties.Resources" ascii fullword
        $str21  = ".zip" ascii fullword

        $a00  = "HttpGet" ascii fullword
        $a01  = "System.Net" ascii fullword
        $a02  = "Target" ascii fullword
        $a03  = "WebClient" ascii fullword
        $a04 = "get_Current" ascii fullword
        $a05  = "Endpoint" ascii fullword
        $a06  = "AesDecrypt" ascii fullword
        $a07  = "AesEncrypt" ascii fullword
        $a08  = "cert" ascii fullword
        $a09  = "WebRequest" ascii fullword
        $a10  = "HttpPost" ascii fullword

    condition:
        uint16(0) == 0x5a4d
        and
        (
            (8 of ($str*) or (all of ($a*) and $pdb01) or $pdb01)
        )
}     
