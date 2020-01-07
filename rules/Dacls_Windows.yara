rule Dacls_Trojan_Windows
{
    meta:
        Author = "Adam M. Swanda"
        Repo = "https://github.com/deadbits/yara-rules"

    strings:
        $fext00 = ".exe" ascii wide
        $fext01 = ".cmd" ascii wide
        $fext02 = ".bat" ascii wide
        $fext03 = ".com" ascii wide

        $str00 = "Software\\mthjk" ascii wide
        $str01 = "WindowsNT.dll" ascii fullword
        $str02 = "GET %s HTTP/1.1" ascii fullword
        $str03 = "content-length:" ascii fullword
        $str04 = "Connection: keep-alive" ascii fullword

        $cls00 = "c_2910.cls" ascii fullword
        $cls01 = "k_3872.cls" ascii fullword

    condition:
        (uint16(0) == 0x5a4d)
        and
        (
            (all of ($cls*))
            or
            (all of ($fext*) and all of ($str*))
        )
}
