rule APT34_VALUEVAULT: apt34 infostealer winmalware
{
    meta:
        Description= "Information stealing malware used by APT34, written in Go."
        Reference = "https://www.fireeye.com/blog/threat-research/2019/07/hard-pass-declining-apt34-invite-to-join-their-professional-network.html"

    strings:
        $fsociety = "fsociety.dat" ascii

        $powershell = "New-Object -ComObject Shell.Application" ascii

        $gobuild = "Go build ID: " ascii

        $gopath01 = "browsers-password-cracker" ascii nocase
        $gopath02 = "main.go" ascii nocase
        $gopath03 = "mozilla.go" ascii nocase
        $gopath04 = "ie.go" ascii nocase
        // main.go, mozilla.go, ie.go, etc etc... this should probably be a regex but this works too i guess :|

        // some function names
        str1 = "main.Decrypt" ascii fullword
        str3 = "main.NewBlob" ascii fullword
        str4 = "main.CheckFileExist" ascii fullword
        str5 = "main.CopyFileToDirectory" ascii fullword
        str6 = "main.CrackChromeBased" ascii fullword
        str7 = "main.CrackIE" ascii fullword
        str8 = "main.decipherPassword" ascii fullword
        str9 = "main.DecodeUTF16" ascii fullword
        str10 = "main.getHashTable" ascii fullword
        str11 = "main.getHistory" ascii fullword
        str12 = "main.getHistoryWithPowerShell" ascii fullword
        str13 = "main.getHistoryFromRegistery" ascii fullword
        str14 = "main.main" ascii fullword
        str15 = "main.DecryptAESFromBase64" ascii fullword
        str16 = "main.DecryptAES" ascii fullword

        // typo of Mozilla is intentional
        str17 = "main.CrackMozila" ascii fullword
        str18 = "main.decodeLoginData" ascii fullword
        str19 = "main.decrypt" ascii fullword
        str20 = "main.removePadding" ascii fullword
        str21 = "main.getLoginData" ascii fullword
        str22 = "main.isMasterPasswordCorrect" ascii fullword
        str23 = "main.decrypt3DES" ascii fullword
        str24 = "main.getKey" ascii fullword
        str25 = "main.manageMasterPassword" ascii fullword
        str26 = "main.getFirefoxProfiles" ascii fullword
        str27 = "main._Cfunc_DumpVault" ascii fullword
        str28 = "main.CrackIEandEdgeNew" ascii fullword
        str29 = "main.init.ializers" ascii fullword
        str30 = "main.init" ascii fullword

    condition:
        uint16(0) == 0x5a4d
        and
        (
            (10 of ($str*) and 3 of ($gopaths*))
            or
            ($fsociety and $powershell and $gobuild)
            or
            ($fsociety and 10 of ($str*))
        )
}
