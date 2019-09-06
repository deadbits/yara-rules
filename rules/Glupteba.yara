rule Glupteba: malware dropper
{

    meta:
        Author = "Adam M. Swanda"
        Website = "https://www.deadbits.org"
        Repo = "https://github.com/deadbits/yara-rules"
        Date = "2019-09-06"
        Note = "Attempts to detect the Glupteba malware; needs some tuning"

    strings:
        $str1 = "struct { F uintptr; serverRandom []uint8; clientRandom []uint8; version uint16; suite *tls.cipherSuite; masterSecret []uint8 }" ascii fullword
        $str2 = "func(context.Context, io.ReadWriter, http.socksAuthMethod) error" ascii fullword
        $str3 = "*http.socksUsernamePassword }" ascii
        $str4 = "net/http.(*socksDialer).validateTarget" ascii fullword
        $str5 = "net/http.(*socksCommand).String" ascii fullword
        $str6 = "net/http.socksCommand.String" ascii fullword
        $str7 = "type..hash.net/http.socksUsernamePassword" ascii fullword

        $str8 = "github.com/cenkalti/backoff." ascii
        $str9 = "golang.org/x/sys/windows.LookupAccountName" ascii fullword
        $str10 = "golang.org/x/sys/windows.LookupSID" ascii fullword

        $str00 = "json:\"login\"" ascii fullword
        $str01 = "Passwords" ascii fullword
        $str02 = "json:\"passwords\"" ascii fullword
        $str03 = "main.Password" ascii fullword
        $str04 = "main.postData" ascii fullword
        $str05 = "net/http.Post" ascii fullword
        $str06 = "json:\"browser_name\"" ascii fullword
        $str07 = "json:\"date_created\"" ascii fullword
        $str08 = "json:\"domain\"" ascii fullword
        $str09 = "encoding/json" ascii
        $str010 = "hash.main.Password" ascii

    condition:
        (
            uint16(0) == 0x5a4d
            and filesize < 20000KB
            and 8 of them
        )
        or
        (
            all of them
        )
}
