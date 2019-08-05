rule KPOT_v2: winmalware infostealer
{
    meta:
        Description = "Attempts to detect KPOT version 2 payloads"
        Author = "Adam M. Swanda"
        Website = "https://www.deadbits.org"
        Repo = "https://github.com/deadbits/yara-rules"
        Date = "2019-08-05"
    strings:
        $str01 = "%s: " ascii fullword
        $str02 = " _%s_" ascii fullword
        $str03 = "0|%S|%s|%s|%s" ascii fullword
        $str04 = "%s | %02d/%04d | %s | %s | %s" ascii fullword
        $str05 = "%s | %s | %s | %s | %s | %s | %s | %d | %s" ascii fullword
        $str06 = "%s: %s | %02d/%04d | %s" ascii fullword
        $str07 = "%s = %s" ascii fullword
        $str08 = "password-check" ascii fullword

        $conf_re1 = /(SMTP|POP3|IMAP)\sServer/ wide
        $conf_re2 = /(SMTP|POP3|IMAP)\s(User|Password|Port)/ wide

        $conf01 = "*.config" ascii wide fullword
        $conf02 = "HTTP Server URL" ascii wide fullword

        $conf03 = "%s: %d" ascii wide fullword
        $conf04 = "%s\\Outlook.txt" ascii wide fullword

    condition:
        uint16(0) == 0x5a4d
        and all of ($str*)
        and all of ($conf_re*)
        and all of ($conf0*)
}
