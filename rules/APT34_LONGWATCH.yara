rule APT34_LONGWATCH: apt34 winmalware keylogger
{
    meta:
        Description = "APT34 Keylogger"
        Reference = "https://www.fireeye.com/blog/threat-research/2019/07/hard-pass-declining-apt34-invite-to-join-their-professional-network.html"

    strings:
        $log = "c:\\windows\\temp\\log.txt" ascii fullword
        $clipboard = "---------------CLIPBOARD------------" ascii fullword

        $func0 = "\"Main Invoked.\"" ascii fullword
        $func1 = "\"Main Returned.\"" ascii fullword

        $logger3 = ">---------------------------------------------------" ascii fullword
        $logger4 = "[ENTER]" ascii fullword
        $logger5 = "[CapsLock]" ascii fullword
        $logger6 = "[CRTL]" ascii fullword
        $logger7 = "[PAGE_UP]" ascii fullword
        $logger8 = "[PAGE_DOWN]" ascii fullword
        $logger9 = "[HOME]" ascii fullword
        $logger10 = "[LEFT]" ascii fullword
        $logger11 = "[RIGHT]" ascii fullword
        $logger12 = "[DOWN]" ascii fullword
        $logger13 = "[PRINT]" ascii fullword
        $logger14 = "[PRINT SCREEN]" ascii fullword
        $logger15 = "[INSERT]" ascii fullword
        $logger16 = "[SLEEP]" ascii fullword
        $logger17 = "[PAUSE]" ascii fullword
        $logger18 = "[TAB]" ascii fullword
        $logger19 = "[ESC]" ascii fullword
        $logger20 = "[DEL]" ascii fullword
        $logger21 = "[ALT]" ascii fullword

    condition:
        uint16(0) == 0x5a4d
        and
        $log
        and
        all of ($func*)
        and
        all of ($logger*)
        and $clipboard
}
