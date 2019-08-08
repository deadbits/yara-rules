rule APT32_KerrDown: apt apt32 winmalware downloader
{
    meta:
        Author = "Adam M. Swanda"
        Website = "https://www.deadbits.org"
        Repo = "https://github.com/deadbits/yara-rules"
        Date = "2019-08-08"

    strings:
        $hijack = "DllHijack.dll" ascii fullword
        $fmain = "FMain" ascii fullword
        $gfids = ".gfids" ascii fullword
        $sec01 = ".xdata$x" ascii fullword
        $sec02 = ".rdata$zzzdbg" ascii fullword
        $sec03 = ".rdata$sxdata" ascii fullword

        $str01 = "wdCommandDispatch" ascii fullword
        $str02 = "TerminateProcess" ascii fullword
        $str03 = "IsProcessorFeaturePresent" ascii fullword
        $str04 = "IsDebuggerPresent" ascii fullword
        $str05 = "SetUnhandledExceptionFilter" ascii fullword
        $str06 = "QueryPerformanceCounter" ascii fullword

condition:
        (uint16(0) == 0x5a4d)
        and
        (
            ($hijack and $fmain and $gfids)
            or
            ($gfids and 6 of them)
        )
}
