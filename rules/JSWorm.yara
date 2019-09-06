rule JSWorm: malware
{
    strings:
        $name00 = "JSWORM" nocase

        $str00 = "DECRYPT.txt" nocase
        $str02 = "cmd.exe"
        $str03 = "/c reg add HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v \"zapiska\" /d \"C:\\ProgramData\\"
        $str04 = /\/c taskkill.exe taskkill \/f \/im (store|sqlserver|dns|sqlwriter)\.exe/
        $str05 = "/c start C:\\ProgramData\\"
        $str06 = "/c vssadmin.exe delete shadows /all /quiet"
        $str07 = "/c bcdedit /set {default} bootstatuspolicy ignoreallfailures -y"
        $str08 = "/c bcdedit /set {default} recoveryenabled No -y"
        $str09 = "/c wbadmin delete catalog -quiet"
        $str10 = "/c wmic shadowcopy delete -y"

        $uniq00 = "fuckav"
        $uniq01 = "DECRYPT.hta" nocase
        $uniq02 = "Backup e-mail for contact :"
        $uniq03 = "<HTA:APPLICATION APPLICATIONNAME=" nocase

        /* suspicious APIs
            $api00 = "TerminateProcess"
            $api01 = "IsProcessorFeaturePresent"
            $api02 = "IsDebuggerPresent"
        */

    condition:
        uint16(0) == 0x5a4d
        and
        (
            ($name00 and 5 of ($str*))
            or
            (5 of ($str*) and 2 of ($uniq*))
            or
            ($name00 and any of ($uniq*))
        )
}
