import "pe"

rule hunting_generic_win_rat
{
    meta:
        author = "Ajin Deepak, AD2001"
        description = "Hunting RATS based on common patterns"
        hunting_tag = "generic_win_rat"
        date = "2026-05-24"
        yarahub_uuid = "310fdf8f-c66d-4c9c-839d-89bd4d35a441"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "e07c651f51ce3d342f004bb8baa38f2b"

    strings:

        $strong00 = "ProcessCritical" nocase ascii wide
        $strong01 = "RecoverCredential" nocase ascii wide
        $strong02 = "RemoteShell" nocase ascii wide
        $strong03 = "ReverseShell" nocase ascii wide
        $strong04 = "ReverseProxy" nocase ascii wide
        $strong05 = "HVNC" nocase ascii wide
        $strong06 = "Keylogger" nocase ascii wide
        $strong07 = "ClipboardLogger" nocase ascii wide
        $strong08 = "PasswordStealer" nocase ascii wide
        $strong09 = "PasswordRecovery" nocase ascii wide
        $strong10 = "RemoteCamera" nocase ascii wide
        $strong11 = "RemoteMicrophone" nocase ascii wide
        $strong12 = "CaptureBrowsers" nocase ascii wide
        $strong13 = "DecryptBrowsers" nocase ascii wide

        $bot00 = "VisitURL" nocase ascii wide
        $bot01 = "URLUpdate" nocase ascii wide
        $bot02 = "URLVisit" nocase ascii wide
        $bot03 = "URLDownload" nocase ascii wide
        $bot04 = "DDoSAttack" nocase ascii wide
        $bot05 = "UDPFlood" nocase ascii wide
        $bot06 = "TCPFlood" nocase ascii wide
        $bot07 = "HTTPFlood" nocase ascii wide
        $bot08 = "SYNFlood" nocase ascii wide
        $bot09 = "SlowLoris" nocase ascii wide

        $mutex00 = /Mutex_[A-Za-z0-9]{6,64}/
        $mutex01 = /Mutex-[A-Za-z0-9]{6,64}/

        $persist00 = "/create /f /RL HIGHEST /sc minute /mo 1 /tn" ascii wide
        $persist01 = "/create /f /sc minute /mo 1 /tn" ascii wide
        $persist02 = "/create /f /RL HIGHEST /sc onlogon /tn" ascii wide
        $persist03 = "schtasks.exe /create" nocase ascii wide
        $persist04 = "AddToStartup" nocase ascii wide
        $persist05 = "InstallStartup" nocase ascii wide
        $persist06 = "InstallPersistence" nocase ascii wide
        $persist07 = "ScheduledTaskInstall" nocase ascii wide
        $persist08 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase ascii wide
        $persist09 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase ascii wide

        $aa00 = "SbieDll.dll" nocase ascii wide
        $aa01 = "Select * from Win32_ComputerSystem" ascii wide
        $aa02 = "VirtualBox" ascii wide
        $aa03 = "VMwareTools" ascii wide
        $aa04 = "VBoxGuest" ascii wide
        $aa05 = "VBoxService" ascii wide
        $aa06 = "vmtoolsd.exe" ascii wide
        $aa07 = "DetectVirtualMachine" nocase ascii wide
        $aa08 = "Select * from AntivirusProduct" ascii wide

        $dbg00 = "x32dbg.exe" nocase ascii wide
        $dbg01 = "x64dbg.exe" nocase ascii wide
        $dbg02 = "ollydbg.exe" nocase ascii wide
        $dbg03 = "windbg.exe" nocase ascii wide
        $dbg04 = "ida64.exe" nocase ascii wide
        $dbg05 = "dnspy.exe" nocase ascii wide
        $dbg06 = "wireshark.exe" nocase ascii wide
        $dbg07 = "fiddler.exe" nocase ascii wide
        $dbg08 = "processhacker.exe" nocase ascii wide
        $dbg09 = "httpdebuggerui.exe" nocase ascii wide

        $av00 = "MsMpEng.exe" nocase ascii wide
        $av01 = "avp.exe" nocase ascii wide
        $av02 = "avastsvc.exe" nocase ascii wide
        $av03 = "avgsvc.exe" nocase ascii wide
        $av04 = "bdagent.exe" nocase ascii wide
        $av05 = "egui.exe" nocase ascii wide
        $av06 = "ekrn.exe" nocase ascii wide
        $av07 = "mbam.exe" nocase ascii wide
        $av08 = "mcshield.exe" nocase ascii wide
        $av09 = "ccSvcHst.exe" nocase ascii wide

    condition:
        pe.is_pe and
        filesize < 150MB and
        (
            (
                5 of ($strong*) and
                (
                    1 of ($bot*) or
                    1 of ($mutex*) or
                    1 of ($persist*) or
                    1 of ($aa*) or
                    2 of ($dbg*) or
                    2 of ($av*)
                )
            )

            or

            (
                4 of ($strong*) and
                (
                    (2 of ($bot*) and (1 of ($mutex*) or 1 of ($persist*) or 2 of ($aa*) or 2 of ($dbg*) or 2 of ($av*))) or
                    (1 of ($mutex*) and (1 of ($persist*) or 2 of ($aa*) or 2 of ($dbg*) or 2 of ($av*))) or
                    (1 of ($persist*) and (2 of ($aa*) or 2 of ($dbg*) or 2 of ($av*))) or
                    (2 of ($aa*) and 2 of ($dbg*)) or
                    (2 of ($av*) and (2 of ($aa*) or 2 of ($dbg*)))
                )
            )

            or

            (
                3 of ($strong*) and
                (
                    (1 of ($bot*) and 1 of ($mutex*) and (1 of ($persist*) or 2 of ($aa*) or 2 of ($dbg*) or 2 of ($av*))) or
                    (1 of ($bot*) and 1 of ($persist*) and (2 of ($aa*) or 2 of ($dbg*) or 2 of ($av*))) or
                    (1 of ($mutex*) and 1 of ($persist*) and (2 of ($aa*) or 2 of ($dbg*) or 2 of ($av*))) or
                    (1 of ($persist*) and 2 of ($aa*) and 2 of ($dbg*)) or
                    (2 of ($bot*) and 2 of ($aa*) and 2 of ($dbg*)) or
                    (2 of ($av*) and 1 of ($persist*) and (2 of ($aa*) or 2 of ($dbg*)))
                )
            )

            or

            (
                2 of ($strong*) and
                1 of ($bot*) and
                1 of ($mutex*) and
                1 of ($persist*) and
                (2 of ($aa*) or 2 of ($dbg*) or 2 of ($av*))
            )
        )
}