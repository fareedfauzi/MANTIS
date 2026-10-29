import "pe"
import "math"

rule TH_APT_EquationGroup_2026_CYFARE
{
    meta:
        author                       = "CYFARE"
        description                  = "Equation Group (G0020) APT malware detection - covers EquationDrug, GrayFish, DoubleFantasy, TripleFantasy, Fanny, GROK, nls_933w HDD firmware module, and Shadow Brokers tooling"
        reference                    = "https://cyfare.net/"
        date                         = "2026-03-19"
        version                      = "1.0.0"
        yarahub_uuid                 = "a3f1e82d-7b49-4c61-9d3a-bf5604d83c17"
        yarahub_license              = "CC0 1.0"
        yarahub_rule_matching_tlp    = "TLP:WHITE"
        yarahub_rule_sharing_tlp     = "TLP:WHITE"
        yarahub_reference_md5        = "11fb08b9126cdb4668b3f5135cf7a6c5"

    strings:
        // ---- Equation Group mutex and event names ----
        $mutex1 = "prkMtx" ascii wide
        $mutex2 = "cnFormSyncExFBC" ascii wide
        $mutex3 = "cnFormVoidFBC" ascii wide
        $mutex4 = "D0385CB7-B834-45d1-A501-1A1700E6C34E" ascii wide
        $mutex5 = "{8c38e4f3-591f-91cf-06a6-67b84d8a0102}" ascii wide

        // ---- Internal codenames (NSA program names) ----
        $code1  = "SKYHOOKCHOW" ascii wide nocase
        $code2  = "STEALTHFIGHTER" ascii wide nocase
        $code3  = "DRINKPARSLEY" ascii wide nocase
        $code4  = "STRAITACID" ascii wide nocase
        $code5  = "LUTEUSOBSTOS" ascii wide nocase
        $code6  = "STRAITSHOOTER" ascii wide nocase
        $code7  = "DESERTWINTER" ascii wide nocase
        $code8  = "Backsnarf_AB25" ascii wide
        $code9  = "SkyhookChow" ascii wide
        $code10 = "standalonegrok" ascii wide nocase
        $code11 = "URInstall" ascii wide nocase
        $code12 = "YOURBACKUP" ascii wide nocase

        // ---- Malware file artifacts ----
        $file1  = "nls_933w.dll" ascii wide
        $file2  = "mscfg32.dll" ascii wide
        $file3  = "mscfg32.exe" ascii wide
        $file4  = "msrtdv.sys" ascii wide
        $file5  = "msndsrv.sys" ascii wide
        $file6  = "tdip.sys" ascii wide
        $file7  = "win32m.sys" ascii wide
        $file8  = "lsasrv32.dll" ascii wide
        $file9  = "DOGROUND.exe" ascii wide
        $file10 = "comhost.dll" ascii wide
        $file11 = "msdtc32.exe" ascii wide
        $file12 = "AGENTCPD.DLL" ascii wide
        $file13 = "ElbyCDIO.sys" ascii wide
        $file14 = "ahlhcib.dll" ascii wide
        $file15 = "sjyntmv.dat" ascii wide
        $file16 = "ee.dll" ascii wide
        $file17 = "standalonegrok_2.1.1.1" ascii wide

        // ---- Registry persistence paths ----
        $reg1   = "MemSubSys" ascii wide
        $reg2   = "{42E14DD3-F07A-78F1-7659-26AE141569AC" ascii wide
        $reg3   = "{F4CF0326-6DCD-EEC8-5323-01CEDB66741A" ascii wide
        $reg4   = "{B6F5CD13-A74D-8B82-A6AA-6FA1BE2484C1" ascii wide
        $reg5   = "{6AF33D21-9BC5-4f65-8654-B8059B822D91}" ascii wide
        $reg6   = "DigitalProductId" ascii wide
        $reg7   = "MediaResources\\acm\\ECELP4" ascii wide
        $reg8   = "{77032DAA-B7F2-101B-A1F0-01C29183BCA1}" ascii wide
        $reg9   = "SkyhookChow Payload" ascii wide
        $reg10  = "SkyhookChow Target" ascii wide

        // ---- RC5/RC6 crypto fingerprint (unique constant representation) ----
        // Q stored as -0x61C88647 instead of 0x9E3779B9
        $crypto1 = { B9 79 37 9E }  // 0x9E3779B9 little-endian
        $crypto2 = { 63 51 E1 B7 }  // P=0xB7E15163 little-endian
        $crypto3 = { B9 86 C8 61 }  // 0x61C88647 (negated Q form)

        // ---- Equation Group crypto library signature (Kaspersky) ----
        $cryptolib = {
            37 DF E8 B6 C7 9C 0B AE 91 EF F0 3B 90 C6 80 85
            5D 19 4B 45 44 12 3C E2 0D 5C 1C 7B C4 FF D6 05
            17 14 4F 03 74 1E 41 DA 8F 7D DE 7E 99 F1 35 AC
            B8 46 93 CE 23 82 07 EB 2B D4 72 71 40 F3 B0 F7
            78 D7 4C D1 55 1A 39 83 18 FA E1 9A 56 B1 96 AB
            A6 30 C5 5F BE 0C 50 C1
        }

        // ---- C2 domain indicators (high-confidence subset) ----
        $c2_1  = "moretimeads.com" ascii wide
        $c2_2  = "ad-noise.net" ascii wide
        $c2_3  = "quik-serv.com" ascii wide
        $c2_4  = "subad-server.com" ascii wide
        $c2_5  = "newjunk4u.com" ascii wide
        $c2_6  = "ad-void.com" ascii wide
        $c2_7  = "webuysupplystore.mooo.com" ascii wide
        $c2_8  = "itemagic.net" ascii wide
        $c2_9  = "team4heat.net" ascii wide
        $c2_10 = "damavandkuh.com" ascii wide
        $c2_11 = "technicupdate.com" ascii wide
        $c2_12 = "ad-servicestats.net" ascii wide
        $c2_13 = "monster-ads.net" ascii wide
        $c2_14 = "businessdirectnessource.com" ascii wide
        $c2_15 = "phoneysoap.com" ascii wide
        $c2_16 = "dowelsobject.com" ascii wide
        $c2_17 = "cribdare2no.com" ascii wide
        $c2_18 = "mimicrice.com" ascii wide
        $c2_19 = "rubriccrumb.com" ascii wide
        $c2_20 = "cigape.net" ascii wide

        // ---- HDD firmware reprogramming strings ----
        $hdd1  = "KfAcquireSpinLock" ascii
        $hdd2  = "BINARY" wide
        $hdd3  = "nls_933w.dll" ascii

        // ---- DoubleFantasy artifact strings ----
        $df1   = "msvcp5%d.dll" ascii
        $df2   = "actxprxy.GetProxyDllInfo" ascii
        $df3   = "actxprxy.DllGetClassObject" ascii
        $df4   = "actxprxy.DllRegisterServer" ascii
        $df5   = "actxprxy.DllUnregisterServer" ascii

        // ---- DoublePulsar XOR shellcode pattern ----
        $dp_xor = {
            FD 0C 8C 5C B8 C4 24 C5
            CC CC CC 0E E8 CC 24 6B CC CC CC 0F 24 CD CC CC
            CC 27 5C 97 75 BA CD CC CC C3 FE
        }

        // ---- Injection and kernel APIs ----
        $api1  = "VirtualAllocEx" ascii wide
        $api2  = "WriteProcessMemory" ascii wide
        $api3  = "CreateRemoteThread" ascii wide
        $api4  = "DeviceIoControl" ascii wide
        $api5  = "NtQuerySystemInformation" ascii wide
        $api6  = "ZwQuerySystemInformation" ascii wide

        // ---- Network communication APIs ----
        $net1  = "InternetOpenA" ascii wide
        $net2  = "InternetConnectA" ascii wide
        $net3  = "HttpOpenRequestA" ascii wide
        $net4  = "WinHttpOpen" ascii wide

        // ---- Anti-debug / evasion ----
        $adbg1 = "IsDebuggerPresent" ascii wide
        $adbg2 = "CheckRemoteDebuggerPresent" ascii wide

    condition:
        pe.is_pe and
        pe.number_of_sections > 0 and
        (
            // --- HIGH CONFIDENCE: Equation Group specific artifacts ---
            // Any mutex/event name unique to Equation Group
            ( 1 of ($mutex*) ) or

            // Any internal NSA codename
            ( 1 of ($code*) ) or

            // Crypto library fingerprint
            ( $cryptolib ) or

            // DoublePulsar XOR shellcode
            ( $dp_xor ) or

            // HDD firmware module triad
            ( all of ($hdd*) ) or

            // DoubleFantasy artifact cluster
            ( $df1 and 3 of ($df*) ) or

            // Equation Group registry persistence paths (2+ = high confidence)
            ( 2 of ($reg*) ) or

            // --- MEDIUM CONFIDENCE: Correlated indicators ---
            // Known C2 domain + any malware file artifact
            ( 1 of ($c2_*) and 1 of ($file*) ) or

            // RC5/RC6 crypto constants + registry artifacts
            ( 2 of ($crypto*) and 1 of ($reg*) ) or

            // Multiple malware file artifacts + network capability
            ( 3 of ($file*) and 1 of ($net*) ) or

            // RC5/RC6 crypto constants + injection APIs + high entropy section
            ( 2 of ($crypto*) and 2 of ($api*) and
              for any i in (0..pe.number_of_sections - 1): (
                  pe.sections[i].raw_data_size > 4096 and
                  math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) >= 7.2
              )
            ) or

            // --- BEHAVIORAL: Equation-style kernel + injection + evasion ---
            ( 2 of ($api*) and 1 of ($net*) and 1 of ($adbg*) and 1 of ($file*) and
              for any i in (0..pe.number_of_sections - 1): (
                  pe.sections[i].raw_data_size > 4096 and
                  math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) >= 7.2
              )
            )
        )
}
