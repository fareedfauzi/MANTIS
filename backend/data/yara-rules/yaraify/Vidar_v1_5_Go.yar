import "pe"

/*
    Vidar v1.5 Go Infostealer -- submitted build YARA rule
    Author: derp.ca
    Date: 2026-05-16
    Source: https://github.com/kirkderp/yara

    Targets the submitted Go 1.25.4 Vidar v1.5 PE and related memory/runtime
    strings from the same case. The on-disk branch is build scoped because the
    strongest static identifiers are Go build metadata and runtime/API layout.
    Memory branches cover sandbox scoring, dead-drop C2 discovery, multipart
    exfil fields, botnet ID, and AV process enumeration.

    SHA256: 2995ffb73342453b258926ec865c724e3567eee1bb8eb35d61796ee0c4f25105
    Triage: 10/10 (vidar)
    Version: 1.5
    Botnet: 702ef1b4007f07887e9faaee0667b50b
*/

rule Vidar_v1_5_Go
{
    meta:
        id = "2Vxzpyv1AK7DWVq2sf4tW7"
        fingerprint = "9d4b9b4d3083797b9cbf5d486b47a321c9b497491250197b11a6e8429c72c7a3"
        version = "2.0"
        date = "2026-05-16"
        modified = "2026-05-19"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "https://github.com/kirkderp/yara"
        author = "derp.ca"
        description = "Submitted Vidar v1.5 Go build and memory/runtime rule with Go build metadata, native API layout, sandbox scoring strings, Telegram/Steam dead drops, multipart exfil fields, botnet ID, and AV process enumeration."
        category = "MALWARE"
        malware = "VIDAR"
        malware_type = "INFOSTEALER"
        mitre_att = "T1555.003"
        reference = "https://github.com/kirkderp/yara"
        triage_score = 10
        triage_description = "Vidar v1.5 Go submitted build and memory/runtime indicators with sandbox scoring, Telegram/Steam dead drops, multipart exfil, and AV process enumeration."
        yarahub_uuid = "1d0f5130-065b-41e2-b6c4-3ae5e2e04c6b"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "87332fcdf79e1c0bfb7713e9a52c0313"

    strings:
        // Go build ID (unique per-compile, embedded in binary)
        $go_build_id = "3pICFQ04tHLo5t8EsOnB" ascii

        // Go 1.25.4 version marker
        $go_version = "go1.25.4" ascii

        // Characteristic DLL name strings found in Go runtime error blob
        $dll_ntdll = "ntdll.dll" ascii
        $dll_kernel32 = "kernel32.dll" ascii
        $dll_crypt32 = "crypt32.dll" ascii
        $dll_secur32 = "secur32.dll" ascii
        $dll_userenv = "userenv.dll" ascii
        $dll_ws2_32 = "ws2_32.dll" ascii
        $dll_advapi32 = "advapi32.dll" ascii
        $dll_iphlpapi = "iphlpapi.dll" ascii

        // Go runtime helpers this binary uses
        $rtl_getversion = "RtlGetVersion" ascii
        $rtl_getpeb = "RtlGetCurrentPeb" ascii
        $proc_prng = "ProcessPrng" ascii
        $time_begin = "timeBeginPeriod" ascii
        $hex_lower = "0123456789abcdef" ascii
        $nt_create_wait = "NtCreateWaitCompletionPacket" ascii
        $nt_assoc_wait = "NtAssociateWaitCompletionPacket" ascii

        // Sandbox scoring categories (Vidar-specific naming, memory/dump only)
        $sb_internet = "sb: internet" ascii
        $sb_debugger = "sb: debugger" ascii
        $sb_peb = "sb: peb_flags" ascii
        $sb_cpus = "sb: cpus" ascii
        $sb_rdtsc = "sb: rdtsc" ascii
        $sb_modules = "sb: modules" ascii
        $sb_ram = "sb: ram" ascii
        $sb_disk = "sb: disk" ascii
        $sb_user = "sb: user" ascii
        $sb_av = "sb: av_sandbox" ascii
        $sb_pc = "sb: pc" ascii
        $sb_uptime = "sb: uptime" ascii
        $sb_score = "sb: score" ascii

        // Dead drop C2 logging
        $dead_drop = "Dead drop: %s (sw: %s)" ascii
        $sw_version = "(sw: %s)" ascii

        // C2 multipart form template (Vidar-specific field names)
        $multipart_hwid = "name=\"hwid\"" ascii
        $multipart_build_id = "name=\"build_id\"" ascii
        $multipart_boundary = "Content-Type: multipart/form-data; boundary=" ascii

        // C2 domains/URLs
        $telegram_c2 = "telegram.me" ascii
        $steam_c2 = "steamcommunity.com" ascii
        $c2_ip = "135.181.237.59" ascii

        // User-Agent strings
        $ua_mac = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:140.0) Gecko/20100101 Firefox/140.0" ascii
        $ua_win = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:153.0) Gecko/20100101 Firefox/153.0" ascii

        // AV process blacklist
        $av_avast = "AvastSvc.exe" ascii
        $av_eset = "ekrn.exe" ascii
        $av_kaspersky = "avp.exe" ascii
        $av_defender = "MsMpEng.exe" ascii
        $av_bitdefender = "bdagent.exe" ascii
        $av_norton = "NortonSecurity.exe" ascii
        $av_mcafee = "coreServiceShell.exe" ascii
        $av_mbam = "MBAMService.exe" ascii
        $av_trend = "PccNTMon.exe" ascii

        // Botnet marker
        $botnet_id = "702ef1b4007f07887e9faaee0667b50b" ascii

    condition:
        uint16(0) == 0x5A4D
        and pe.machine == pe.MACHINE_AMD64
        and filesize > 5MB and filesize < 10MB
        and (
            // On-disk submitted build: Go metadata + native API layout
            ($go_build_id and $go_version and $rtl_getversion and $rtl_getpeb and $hex_lower
             and 3 of ($dll_ntdll, $dll_kernel32, $dll_crypt32, $dll_secur32,
                       $dll_ws2_32, $dll_advapi32, $dll_iphlpapi, $dll_userenv))
            or
            // On-disk submitted build: Go metadata + native wait/random/timer API layout
            ($go_build_id and $go_version and $nt_create_wait and $nt_assoc_wait
             and $proc_prng and $time_begin and 2 of ($dll_ntdll, $dll_kernel32))
            or
            // Memory/dump: sandbox scoring system (strong Vidar indicator)
            (5 of ($sb_internet, $sb_debugger, $sb_peb, $sb_cpus, $sb_rdtsc, $sb_modules,
                   $sb_ram, $sb_disk, $sb_user, $sb_av, $sb_pc, $sb_uptime, $sb_score)
             and 2 of ($dead_drop, $multipart_hwid, $multipart_build_id, $multipart_boundary))
            or
            // Memory/dump: C2 dead drop discovery + exfil pattern
            ((1 of ($telegram_c2, $steam_c2) or $c2_ip)
             and 2 of ($multipart_hwid, $multipart_build_id, $multipart_boundary, $dead_drop)
             and ($sw_version or 1 of ($ua_mac, $ua_win)))
            or
            // Memory/dump: botnet ID + AV process enumeration
            ($botnet_id and 4 of ($av_avast, $av_eset, $av_kaspersky, $av_defender,
                                  $av_bitdefender, $av_norton, $av_mcafee, $av_mbam, $av_trend))
        )
}
