import "pe"

/*
    DeadLock ransomware -- submitted-build YARA rule
    Author: derp.ca
    Date: 2026-06-21
    Source: https://github.com/kirkderp/yara

    Targets the observed 32-bit Windows DeadLock ransomware sample from
    Triage task 260621-velt4aes3r. The rule avoids the embedded Session
    contact ID and contract value because those are campaign-changeable.

    Detection targets:
      - Submitted PE: DeadLock ransom-note and HTML recovery template,
        .dlock extension handling, static recovery filenames, Windows
        disruption API-name clusters, process/service/path exclusion
        config, and code bytes from config parsing and recovery setup.

    Hashes:
        Submitted PE: c9cc95ff8f2998229394dfd31c2bd6b723e826a3ca5e008d2b5be19ba419ae2c
*/

rule DeadLock_Ransomware
{
    meta:
        id = "Dlk260621RansomYara001"
        fingerprint = "c9cc95ff8f2998229394dfd31c2bd6b723e826a3ca5e008d2b5be19ba419ae2c"
        version = "1.0"
        date = "2026-06-21"
        modified = "2026-06-21"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "https://github.com/kirkderp/yara"
        author = "derp.ca"
        description = "Submitted 32-bit Windows DeadLock ransomware build with DeadLock recovery template, .dlock extension handling, Windows disruption API-name clusters, process/service/path exclusion config, and supporting code bytes."
        category = "MALWARE"
        malware = "DEADLOCK"
        malware_type = "RANSOMWARE"
        mitre_att = "T1486"
        reference = "https://tria.ge/260621-velt4aes3r"
        triage_score = 10
        triage_description = "DeadLock ransomware build with .dlock extension handling, RECOVERY_CHAT/HOW_RECOVER notes, embedded HTML chat recovery page, privilege/event-log/service-control API clusters, and static exclusion config."
        yarahub_uuid = "7b4c7e2b-cc65-4a10-82e2-82143dd34d5d"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "4374eb7807fbcb767ae3a6202b4dd8f8"

    strings:
        $note_deadlocked = "Your infrastructure DeadLocked All Files stolen and encrypted" ascii
        $note_unlock = "Instructions to unlock in '" ascii
        $note_personal = "# Your personal ID: {_UID}[NL][NL]# Your company's network is attacked" ascii
        $note_recovery = "RECOVERY_CHAT.{_UID}.HTML" ascii
        $note_payment = "# We accept Bitcoin/Monero[NL]# Attention!" ascii

        $html_title = "<title>Deadlock - data is safe, sure</title>" ascii
        $html_brand = "<l>DeadLock</l><r>{_UID}</r>" ascii
        $html_notice = "Your important files have been encrypted by DeadLock using military-grade encryption" ascii
        $html_stolen = "encrypted and STOLEN" ascii
        $html_lib_protobuf = "cdn.jsdelivr.net/npm/protobufjs/dist/protobuf.min.js" ascii
        $html_lib_nacl = "cdnjs.cloudflare.com/ajax/libs/js-nacl/1.4.0/nacl_factory.js" ascii
        $html_chat_snodes = "sendProxy(\"get_snodes\"" ascii
        $html_chat_swarms = "sendProxy(\"get_swarms\"" ascii
        $html_chat_store = "sendProxy(\"store\"" ascii
        $html_chat_poll = "sendProxy(\"poll\"" ascii

        $file_ext = ".dlock" ascii
        $file_recovery = "RECOVERY_CHAT" ascii
        $file_recover = "HOW_RECOVER" ascii
        $file_uid_html = "{_UID}.html" ascii
        $file_public_desktop = "Users\\Public\\Desktop\\" ascii

        $api_priv = "GetCurrentProcessOpenProcessTokenSeDebugPrivilege" ascii
        $api_priv_restore = "SeRestorePrivilege" ascii
        $api_priv_backup = "SeBackupPrivilege" ascii
        $api_priv_take_ownership = "SeTakeOwnershipPrivilege" ascii
        $api_adjust = "AdjustTokenPrivilegesLookupPrivilegeValueA" ascii
        $api_volume = "FindVolumeCloseFindNextVolumeWFindFirstVolumeWSetVolumeMountPointWGetVolumePathNamesForVolumeNameW" ascii
        $api_eventlog = "EvtOpenChannelEnumEvtNextChannelPathEvtCloseOpenEventLogWClearEventLogWCloseHandle" ascii
        $api_services = "OpenSCManagerAEnumServicesStatusExWControlServiceOpenServiceWChangeServiceConfigWCloseServiceHandle" ascii
        $api_process = "CreateToolhelp32SnapshotProcess32FirstProcess32NextOpenProcessTerminateProcess" ascii
        $api_crypto_file = "GlobalMemoryStatusExGetSystemTimesCryptGenRandomCryptReleaseContextCryptAcquireContextWCreateFileWWriteFileDeleteFileWGetFileAttributesW" ascii
        $api_wallpaper = "RegOpenKeyExARegCloseKeyRegSetValueExASOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\SystemWallpaper" ascii
        $api_gdi = "GetDCReleaseDCCreateCompatibleDCCreateCompatibleBitmapDeleteDCSelectObjectSetBkModeSetTextColorGetDIBitsDeleteObjectTextOutWCreateFontWArialBMSystemParametersInfoW.bmp" ascii

        $cfg_processes = "anydesk,applicationframehost,certsrv,clussvc,cmd,conhost,csrss,ctfmon" ascii
        $cfg_services_user = "UdkUserSvc*,DevicesFlowUserSvc*,AarSvc*,WpnUserService*,CDPUserSvc*" ascii
        $cfg_services_defender = "WinDefend,WSRM,WINS,silsvc,WaaSMedicSvc" ascii
        $cfg_extensions = ".386,.adv,.ani,.bat,.bin,.cab,.cmd,.com,.cpl,.cur" ascii
        $cfg_system_files = "\\GDIPFONTCACHEV1.DAT,\\autorun.inf,\\boot.ini,\\bootfont.bin" ascii
        $cfg_paths = "$recycle.bin,$windows.~bt,$windows.~ws,Users\\All Users\\application data" ascii

        $support_rust = "RUST_MIN_STACK" ascii
        $support_chacha = "expand 32-byte k" ascii
        $support_ntquery_dir = "NtQueryDirectoryFile" ascii
        $support_ntset_info = "NtSetInformationFile" ascii

        $code_config_parse = {
            55 53 57 56 81 EC CC 00 00 00 BA ?? ?? ?? ?? 8D BC 24 8C 00 00 00
            89 4C 24 18 89 F9 68 E8 FD 00 00 E8 ?? ?? ?? ?? 58 8B 77 04
            8D 9C 24 A4 00 00 00 89 D9 89 F2 6A 60 FF 77 08 E8 ?? ?? ?? ??
            58 59 89 D9 E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 89 C5 89 D7
            6A 04 59 89 CA 6A 08 E8 ?? ?? ?? ?? 59 89 D3 89 E1 89 2A 89 7A 04
        }

        $code_dlock_recovery = {
            8D 7C 24 70 89 5C 24 28 BA ?? ?? ?? ?? 89 F9 6A 10 E8 ?? ?? ?? ??
            58 8D B4 24 EC 03 00 00 BA ?? ?? ?? ?? 89 F1 6A 06 E8 ?? ?? ?? ??
            58 8D 8C 24 E0 01 00 00 89 F2 E8 ?? ?? ?? ?? 31 C0 3B 07
            0F 81 ?? ?? ?? ?? 8B 84 24 E0 01 00 00 F7 D8 0F 81 ?? ?? ?? ??
        }

        $code_dynamic_api = {
            55 53 57 56 83 EC 1C E8 ?? ?? ?? ?? A8 01 0F 84 ?? ?? ?? ??
            89 D1 BA ?? ?? ?? ?? 6A 11 E8 ?? ?? ?? ?? 59 89 C6 E8 ?? ?? ?? ??
            A8 01 74 ?? 89 D1 89 D5 E8 ?? ?? ?? ?? 8D 7C 24 10 89 44 24 08
            BA ?? ?? ?? ?? 89 F9 6A 13 E8 ?? ?? ?? ?? 58 89 F9 31 D2 31 DB
            E8 ?? ?? ?? ??
        }

    condition:
        uint16(0) == 0x5A4D and
        filesize > 200KB and filesize < 400KB and
        pe.machine == pe.MACHINE_I386 and
        pe.number_of_sections == 4 and
        pe.imports("KERNEL32.dll", "GetProcAddress") and
        pe.imports("KERNEL32.dll", "CreateFileW") and
        pe.imports("KERNEL32.dll", "MoveFileExW") and
        pe.imports("ntdll.dll", "NtWriteFile") and
        pe.imports("ntdll.dll", "NtReadFile") and
        3 of ($note_*) and
        4 of ($html_*) and
        3 of ($file_*) and
        5 of ($api_*) and
        4 of ($cfg_*) and
        2 of ($support_*) and
        1 of ($code_*)
}
