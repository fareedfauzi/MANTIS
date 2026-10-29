import "pe"

/*
    CrystalX Go RAT -- submitted loader and recovered payload YARA rule
    Author: derp.ca
    Date: 2026-05-18
    Source: https://github.com/kirkderp/yara

    Go RAT delivered through a native PE64 loader. Resource 970 unwraps
    through position-dependent XOR, ChaCha20, and raw DEFLATE into a Go
    payload with AES-GCM string obfuscation and TLS WebSocket C2.

    Detection targets:
      - Submitted loader: large RCDATA 970 payload, resource-loading imports,
        PE mapping imports, and loader PE-check code marker
      - Recovered payload: Go PE with WebSocket path, remote-access command
        vocabulary, persistence prefix, and build support markers

    Hashes:
        Loader: 34b84db8f10d34f711bb242b21bdf662ee489dcd0e9c23b9cc95240d324bb094
        Payload: a9340c46243f5d2b00e30ea649bd14fc146ebbb42e43dbe45f5ee0cc9fc9227a
*/

rule CrystalX_Go_RAT
{
    meta:
        id = "2E5Zyysv2Iz6BmV29zdqCH"
        fingerprint = "05d5c92b7cae0f32da96d4f05272136894c1f161041fd87d2824d0aac45f90ed"
        version = "2.0"
        date = "2026-05-18"
        modified = "2026-05-19"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "https://github.com/kirkderp/yara"
        author = "derp.ca"
        description = "CrystalX submitted loader and recovered Go payload rule targeting RCDATA 970 loader structure, PE-check code, WebSocket path, command vocabulary, and build support markers."
        category = "MALWARE"
        malware = "CRYSTALX"
        malware_type = "RAT"
        mitre_att = "T1055.012"
        reference = "https://github.com/kirkderp/yara"
        triage_score = 10
        triage_description = "CrystalX submitted loader and recovered Go payload with RCDATA 970 loader structure, PE-check code, WebSocket path, and remote-access command vocabulary."
        yarahub_uuid = "9b56434e-3bd2-4dfa-80bf-4d7f59c552f9"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "1fc32ba003f385deca86e5ccf8d6ae43"

    strings:
        // Loader code markers
        $loader_pe_check = { 66 81 38 4D 5A 75 ?? 48 63 50 3C 48 01 D0 81 38 50 45 00 00 74 }

        // Payload/runtime layer
        $go_build = "Go buildinf:" ascii
        $proto_ws_path = "/api/ws" ascii

        // Remote desktop / interaction command fragments
        $cmd_rd_start = "rd_start" ascii
        $cmd_rd_block = "rd_block" ascii
        $cmd_rd_input = "rd_input" ascii
        $cmd_rd_list = "rd_list_" ascii
        $cmd_webcam_start = "webcam_s" ascii
        $cmd_webcam_list = "webcam_l" ascii

        // File manager / collection command fragments
        $cmd_fm_drive = "fm:drive" ascii
        $cmd_fm_ls = "fm:ls:" ascii
        $cmd_fm_del = "fm:del:" ascii
        $cmd_clipboard_set = "clipboard:set:" ascii
        $cmd_steal_manual = "steal:manual" ascii
        $cmd_software_uninstall = "software:uninstall:" ascii

        // Build and environment markers
        $support_task_prefix = "NvContainerTask_" ascii
        $support_build_id = "YBFZUW1U32T" ascii
        $support_string_key = "Hk4fOCLbqKFbbAxwyAcFKUKXK4iqVaMD" ascii
        $support_wc_elv = "WC_ELV" ascii
        $support_geo = "ip-api.com" ascii

    condition:
        uint16(0) == 0x5a4d and
        (
            (
                filesize > 2MB and filesize < 4MB and
                pe.machine == pe.MACHINE_AMD64 and
                pe.number_of_sections == 11 and
                pe.imports("KERNEL32.dll", "FindResourceW") and
                pe.imports("KERNEL32.dll", "LoadResource") and
                pe.imports("KERNEL32.dll", "LockResource") and
                pe.imports("KERNEL32.dll", "VirtualProtect") and
                pe.imports("KERNEL32.dll", "GetProcAddress") and
                pe.imports("KERNEL32.dll", "LoadLibraryA") and
                pe.imports("WS2_32.dll", "WSAStartup") and
                for any i in (0..pe.number_of_resources - 1): (
                    pe.resources[i].type == pe.RESOURCE_TYPE_RCDATA and
                    pe.resources[i].id == 970 and
                    pe.resources[i].length > 2MB
                ) and
                $loader_pe_check
            )
            or
            (
                filesize > 4MB and filesize < 20MB and
                $go_build and
                $proto_ws_path and
                7 of ($cmd_*) and
                2 of ($support_*)
            )
        )
}
