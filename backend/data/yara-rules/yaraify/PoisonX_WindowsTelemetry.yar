import "pe"

/*
    PoisonX WindowsTelemetry -- case chain YARA rule
    Author: derp.ca
    Date: 2026-05-19
    Source: https://github.com/kirkderp/yara

    Targets the observed WindowsTelemetry chain: VERSION.dll sideload loader,
    rolling-XOR scheduler/cache blobs, decoded BYOVD scheduler, and decoded
    10FX RAT core. Scheduler and RAT branches include code anchors from the
    decoded DLLs plus exports and protocol/task/plugin evidence.

    Detection targets:
      - VERSION.dll loader: small x64 DLL with scheduler cache references
      - Raw cache blobs: rolling-XOR encoded cache headers
      - Decoded scheduler: SetSuspendState export, scheduler code bytes,
        WindowsTelemetry persistence, driver-blocklist and callback-removal evidence
      - Decoded RAT core: StartPayload export, plugin/config code bytes,
        10FX protocol, RAT task vocabulary, and plugin cache/request markers

    Hashes:
        VERSION.dll: 62431e499db7c6a02e93c5f9c79fbcff954144db1b016695d3f34f30c89d0b44
        VERSION.dll: 0ea1335fefc490622dae07b1a5936a539fa4152f89b64f4b270c8e23846deba6
        Decoded scheduler: c07573810f5f4578315681ca9108ada8a56eefc1b4786b4e93b54b7abf4b028c
        Decoded RAT core: 0f841b7bddf9788589fce191bb3e7f9f52ec76adb67ff8c360618df8745ee320
*/

rule PoisonX_WindowsTelemetry
{
    meta:
        id = "4D836ABE06CF42568E2EE4"
        fingerprint = "663a4ef0fbe353750e5950c91c9de20df0e7fdfa33e0921b91cbce54df5d9929"
        version = "2.0"
        date = "2026-05-19"
        modified = "2026-05-19"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "https://github.com/kirkderp/yara"
        author = "derp.ca"
        description = "PoisonX WindowsTelemetry case rule for VERSION.dll loader, rolling-XOR cache blobs, decoded BYOVD scheduler, and decoded 10FX RAT core."
        category = "MALWARE"
        malware = "POISONX"
        malware_type = "RAT"
        mitre_att = "T1574.002"
        reference = "https://github.com/kirkderp/yara"
        triage_score = 10
        triage_description = "PoisonX WindowsTelemetry chain with sideload loader, rolling-XOR cache blobs, BYOVD scheduler, and 10FX RAT core."
        yarahub_uuid = "4d836abe-06cf-4256-8e2e-e4145fdddc29"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "b327aa9db2451507af259642ae840bdc"

    strings:
        $ldr_pdb = "xml_loader.pdb" ascii
        $ldr_dll = "xml_loader.dll" ascii
        $ldr_cache = "scheduler.cache" ascii
        $ldr_encoded_cache = "z2)%)./8%>3(zscheduler.cache" ascii

        $raw_seed_29_hdr = { 29 64 70 BB 2C 2E 2E 2F 30 35 32 33 34 CA C9 37 38 81 3A 3B 3C 3D 3E 3F 40 01 42 43 44 45 }
        $raw_seed_4a_hdr = { 4A 07 11 DC 4D 4D 4F 50 51 56 53 54 55 A9 A8 58 59 E2 5B 5C 5D 5E 5F 60 61 22 63 64 65 66 }

        $code_sch_export_stub = { 48 83 EC 38 49 89 D0 48 8D 44 24 34 83 20 00 48 89 44 24 20 BA 44 20 10 80 4D 89 C1 E8 ?? ?? ?? ?? 90 48 83 C4 38 C3 }
        $code_sch_dllmain = { 56 48 83 EC 20 48 89 CE FF 15 ?? ?? ?? ?? 85 C0 75 1D E8 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? BA 8D 42 9E D2 E8 ?? ?? ?? ?? 48 }
        $sch_persist = "\\Microsoft\\WindowsTelemetry" ascii
        $sch_service = "WinHealthSvc" ascii
        $sch_blocklist = "VulnerableDriverBlocklistEnable" ascii
        $sch_cb_process = "PsSetCreateProcessNotifyRoutine" ascii
        $sch_cb_thread = "PsSetCreateThreadNotifyRoutine" ascii
        $sch_cb_image = "PsSetLoadImageNotifyRoutine" ascii
        $sch_byovd_log = "[byovd] driver blocklist disabled" ascii
        $sch_startpayload = "StartPayload export not found" ascii

        $code_rat_plugin_load = { 41 57 41 56 41 55 41 54 55 57 56 53 48 81 EC 38 02 00 00 48 8D 05 ?? ?? ?? ?? 8B B4 24 A0 02 00 00 48 85 C9 44 89 C5 49 89 CD 49 89 D6 48 0F 45 C1 }
        $code_rat_process_data = { 41 57 41 56 41 55 41 54 55 57 56 53 48 83 EC 78 4D 89 C4 45 8B 00 49 89 CD 48 89 D5 41 83 F8 0B 0F 8E ?? ?? ?? ?? 48 8D 35 ?? ?? ?? ?? }
        $code_rat_json_get = { 41 57 41 56 41 55 41 54 55 57 56 53 48 81 EC D8 00 00 00 0F 11 74 24 70 0F 11 BC 24 80 00 00 00 44 0F 11 84 24 90 00 00 00 }
        $rat_proto = "10FX" ascii
        $rat_task_shell = "SHELL_EXEC" ascii
        $rat_task_service = "CONTROL_SERVICE" ascii
        $rat_task_window = "CONTROL_WINDOW" ascii
        $rat_task_socks = "SOCKS5_START" ascii
        $rat_task_update = "SELF_UPDATE_PAYLOAD" ascii
        $rat_plugin_entry = "PluginEntry" ascii
        $rat_plugin_load = "LoadEncrypted: name=" ascii
        $rat_plugin_cache = "%s\\plugin.dat" ascii
        $rat_plugin_req = "{\"plugin\":\"%s\"}" ascii

    condition:
        (
            (filesize == 355420 or filesize == 557230) and
            any of ($raw_seed_*)
        )
        or
        (
            uint16(0) == 0x5A4D and
            (
                (
                    filesize < 20KB and
                    pe.is_dll() and
                    pe.machine == pe.MACHINE_AMD64 and
                    all of ($ldr_*)
                )
                or
                (
                    filesize > 300KB and filesize < 400KB and
                    pe.is_dll() and
                    pe.machine == pe.MACHINE_AMD64 and
                    pe.exports("SetSuspendState") and
                    1 of ($code_sch_*) and
                    $sch_blocklist and
                    2 of ($sch_cb_*) and
                    2 of ($sch_persist, $sch_service, $sch_startpayload, $sch_byovd_log)
                )
                or
                (
                    filesize > 500KB and filesize < 600KB and
                    pe.is_dll() and
                    pe.machine == pe.MACHINE_AMD64 and
                    pe.exports("StartPayload") and
                    2 of ($code_rat_*) and
                    $rat_proto and
                    4 of ($rat_task_*) and
                    2 of ($rat_plugin_*)
                )
            )
        )
}
