import "pe"

/*
    SilverFox-style Panasonic/Sauron loader chain -- case-chain YARA rule
    Author: derp.ca
    Date: 2026-06-21
    Source: https://github.com/kirkderp/yara

    Targets the observed Panasonic PC Notification wrapper chain from
    Triage task 260619-v47g4ah12k. The chain moves through an early
    staged loader, Alibaba OSS image-named carriers, a UxEnhance
    side-load bundle, RPC Task Scheduler staging, an adoresd.dll bridge,
    a Philips D1/XPSPLOG cluster, and rundll32.dat!Edge Sauron behavior.

    Detection targets:
      - Submitted Panasonic wrapper with staged-loader copy/jump bytes
      - Decoded heap payload with Defender exclusion and VBS helper strings
      - First-bucket image-named carrier files with observed trailer grammar
      - UxEnhance64.dll side-loaded protected DLL
      - msadox.tb and adoresd.dat carrier material
      - RPCScheduleTask.dll / VirtuOne scheduler module
      - adoresd.dll bridge and populated bridge module
      - Philips image.dll prep/dropper and rundll32.dat!Edge Sauron stage

    Hashes:
        Submitted EXE: 200d9f5d041c870e69f73da32c753a69096742c33e2dab65299767ac31578267
        Heap payload: 679921a7373fc0a77d60416e3f7ce4454dfd394c12d9c0387be9538b8f030e02
        UxEnhance64.dll: cc6ae6f13d33a7313295ae00a6b0503adc277289fbe615eaf48b6a30ce09f11c
        RPCScheduleTask.dll: a1e68e7adc5597eae23a6590f1ac345f796abebceb91afcc0f2dd97cc0622740
        adoresd.dll: aaa13e34e7c45dc49552e843ee8b611b2373959d8a7cc23265abc353d76235ba
        rundll32.dat: 4f67662ae285337b17e537147e4783a6f307b25d61b362e7908b2595c4188f2a
*/

rule SilverFox_Panasonic_Sauron_Loader
{
    meta:
        id = "R0rLXDygiD7cQ19ZhTfUfU"
        fingerprint = "328613de459f24ac11520ca846c69b68cc72833f554e476e9ff267e87c1f53a4"
        version = "1.0"
        date = "2026-06-21"
        modified = "2026-06-21"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "https://github.com/kirkderp/yara"
        author = "derp.ca"
        description = "SilverFox-style Panasonic/Sauron loader chain targeting the staged Panasonic wrapper, image-named Alibaba OSS carriers, UxEnhance side-load bundle, RPC scheduler module, adoresd bridge, Philips D1 cluster, and rundll32.dat Edge/Sauron stage."
        category = "MALWARE"
        malware = "SILVERFOX"
        malware_type = "LOADER"
        mitre_att = "T1574.002"
        reference = "https://www.derp.ca/research/silverfox-panasonic-sauron-loader-chain/"
        triage_score = 10
        triage_description = "SilverFox-style Panasonic/Sauron loader chain with staged loader, Alibaba OSS carrier grammar, side-loaded UxEnhance64.dll, RPC Task Scheduler payload, adoresd bridge, and Sauron Edge stage."
        yarahub_uuid = "b79241c5-00ed-4202-a361-b4f8d6af1e02"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "98a7f905b18359626152c22ba906b3b7"

    strings:
        // Submitted Panasonic wrapper and early staged loader
        $outer_pdb = "D:\\a\\1\\s\\src\\x64\\Release\\PPcNotif.Provider.RequiredApp.pdb" ascii
        $outer_panasonic = "Panasonic PC Notification" wide ascii
        $outer_marker = { 2A 2F 26 FE C8 54 11 D1 7C 90 FE FE 8B 9B 99 9B }
        $outer_marker_host = "ale616" ascii
        $outer_stage = { E8 28 CE 00 00 90 82 6E 71 9C 8F 83 1B 70 9B 6C 10 DB 95 73 36 }
        $outer_alloc_copy = { 33 C9 44 8D 49 40 BA 59 CE 00 00 41 B8 00 10 00 00 48 FF 15 ?? ?? ?? ?? 48 85 C0 74 ?? 49 89 C5 48 8D 35 ?? ?? ?? ?? 4C 89 EF B9 59 CE 00 00 89 CA C1 E9 02 AD AB FF C9 75 FA 83 E2 03 74 06 AC AA FF CA 75 FA 41 FF E5 }

        // Decoded heap payload
        $heap_kernel32 = "kernel32.dll" ascii
        $heap_powershell = "powershell.exe" ascii
        $heap_defender_icim = "MSFT_MpPreference @{ExclusionPath" ascii
        $heap_defender_add = "Add-MpPreference -ExclusionPath" ascii
        $heap_checktime = "checktime.vbs" ascii
        $heap_runas = "runas" ascii

        // First-bucket and later carrier grammar
        $jfif = { FF D8 FF E0 00 10 4A 46 49 46 00 }
        $png = { 89 50 4E 47 0D 0A 1A 0A }
        $sqlite = "SQLite format 3" ascii
        $msadox_marker = { BB E6 36 23 33 96 3B 89 }

        // Ux side-load bundle
        $ux_name = "UxEnhance64.dll" ascii
        $ux_sec_ias = ".Ias" ascii
        $ux_sec_lux = ".LUx" ascii
        $ux_sec_of = ".\\OF" ascii

        // RPC scheduler payload from s.jpg
        $rpc_name = "RPCScheduleTask.dll" ascii
        $rpc_virtuone = "VirtuOne" ascii
        $rpc_ndr = "NdrClientCall3" ascii
        $rpc_binding = "RpcStringBindingComposeW" ascii

        // adoresd.dll bridge and populated bridge module
        $ador_export = "DelegateEnSerialization" ascii
        $ador_name = "adoresd.dll" ascii
        $bridge_registry = "Software\\ODBDC" ascii
        $bridge_task1 = "cmd.exe /c SCHTASKS /Create /F /TN \"Task1\"" ascii
        $bridge_hangzhou = "-cn-hangzhou.ali" ascii
        $bridge_drops = ".yuncs.com/drops" ascii
        $bridge_getdata = "GetData" ascii
        $bridge_ranchserv = "C:\\Windows\\Temp\\ranchserv.jpg" ascii
        $bridge_edge_task = "MicrosoftEdgeUpdateTaskMachineCore1{" ascii

        // Philips D1/image.dll prep stage
        $d1_alibaba = "Alibaba SecurityHealth" ascii
        $d1_host = "C:\\Program Files (x86)\\D1IQf1\\D1IQf1.exe" ascii
        $d1_image = "image.png" ascii
        $d1_thumbs = "thumbs.db" ascii
        $d1_xpsplog = "XPSPLOG.dll" ascii
        $d1_raw_sec_az = ".az*" ascii
        $d1_raw_sec_j7 = ".+j7" ascii
        $d1_raw_sec_k = ".k]\\" ascii

        // rundll32.dat!Edge / Sauron stage
        $sauron_name = "Sauron" ascii
        $sauron_rundll = "rundll32.dat" ascii
        $sauron_reg_delete = "reg delete HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services\\Sauron /va /f" ascii
        $sauron_edge_log = "C:\\ProgramData\\Microsoft\\EdgeUpdate\\Log\\kill.bat" ascii
        $sauron_bootsect = "C:\\ProgramData\\Microsoft\\eHome\\BOOTSECT.exe" ascii
        $sauron_firewall = "NetSh Advfirewall set allprofiles state off" ascii

    condition:
        (
            // Submitted Panasonic wrapper: huge .data stage plus staged-copy code and marker bytes.
            uint16(0) == 0x5A4D and
            filesize > 70MB and filesize < 80MB and
            pe.machine == pe.MACHINE_AMD64 and
            pe.number_of_sections == 6 and
            pe.imports("KERNEL32.dll", "VirtualAlloc") and
            pe.imports("KERNEL32.dll", "ReadFile") and
            $outer_pdb and
            $outer_panasonic and
            $outer_marker and $outer_marker_host and
            $outer_stage and $outer_alloc_copy
        )
        or
        (
            // Decoded heap payload recovered from the staged loader.
            filesize > 40KB and filesize < 50KB and
            uint32(0) == 0x000500E9 and
            uint8(4) == 0x00 and
            $heap_kernel32 and $heap_powershell and
            3 of ($heap_defender_*, $heap_checktime, $heap_runas)
        )
        or
        (
            // First Alibaba OSS image-named JPEG carriers: observed exact sizes and EOF trailer grammar.
            (filesize == 140021 or filesize == 3278261 or filesize == 9286 or filesize == 5037946) and
            $jfif at 0 and
            uint32(filesize - 5) == 0x000003A0 and
            uint8(filesize - 1) == 0x45
        )
        or
        (
            // s.jpg PNG carrier for the compressed VirtuOne payload.
            filesize == 83215 and
            $png at 0 and
            uint32(filesize - 5) == 0x00002140 and
            uint8(filesize - 1) == 0xA8
        )
        or
        (
            // UxEnhance64.dll: protected side-loaded DLL with Ux exports and unusual section names.
            uint16(0) == 0x5A4D and
            filesize > 3MB and filesize < 4MB and
            pe.machine == pe.MACHINE_AMD64 and
            pe.is_dll() and
            pe.exports("?EnableUxEnhance@@YA_NXZ") and
            pe.exports("?DisableUxEnhance@@YA_NXZ") and
            pe.imports("KERNEL32.dll", "ReadFile") and
            $ux_name and 3 of ($ux_sec_*)
        )
        or
        (
            // msadox.tb: SQLite-looking opaque loader material with the marker used before RC4 shellcode decode.
            filesize == 8353 and
            $sqlite at 0 and
            $msadox_marker
        )
        or
        (
            // adoresd.dat: PNG carrier for sparse adoresd.dll bridge.
            filesize == 5037013 and
            $png at 0 and
            uint32(filesize - 5) == 0x000005D0 and
            uint8(filesize - 1) == 0xF8
        )
        or
        (
            // RPCScheduleTask.dll recovered from s.jpg: VirtuOne export plus Task Scheduler RPC imports.
            uint16(0) == 0x5A4D and
            filesize > 100KB and filesize < 200KB and
            pe.machine == pe.MACHINE_AMD64 and
            pe.is_dll() and
            pe.exports("VirtuOne") and
            pe.imports("RPCRT4.dll", "NdrClientCall3") and
            pe.imports("RPCRT4.dll", "RpcStringBindingComposeW") and
            2 of ($rpc_*)
        )
        or
        (
            // Decoded sparse adoresd.dll bridge.
            uint16(0) == 0x5A4D and
            filesize > 4MB and filesize < 6MB and
            pe.machine == pe.MACHINE_AMD64 and
            pe.is_dll() and
            pe.exports("DelegateEnSerialization") and
            $ador_export and $ador_name
        )
        or
        (
            // Populated Ux bridge image with Task1, 26nn/drops fragments, GetData, and adoresd bridge strings.
            uint16(0) == 0x5A4D and
            filesize > 8MB and filesize < 10MB and
            pe.machine == pe.MACHINE_AMD64 and
            pe.is_dll() and
            $ador_export and $ador_name and
            $bridge_task1 and
            3 of ($bridge_hangzhou, $bridge_drops, $bridge_getdata, $bridge_registry) and
            1 of ($bridge_ranchserv, $bridge_edge_task)
        )
        or
        (
            // Raw decoded Philips image.dll prep/dropper layer.
            uint16(0) == 0x5A4D and
            filesize > 4MB and filesize < 6MB and
            pe.machine == pe.MACHINE_I386 and
            pe.is_dll() and
            pe.exports("PhilipsCoInitialize") and
            pe.imports("KERNEL32.dll", "Process32Next") and
            pe.imports("USER32.dll", "SystemParametersInfoA") and
            pe.imports("WININET.dll", "InternetCloseHandle") and
            pe.imports("IPHLPAPI.DLL", "SetTcpEntry") and
            2 of ($d1_raw_sec_*)
        )
        or
        (
            // Rebuilt Philips image.dll prep/dropper memory image.
            uint16(0) == 0x5A4D and
            filesize > 4MB and filesize < 9MB and
            pe.machine == pe.MACHINE_I386 and
            pe.is_dll() and
            pe.exports("PhilipsCoInitialize") and
            $d1_alibaba and $bridge_task1 and $bridge_ranchserv and
            3 of ($d1_host, $d1_image, $d1_thumbs, $d1_xpsplog)
        )
        or
        (
            // rundll32.dat!Edge / Sauron backdoor stage.
            uint16(0) == 0x5A4D and
            filesize > 300KB and filesize < 500KB and
            pe.machine == pe.MACHINE_I386 and
            pe.exports("Edge") and
            pe.imports("WININET.dll", "InternetOpenUrlA") and
            pe.imports("ADVAPI32.dll", "CreateServiceA") and
            pe.imports("ADVAPI32.dll", "StartServiceA") and
            $sauron_name and $sauron_rundll and
            3 of ($sauron_reg_delete, $sauron_edge_log, $sauron_bootsect, $sauron_firewall)
        )
}
