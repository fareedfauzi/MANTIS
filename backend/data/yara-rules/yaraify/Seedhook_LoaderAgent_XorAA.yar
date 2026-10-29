rule Seedhook_LoaderAgent_XorAA
{
    meta:
        yarahub_uuid = "d8443845-32ba-44a1-bf08-01b5e1b101df"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "8291121949d8e8c87bba48b09425c7f8"
        description = "Seedhook/MacSync loader_agent: ObfuscatedString XOR-0xAA encoded paths, gate endpoints and persistence strings"
        actor = "Seedhook (MacSync Stealer cluster)"
        reference_sha256 = "ac13d281a641dbfe19ff05dbcd9d758e567a0d608ae188d8202d53836c54095c"
        date = "2026-09-13"
        tlp = "CLEAR"

    strings:
        $x1 = "/loader/gate" xor(0xAA)
        $x2 = "/loader/file-upload" xor(0xAA)
        $x3 = "/loader/agent/" xor(0xAA)
        $x4 = "/tmp/.com.apple.xpcd" xor(0xAA)
        $x5 = "/tmp/.com.apple.dsync" xor(0xAA)
        $x6 = "/.local/.mpwd" xor(0xAA)
        $x7 = "system_profiler SPHardwareDataType 2>/dev/null" xor(0xAA)
        $x8 = "request_file" xor(0xAA)
        $x9 = "capture_screen" xor(0xAA)

    condition:
        Seedhook_MachO and filesize < 40MB and 5 of them
}
