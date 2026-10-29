rule Seedhook_LoaderAgent_realtux
{
    meta:
        yarahub_uuid = "0f8d87f5-9913-4362-adcc-1e961d070b52"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "8291121949d8e8c87bba48b09425c7f8"
        description = "Seedhook/MacSync loader_agent build with XOR-0xAA encoded C2 realtux.com (reverse tunnel on :443)"
        actor = "Seedhook (MacSync Stealer cluster)"
        reference_sha256 = "ac13d281a641dbfe19ff05dbcd9d758e567a0d608ae188d8202d53836c54095c"
        c2 = "realtux.com:443"
        date = "2026-09-13"
        tlp = "CLEAR"

    strings:
        $c2 = "realtux.com" xor(0xAA)
        $g  = "/loader/gate" xor(0xAA)

    condition:
        Seedhook_MachO and all of them
}
