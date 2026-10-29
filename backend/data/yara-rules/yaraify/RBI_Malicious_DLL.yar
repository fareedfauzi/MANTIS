rule RBI_Malicious_DLL
{
    meta:
        description = "Detection rule for DLL associated with Enter.exe"
        author = "ShriyaTiger"
        date = "2026-07-10"

        yarahub_uuid = "8afa369b-18fa-4510-a329-28bdbede2973"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

        yarahub_reference_md5 = "de2e1152201ed82ae11fa7d44a604410"

        md5 = "de2e1152201ed82ae11fa7d44a604410"
        sha256 = "3c96753731fbf688047f5580db9cf3f560f23e35b796baa289f31f610c73f582"

        malware_family = "RBI"
        sample_type = "DLL"

    strings:
        $reg1 = "SOFTWARE\\Microsoft\\Cryptography" ascii wide
        $reg2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" ascii wide

        $dll1 = "kernel32.dll" ascii nocase
        $dll2 = "user32.dll" ascii nocase
        $dll3 = "advapi32.dll" ascii nocase
        $dll4 = "shell32.dll" ascii nocase
        $dll5 = "psapi.dll" ascii nocase
        $dll6 = "rpcrt4.dll" ascii nocase
        $dll7 = "ntdll.dll" ascii nocase

    condition:
        (
            hash.md5(0, filesize) == "de2e1152201ed82ae11fa7d44a604410"
        )
        or
        (
            hash.sha256(0, filesize) == "3c96753731fbf688047f5580db9cf3f560f23e35b796baa289f31f610c73f582"
        )
        or
        (
            uint16(0) == 0x5A4D and
            2 of ($reg*) and
            4 of ($dll*)
        )
}