import "math"

rule Foxveil_Loader_MachO
{
    meta:
        yarahub_uuid = "b64f94fa-4600-4f0c-8722-1bc96e9c58ca"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "72d5aa3d8e51e1cf8e37e613c21c450b"
        description = "Foxveil macOS loader (ClickFix -> AMOS): mmap(0xC2) buffer setup in both slices plus ad-hoc 'setup-<hex>' signing and dlsym import shape"
        actor = "Foxveil"
        family = "AMOS loader"
        reference_sha256 = "708a0836a8c20e79f2ae522f097787326a90965e0532f3fd488d8d6e428f77b6"
        date = "2026-09-13"
        tlp = "CLEAR"

    strings:
        // x86_64: mov esi,0xC2; xor edi,edi; mov edx,3; mov ecx,0x1002; mov r8d,-1; xor r9d,r9d
        $x64_mmap = { BE C2 00 00 00 31 FF BA 03 00 00 00 B9 02 10 00 00 41 B8 FF FF FF FF 45 31 C9 }
        // arm64: mov x0,#0; mov w1,#0xC2; mov w2,#3; mov w3,#0x1002; mov w4,#-1
        $a64_mmap = { 00 00 80 D2 41 18 80 52 62 00 80 52 43 00 82 52 04 00 80 12 }
        // arm64: strb wzr,[x19,x8]; add x8,x8,#1; cmp x8,#0xC2; b.ne loop
        $a64_zero = { 7F 6A 28 38 08 05 00 91 1F 09 03 F1 A1 FF FF 54 }

        $cs_id  = /setup-[0-9a-f]{40}\x00/
        $imp1   = "_dlsym\x00"
        $dylib1 = "/usr/lib/libSystem.B.dylib\x00"
        $dylib2 = "/usr/lib/libc++.1.dylib\x00"

    condition:
        Foxveil_Fat_x64_arm64 and filesize < 2MB and
        (
            ($x64_mmap and 1 of ($a64_*)) or
            (1 of ($x64_mmap, $a64_*) and #cs_id >= 2 and $imp1 and all of ($dylib*))
        )
}
