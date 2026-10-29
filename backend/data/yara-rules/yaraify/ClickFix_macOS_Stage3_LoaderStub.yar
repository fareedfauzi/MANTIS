/*
    macOS ClickFix stage-3 loader stub (self-decrypting, in-memory)

    Unlike the other rules in this directory, this one IS for Mach-O scanning.

    It matches the loader, not the stealer. The stealer itself is an encrypted blob
    inside __DATA,__const which is decrypted into anonymous memory at runtime and
    never touches disk. The stub carries almost no code of its own -- roughly 20 KB of
    unpacker against 70 KB of ciphertext.

    What makes it identifiable is the import table. Sixteen symbols total, and the
    combination is close to a fingerprint of "read my own section, decrypt it, run it
    without leaving traces":

        _getsectiondata + __dyld_get_image_header   locate own encrypted section
        _mmap / _munmap                             anonymous executable memory
        _mlock / _munlock                           keep plaintext out of swap
        _dlsym                                      resolve every real API at runtime
        _getenv                                     pick up C2 config from environment
        _pthread_main_np                            thread-context / anti-analysis check

    No networking, no file, no crypto, no Security.framework imports -- because the
    loader genuinely needs none of them. That absence is the signal.

    The mlock pair is the detail worth keeping: the operator deliberately prevents the
    decrypted payload from reaching the swapfile. It is an anti-forensics measure, and
    it is uncommon enough in benign software to carry weight.

    Reference sample: SHA256 29be0f56275f051181ea3ec37ddc3d3807cde34cb65de855709fae0e13786a40
*/

import "hash"

rule ClickFix_macOS_Stage3_LoaderStub : clickfix macos loader macho
{
    meta:
        author       = "Novum Analytica GmbH"
        date         = "2026-08-06"
        yarahub_uuid                = "fbc7d408-b105-4708-82d1-d4940c45ce2d"
        yarahub_reference_md5       = "ab477021780e553be4271cb34bb8394b"
        yarahub_reference_link      = "https://github.com/raimurokko/macos-threat-tracking"
        yarahub_license             = "CC0 1.0"
        yarahub_rule_matching_tlp   = "TLP:WHITE"
        yarahub_rule_sharing_tlp    = "TLP:WHITE"
        description  = "Self-decrypting macOS loader stub delivering an in-memory infostealer (AMOS lineage assessed)"
        reference    = "https://github.com/raimurokko/macos-threat-tracking"
        severity     = "critical"
        mitre_attack = "T1027.009, T1620, T1105, T1497"
        tlp          = "TLP:CLEAR"
        license      = "CC0-1.0"
        note         = "Matches the loader family, not one build. Reference sample has exactly 16 imports; verify hits against that. The $absent* exclusions are the fragile part - a variant that imports CFNetwork or Security.framework will evade this rule silently."

    strings:
        // Self-inspection: locate own encrypted section
        $i1 = "_getsectiondata"          ascii
        $i2 = "_dyld_get_image_header"   ascii

        // In-memory execution with swap suppression
        $i3 = "_mmap"                    ascii
        $i4 = "_mlock"                   ascii
        $i5 = "_munlock"                 ascii

        // Everything real is resolved at runtime
        $i6 = "_dlsym"                   ascii

        // Config via environment, thread-context check
        $i7 = "_getenv"                  ascii
        $i8 = "_pthread_main_np"         ascii

        $l1 = "/usr/lib/libc++.1.dylib"  ascii

        // Ad-hoc signing identifier: "setup-" plus 40 lowercase hex.
        // No Apple team ID -- nothing Apple could revoke.
        $sig = /setup-[0-9a-f]{40}/      ascii

        // Things a real stealer would need and this stub deliberately lacks
        $absent1 = "SecKeychain"         ascii
        $absent2 = "CFNetwork"           ascii
        $absent3 = "NSURLSession"        ascii

    condition:
        // Mach-O or universal binary
        ( uint32be(0) == 0xcafebabe or uint32(0) == 0xfeedfacf or uint32be(0) == 0xcffaedfe )
        and filesize < 5MB
        and all of ($i*)
        and $l1
        and $sig
        and not any of ($absent*)
}
