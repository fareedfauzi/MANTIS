/*
    Known stage-3 loader samples, campaign DANTE, 2026-08.
    Hash-only rule, split into its own file because YARAhub accepts one rule per file.
    Reference: https://github.com/raimurokko/macos-threat-tracking
*/

import "hash"

rule ClickFix_macOS_Stage3_KnownSamples : clickfix macos campaign macho
{
    meta:
        author      = "Novum Analytica GmbH"
        date        = "2026-08-06"
        yarahub_uuid                = "b020502e-f647-417e-9d88-35e5a4ce2e9d"
        yarahub_reference_md5       = "ab477021780e553be4271cb34bb8394b"
        yarahub_reference_link      = "https://github.com/raimurokko/macos-threat-tracking"
        yarahub_license             = "CC0 1.0"
        yarahub_rule_matching_tlp   = "TLP:WHITE"
        yarahub_rule_sharing_tlp    = "TLP:WHITE"
        description = "Known stage-3 loader samples, campaign DANTE, 2026-08"
        reference   = "https://github.com/raimurokko/macos-threat-tracking"
        severity    = "critical"
        tlp         = "TLP:CLEAR"
        license     = "CC0-1.0"

    condition:
        hash.sha256(0, filesize) ==
            "29be0f56275f051181ea3ec37ddc3d3807cde34cb65de855709fae0e13786a40"   // universal
        or hash.sha256(0, filesize) ==
            "3873844f319ebbab08db2f27b6d7336a1d7d91ca65862d9470cd7300e4a3f207"   // arm64 slice
        or hash.sha256(0, filesize) ==
            "3710bb59c25a1c7eaba2ab471876f223ed5d358fc08e979a2ff1ebeedf03e431"   // x86_64 slice
}
