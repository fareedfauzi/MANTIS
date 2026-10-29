import "pe"

rule certum_issuer
{
    meta:
        description = "Looks for files signed with certificate issued by Certum"
        author = "Certum"
        date = "2026-03-25"
        yarahub_uuid = "3b367e79-4c7d-4b39-9b04-3097a943d7ff"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "1f1908d1cef917b8b122b992c9a4e6df" 

     condition:
        uint16(0) == 0x5a4d and // Check if PE file
		pe.number_of_signatures > 0 and // Check if signed
		for any i in (0 .. pe.number_of_signatures - 1): ( // Check if issuer contains Certum
            pe.signatures[i].issuer contains "Certum"
        )
}