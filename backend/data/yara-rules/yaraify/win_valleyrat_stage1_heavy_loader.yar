import "pe"

rule win_valleyrat_stage1_heavy_loader {
    meta:
        author = "Daydream"
        description = "Detects ValleyRAT Stage-1 Inflated Loader (Silver Fox)"
        date = "2026-08-08"
        reference = "https://bazaar.abuse.ch/sample/a82ddf1015b9f676b2aa720f33e351330418e7739da9e90ddb6ebed1304dcd40/"
        yarahub_uuid = "6d6cc4e5-f5e7-4667-9ac6-f2a69983db5c"
        yarahub_license = "CC BY-NC-SA 4.0"
        yarahub_reference_md5 = "ebd0b8e0f53ea8a997823dab5224f2e9"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yaraify_target = "malware"

    strings:
        $bcrypt1 = "BCryptGenerateSymmetricKey" ascii wide
        $bcrypt2 = "BCryptSecretAgreement" ascii wide
        $bcrypt3 = "BCryptEncrypt" ascii wide
        $bcrypt4 = "BCryptFinalizeKeyPair" ascii wide
        $bcrypt5 = "BCryptDestroyKey" ascii wide

        $winapi1 = "SetupDiGetClassDevsW" ascii wide
        $winapi2 = "SetupDiGetDeviceInterfaceDetailW" ascii wide
        $winapi3 = "WTSRegisterSessionNotification" ascii wide
        $winapi4 = "WTSUnRegisterSessionNotification" ascii wide

        $sc_trig1 = "EnumSystemLocalesA" ascii wide
        $sc_trig2 = "EnumSystemLocalesW" ascii wide

        $data_sec = ".data" ascii

    condition:
        uint16(0) == 0x5A4D
        and filesize > 30MB and filesize < 60MB
        and pe.number_of_sections == 6
        and 3 of ($bcrypt1, $bcrypt2, $bcrypt3, $bcrypt4, $bcrypt5)
        and 2 of ($winapi1, $winapi2, $winapi3, $winapi4)
        and 1 of ($sc_trig1, $sc_trig2)
        and $data_sec
}
