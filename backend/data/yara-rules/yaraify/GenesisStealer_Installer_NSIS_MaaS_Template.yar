import "pe"

rule GenesisStealer_Installer_NSIS_MaaS_Template
{
    meta:
        author                      = "n3r"
        description                 = "GenesisStealer NSIS installer (MaaS template). Imphash-based broad detector - also catches ScarfaceStealer / RemusStealer / VoidStealer variants sharing the same installer shell."
        date                        = "2026-05-28"
        sha256                      = "d24dbda069525134f94904f7a16dbf275abcc0c8d7b0b9c065f39d91d3e2dd7a"
        family                      = "GenesisStealer"
        scope                       = "outer NSIS installer; broader MaaS template - also catches ScarfaceStealer/RemusStealer/VoidStealer variants sharing the same imphash"
        confidence                  = "MEDIUM"
        ref                         = "MalwareBazaar GenesisStealer cluster; imphash family"
        yarahub_uuid                = "efa323f6-4028-4928-9f43-a78c8a12d834"
        yarahub_license             = "CC BY 4.0"
        yarahub_reference_md5       = "09cf1fddb08051f5be72245b00638358"
        yarahub_reference_link      = "https://bazaar.abuse.ch/sample/d24dbda069525134f94904f7a16dbf275abcc0c8d7b0b9c065f39d91d3e2dd7a/"
        yarahub_rule_matching_tlp   = "TLP:WHITE"
        yarahub_rule_sharing_tlp    = "TLP:WHITE"

    condition:
        uint16(0) == 0x5A4D
        and pe.imphash() == "b34f154ec913d2d2c435cbd644e91687"
        and filesize > 50MB and filesize < 150MB
}
