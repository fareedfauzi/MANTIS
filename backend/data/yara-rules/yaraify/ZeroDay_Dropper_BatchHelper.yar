import "hash"

rule ZeroDay_Dropper_BatchHelper : dropper android malware
{
    meta:
        author = "CyberStrike"
        description = "ZeroDay RAT dropper - com.batch.helper (Wedding-Ceremoney) targeting Indian banking"
        date = "2026-09-05"
        yarahub_author_twitter = "@XenoSheesh"
        yarahub_reference_md5 = "35b2d781134a7bf705a357ec3b314910"
        yarahub_uuid = "9a87761a-46cc-43bc-b4e3-b63a48c4a991"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        hash_sha256 = "fc341a1770ea2e616a604f1c301dde223b19409da8f9584fe3fc94ecf59c86e0"
        
    strings:
        $pkg1 = "com.batch.helper" ascii wide
        $pkg2 = "com.batch.android.runtime" ascii wide
        $pkg3 = "com.app.messenger.AppActivity" ascii wide
        
        $jni1 = "Java_com_batch_helper_MainPjyrActivity_ndpVC" ascii
        $jni2 = "Java_com_batch_helper_MainPjyrActivity_nativeEnvCheck" ascii
        $jni3 = "Java_com_batch_helper_MainPjyrActivity_getNativeStr" ascii
        
        $act1 = "MainPjyrActivity" ascii wide
        $act2 = "LoggerAnvjApp" ascii wide
        $act3 = "SecureEsgrVpn" ascii wide
        $act4 = "CacheQhraProvider" ascii wide
        $act5 = "ImageIccgReceiver" ascii wide
        
        $se1 = "Wedding-Ceremoney" ascii wide nocase
        $asset = "main_bg.png" ascii wide
        
    condition:
        uint32(0) == 0x04034b50 and
        filesize < 10MB and
        (
            (any of ($pkg*)) or
            (2 of ($jni*)) or
            (3 of ($act*)) or
            ($se1 and $asset) or
            hash.sha256(0, filesize) == "fc341a1770ea2e616a604f1c301dde223b19409da8f9584fe3fc94ecf59c86e0"
        )
}
