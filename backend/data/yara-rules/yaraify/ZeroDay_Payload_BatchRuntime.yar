import "hash"

rule ZeroDay_Payload_BatchRuntime : rat android malware banking
{
    meta:
        author = "CyberStrike"
        description = "ZeroDay RAT payload - com.batch.android.runtime - SMS/UPI/keylog theft"
        date = "2026-09-05"
        yarahub_author_twitter = "@XenoSheesh"
        yarahub_reference_md5 = "3c53caa2fd562d12dcf22bd5b396a2ed"
        yarahub_uuid = "bbd755bb-fa4f-4f22-9e06-f8ac5db274d1"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        hash_sha256 = "01227a8b5dca01ecac7177051e6d2a3cf5e12ce7ca9cbb06040d8bcb9cfcc6a2"
        
    strings:
        $pkg1 = "com.batch.android.runtime" ascii wide
        $pkg2 = "com.app.messenger" ascii wide
        
        $api1 = "/sms/new" ascii wide
        $api2 = "/sms/batch" ascii wide
        $api3 = "/call-logs/batch" ascii wide
        $api4 = "/contacts/batch" ascii wide
        $api5 = "/pin-data" ascii wide
        $api6 = "/live-keylog/status" ascii wide
        
        $c2 = "api.agenticera.club" ascii wide nocase
        
        $flavor1 = "weddingv2luxsuper" ascii wide nocase
        $flavor2 = "sexychatv2lux" ascii wide nocase
        $flavor3 = "mparivahanv4lux" ascii wide nocase
        
        $persist1 = "PersistenceService" ascii wide
        $persist2 = "WatchdogService" ascii wide
        $persist3 = "UltraWorkerService" ascii wide
        
        $upi1 = "com.phonepe.app" ascii wide
        $upi2 = "com.google.android.apps.nbu.paisa" ascii wide
        $upi3 = "net.one97.paytm" ascii wide
        
    condition:
        uint32(0) == 0x04034b50 and
        filesize < 15MB and
        (
            (any of ($pkg*) and 3 of ($api*)) or
            $c2 or
            (2 of ($flavor*)) or
            (3 of ($persist*)) or
            (2 of ($upi*) and any of ($api*)) or
            hash.sha256(0, filesize) == "01227a8b5dca01ecac7177051e6d2a3cf5e12ce7ca9cbb06040d8bcb9cfcc6a2"
        )
}
