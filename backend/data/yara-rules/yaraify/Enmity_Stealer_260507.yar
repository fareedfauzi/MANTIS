import "pe"

/*
    Enmity Stealer -- submitted build YARA rule
    Author: derp.ca
    Date: 2026-05-18
    Source: https://github.com/kirkderp/yara

    Targets the submitted x64 Enmity stealer build. The rule is carried by
    stealer module evidence: embedded Discord-token JavaScript, browser
    credential SQL, wallet collection paths, certificate-store imports,
    clipboard/keylogging imports, and process-memory access imports.

    Detection targets:
      - Submitted PE: browser, wallet, Discord, certificate, clipboard,
        keylogging, and process-memory theft capability cluster

    Hashes:
        Submitted PE: 6d83880802874b883c8e6491fa5efac4898a3bbd59e0b861ecdf11a919a86188
*/

rule Enmity_Stealer_260507
{
    meta:
        id = "La4KjRLX2DRsgoSjQmiSU5"
        fingerprint = "3af678dcc3d37038937344e0b74f2f1e337497fd75937006"
        version = "2.0"
        date = "2026-05-18"
        modified = "2026-05-19"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "https://github.com/kirkderp/yara"
        author = "derp.ca"
        description = "Submitted Enmity stealer build with Discord token JavaScript, browser credential SQL, wallet collection paths, certificate-store access, clipboard/keylogging imports, and process-memory imports."
        category = "MALWARE"
        malware = "ENMITY"
        malware_type = "INFOSTEALER"
        mitre_att = "T1555.003"
        reference = "https://github.com/kirkderp/yara"
        triage_score = 10
        triage_description = "Enmity stealer build with browser, wallet, Discord token, certificate, clipboard, keylogging, and process-memory theft evidence."
        yarahub_uuid = "83485cf8-0e48-48a2-bcca-01dbe4df76c1"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "9678405134c1fc73623c84e679bd3213"

    strings:
        $js_cached_token = "cachedToken" ascii
        $js_get_user_info = "getUserInfo" ascii
        $js_user_cache = "userCache" ascii
        $js_webhook_decl = "const webhook = '" ascii
        $js_discord_users = "discord.com/api/v10/users/@me" ascii

        $sql_firefox_cookies = "SELECT host, path, isSecure, expiry, name, value FROM moz_cookies" ascii
        $sql_chrome_logins = "SELECT origin_url, username_value, password_value FROM logins" ascii
        $sql_login_data = "\\Login Data" ascii

        $wallet_zip = "\\wallets.zip" ascii
        $wallet_exodus = "\\Exodus\\exodus.wallet" ascii
        $wallet_wasabi = "\\WalletWasabi\\Client\\Wallets" ascii
        $wallet_electrum = "\\Electrum\\wallets" ascii
        $wallet_coinomi = "\\Coinomi\\Coinomi\\wallets" ascii
        $wallet_monero = "\\Monero\\wallets" ascii

        $support_ws_c2 = "ws://futuregroupstar.lat:3000" ascii
        $support_pdb = "c:\\Users\\Iago Aquino Mendes\\Documents\\cht\\rocket\\Rocket\\No" ascii
        $support_webhook_path = "1493441198361153547/LOz3gDlrs_vBJI_Lp8X5EM7w-kDqeFhbkWBM9NJSSCbnu_P37n3e0Mza2DZu97WaNnsL" ascii

    condition:
        uint16(0) == 0x5A4D and
        pe.machine == pe.MACHINE_AMD64 and
        filesize > 8MB and filesize < 10MB and
        pe.imports("CRYPT32.dll", "PFXImportCertStore") and
        pe.imports("CRYPT32.dll", "CertOpenStore") and
        pe.imports("CRYPT32.dll", "CertEnumCertificatesInStore") and
        pe.imports("USER32.dll", "GetClipboardData") and
        pe.imports("USER32.dll", "GetAsyncKeyState") and
        pe.imports("KERNEL32.dll", "CreateToolhelp32Snapshot") and
        pe.imports("KERNEL32.dll", "ReadProcessMemory") and
        pe.imports("KERNEL32.dll", "WriteProcessMemory") and
        4 of ($js_*) and
        2 of ($sql_*) and
        3 of ($wallet_*) and
        1 of ($support_*)
}
