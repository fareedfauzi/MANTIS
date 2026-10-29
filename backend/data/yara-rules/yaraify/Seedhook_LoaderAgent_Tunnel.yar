rule Seedhook_LoaderAgent_Tunnel
{
    meta:
        yarahub_uuid = "33ca4ebc-fbba-4086-a33e-1916b19b66ee"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "8291121949d8e8c87bba48b09425c7f8"
        description = "Seedhook/MacSync loader_agent macOS reverse-tunnel backdoor (TLS+WebSocket+yamux+SOCKS5), log strings and symbols"
        actor = "Seedhook (MacSync Stealer cluster)"
        reference_sha256 = "ac13d281a641dbfe19ff05dbcd9d758e567a0d608ae188d8202d53836c54095c"
        date = "2026-09-13"
        tlp = "CLEAR"

    strings:
        // reverse-tunnel ("rv") client log lines
        $rv1 = "[rv] Primary failed (rc=%d), trying fallback %s" ascii
        $rv2 = "[rv] Reconnecting in %d seconds (failures=%d rc=%d)..." ascii
        $rv3 = "[rv] ERROR: Failed to send password" ascii
        $rv4 = "[rv] Password sent successfully" ascii
        $rv5 = "[rv] yamux session created" ascii
        $rv6 = "[rv] SOCKS stream (id=%u, magic=0x%02x)" ascii
        $rv7 = "[rv] SHELL stream (id=%u)" ascii
        $rv8 = "[rv] ERROR: failed to replay SOCKS prefix byte" ascii
        $rv9 = "========== Client started ==========" ascii

        // yamux / socks5 component logs
        $mx1 = "[yamux] ERROR: Failed to send SYN|ACK for stream %u" ascii
        $mx2 = "[socks5] ERROR: getaddrinfo failed for %s:%s" ascii

        // unstripped symbols (C++ mangled names contain these substrings)
        $sy1 = "ObfuscatedString" ascii
        $sy2 = "yamux_session_create" ascii
        $sy3 = "ws_client_handshake" ascii
        $sy4 = "socks5_handle" ascii
        $sy5 = "rv_is_connected" ascii
        $sy6 = "tls_client_handshake" ascii

    condition:
        Seedhook_MachO and filesize < 40MB and
        (
            4 of ($rv*) or
            (2 of ($rv*) and 1 of ($mx*)) or
            (4 of ($sy*) and 1 of ($rv*, $mx*))
        )
}
