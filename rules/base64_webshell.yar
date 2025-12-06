rule base64_webshell
{
    meta:
        description = "Detects Base64-encoded webshell payloads"
        severity = "high"
        category = "Webshell"
        mitre = "T1505.003"

    strings:
        $b64 = /[A-Za-z0-9+\/]{100,}={0,2}/
        $php = "<?php"
    condition:
        $php and $b64
}
