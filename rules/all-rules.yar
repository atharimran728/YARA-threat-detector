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

rule malicious_string
{
    meta:
        description = "Detect literal 'malicious'"
        severity = "medium"
        category = "Malware Artifact"
        mitre = "T1204"

    strings:
        $s1 = "malicious"
    condition:
        $s1
}

rule possible_ransomware_config
{
    meta:
        description = "Detect ransomware-like strings"
        severity = "critical"
        category = "Data Encryption"
        mitre = "T1486"

    strings:
        $ext1 = ".locked"
        $ext2 = ".encrypted"
        $key = "public_key"
        $note = "YOUR FILES HAVE BEEN LOCKED"
    condition:
        any of ($ext*) or $key or $note
}

rule powershell_encoded_command
{
    meta:
        description = "Detect PowerShell encoded payloads"
        severity = "high"
        category = "Command Execution"
        mitre = "T1059.001"

    strings:
        $ps = /powershell(\.exe)?/i
        $enc = /-EncodedCommand\s+[A-Za-z0-9+\/=]{10,}/i
    condition:
        $ps and $enc
}

rule suspicious_js_obfuscation
{
    meta:
        description = "Detect eval() obfuscated JavaScript"
        severity = "medium"
        category = "Initial Access"
        mitre = "T1059.007"

    strings:
        $eval = "eval("
        $unescape = "unescape("
        $hex = /\\x[0-9A-Fa-f]{2}/
    condition:
        $eval and ($unescape or $hex)
}
