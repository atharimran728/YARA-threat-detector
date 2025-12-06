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
