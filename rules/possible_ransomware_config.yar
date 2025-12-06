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
