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
