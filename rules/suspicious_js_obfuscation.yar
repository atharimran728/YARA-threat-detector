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
