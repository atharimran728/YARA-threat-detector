import os
import base64
import math

def file_entropy(path):
    with open(path, "rb") as f:
        data = f.read()
    if not data:
        return 0
    p = [data.count(byte)/len(data) for byte in set(data)]
    return -sum(x * math.log2(x) for x in p)

def detect_base64_blobs(path):
    with open(path, "r", errors="ignore") as f:
        content = f.read()
    return len([b for b in content.split() if len(b) > 40 and all(c.isalnum() or c in "+/=" for c in b)]) > 0

def heuristics_scan(path):
    findings = []

    # High entropy files
    ent = file_entropy(path)
    if ent > 6.5:
        findings.append({"type": "high_entropy", "score": ent})

    # Suspicious Base64 blobs
    if detect_base64_blobs(path):
        findings.append({"type": "base64_blob", "score": "medium"})

    return findings
