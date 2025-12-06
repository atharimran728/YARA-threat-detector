import yara
import os
import json
import hashlib
from datetime import datetime

from heuristics import heuristics_scan
from html_report import generate_html_report
from stats import compute_stats

rules = yara.compile(filepath="rules/all-rules.yar")

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

alerts = []
scan_path = "./samples"
total_files = 0

print("\n=== YARA THREAT SCANNER ===\n")

for root, dirs, files in os.walk(scan_path):
    for file in files:
        total_files += 1
        path = os.path.join(root, file)
        file_alert = {
            "timestamp": datetime.utcnow().isoformat(),
            "file_name": file,
            "file_path": path,
            "sha256": sha256_file(path),
            "yara_matches": [],
            "heuristics": []
        }

        # Run all YARA rule packs
        matches = rules.match(path)
        for m in matches:
            meta = m.meta
            file_alert["yara_matches"].append({
                "rule": m.rule,
                "severity": meta.get("severity", "unknown"),
                "category": meta.get("category", "unknown"),
                "mitre": meta.get("mitre", "unknown"),
            })

        # Heuristics Mode
        heur = heuristics_scan(path)
        if heur:
            file_alert["heuristics"] = heur

        # Show console output
        if file_alert["yara_matches"] or file_alert["heuristics"]:
            print(f"[DETECTED] {file}")
            for m in file_alert["yara_matches"]:
                print(f" ├─ Rule: {m['rule']}")
                print(f" │    Severity: {m['severity']}")
                print(f" │    MITRE: {m['mitre']}")
            for h in file_alert["heuristics"]:
                print(f" └─ Heuristic: {h['type']}")

            alerts.append(file_alert)

# Save alerts
with open("alerts.json", "w") as f:
    json.dump(alerts, f, indent=4)

# Generate HTML Report
generate_html_report(alerts)

# Stats
stats = compute_stats(alerts, total_files)
print("\n=== SCAN SUMMARY ===")
print(stats)
