# YARA Threat Detector

A compact threat-detection toolkit built around YARA, enriched with rule metadata extraction, heuristic scanning, HTML reporting, and a curated malicious sample set for testing. Designed for analysts who want clarity, speed, and practical detection logic without unnecessary complexity.

---

## Features

### Metadata-Aware YARA Engine  
Parses severity, category, and MITRE technique IDs directly from rule meta fields.

### Heuristics Mode  
Detects high-entropy payloads, suspicious Base64 blobs, and other non-signature indicators.

### HTML Reporting  
Generates a clean, analyst-friendly scan report with sortable detection details.

### Console Output (SOC-style)  
Structured terminal output with rule metadata, useful for triage and debugging.

### Custom Rule Packs  
All rules are stored under `rules/all-rules.yar` for easy extension.

### Sample Malware Artifacts  
Test files covering:
- encoded PowerShell payloads  
- ransomware notes  
- obfuscated JavaScript  
- Base64 webshell patterns  
- simple malicious markers

---

## Project Structure

```
yara-threat-detector/
│
├── rules/
│ └── all-rules.yar
| └── base64_webshell.yar
| └── malicious_string.yar
| └── possible_ransomware_config.yar
| └── powershell_encoded_command.yar
| └── suspicious_js_obfuscation.yar
│
├── samples/
│ ├── basic_malware.txt
│ ├── encoded_ps.txt
│ ├── obfuscated.js
│ ├── ransomware_note.txt
│ └── webshell.php
│
├── scanner/
│ ├── heuristics.py
│ ├── html_report.py
│ └── stats.py
│
├── yara_scanner.py
├── alerts.json
└── report.html
```

---

## 🧪 Running the Scanner

```bash
python yara_scanner.py
```

### Outputs:
- terminal detections
- `alerts.json`
- `report.html`

## Add Your Own Rules

Extend `rules/all-rules.yar` and rerun the scanner.
Metadata fields (`severity`, `category`, `mitre`) are automatically parsed.

## Detection Stats
The scanner computes:
- total files scanned
- number of detections
- detection rate (%)
- unique rules triggered


