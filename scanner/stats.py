def compute_stats(alerts, total_files):
    unique_rules = set()

    for a in alerts:
        for m in a["yara_matches"]:
            unique_rules.add(m["rule"])

    return {
        "total_files": total_files,
        "detections": len(alerts),
        "detection_rate": round((len(alerts) / total_files) * 100, 2),
        "unique_rules_triggered": len(unique_rules)
    }
