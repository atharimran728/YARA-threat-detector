def generate_html_report(alerts, output="report.html"):
    html = """
    <html>
    <head>
        <title>Scan Report</title>
        <style>
            body { font-family: Arial; background: #f7f7f7; padding: 20px; }
            table { width: 100%; border-collapse: collapse; }
            th, td { padding: 8px 12px; border-bottom: 1px solid #ccc; }
            th { background: #222; color: #fff; }
        </style>
    </head>
    <body>
        <h1>YARA Threat Scan Report</h1>
        <table>
            <tr>
                <th>File</th>
                <th>Rule</th>
                <th>Severity</th>
                <th>MITRE</th>
                <th>Timestamp</th>
            </tr>
    """

    for a in alerts:
        for r in a["yara_matches"]:
            html += f"""
            <tr>
                <td>{a['file_name']}</td>
                <td>{r['rule']}</td>
                <td>{r['severity']}</td>
                <td>{r['mitre']}</td>
                <td>{a['timestamp']}</td>
            </tr>
            """

    html += """
        </table>
    </body>
    </html>
    """

    with open(output, "w") as f:
        f.write(html)
