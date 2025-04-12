import signal
import nmap
import sys
import os
from datetime import datetime
from collections import Counter
from vulners import VulnersApi

# Prevent broken pipe error
signal.signal(signal.SIGPIPE, signal.SIG_DFL)

# Vulners API key setup
vulners = VulnersApi(api_key="Paste Your Api Key Here")

def classify_severity(score):
    try:
        score = float(score)
        if score >= 9.0:
            return 'Critical', 'red'
        elif score >= 7.0:
            return 'High', 'orange'
        elif score >= 4.0:
            return 'Medium', 'goldenrod'
        elif score > 0:
            return 'Low', 'green'
        else:
            return 'Info', 'skyblue'
    except:
        return 'Info', 'skyblue'

def search_cves(product, version):
    try:
        query = f"{product} {version}"
        results = vulners.find_all(query)
        return results[:5]
    except Exception as e:
        return [{
            "id": "Error",
            "title": f"Search error for {product} {version}: {e}",
            "cvss": {"score": "N/A"}
        }]

def scan_target(target, report_filename):
    scanner = nmap.PortScanner()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    os.makedirs("reports", exist_ok=True)
    html_path = f"reports/{report_filename}.html"

    report_data = []
    severity_counter = Counter()

    print(f"\n[+] Scanning {target} for open ports and services...\n")

    try:
        scanner.scan(hosts=target, arguments='-T4 -sT -sV --version-intensity 7 -p1-1000')
        print("[DEBUG] Scan Info:", scanner.scaninfo())
        print("[DEBUG] Hosts Found:", scanner.all_hosts())

        if not scanner.all_hosts():
            print("[-] No hosts found.")
            return

        for host in scanner.all_hosts():
            for proto in scanner[host].all_protocols():
                ports = scanner[host][proto].keys()

                for port in sorted(ports):
                    service = scanner[host][proto][port]
                    product = service.get('product', '')
                    version = service.get('version', '')
                    print(f"[DEBUG] Port {port}: {product} {version}")
                    cves = []

                    if product and version:
                        results = search_cves(product, version)
                        for vuln in results:
                            score = vuln.get('cvss', {}).get('score', 'N/A')
                            severity, color = classify_severity(score)
                            severity_counter[severity] += 1
                            cves.append({
                                "id": vuln.get('id', ''),
                                "title": vuln.get('title', ''),
                                "score": score,
                                "severity": severity,
                                "color": color
                            })
                    else:
                        severity_counter['Info'] += 1
                        cves.append({
                            "id": "N/A",
                            "title": "No CVEs found or product/version not detected",
                            "score": "0.0",
                            "severity": "Info",
                            "color": "skyblue"
                        })

                    report_data.append({
                        "port": port,
                        "service": service['name'],
                        "product": product or 'N/A',
                        "version": version or 'N/A',
                        "cves": cves
                    })

        generate_html_report(target, timestamp, report_data, html_path, severity_counter)
        print(f"\nReport saved to: {html_path}")

    except KeyboardInterrupt:
        print("\n[!] Scan cancelled.")
    except Exception as e:
        print(f"[-] Error: {e}")

def generate_html_report(target, timestamp, report_data, filename, severity_counter):
    with open(filename, 'w') as f:
        f.write(f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>VulnX Report - {target}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {{ font-family: Arial, sans-serif; background: #f9f9f9; padding: 20px; }}
        h1, h2, h3 {{ color: #333; }}
        table {{ width: 100%; border-collapse: collapse; margin-bottom: 30px; }}
        th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; }}
        th {{ background: #eee; }}
        .red {{ background-color: #c62828; color: white; }}
        .orange {{ background-color: #ff9800; color: black; }}
        .goldenrod {{ background-color: #ffd54f; color: black; }}
        .green {{ background-color: #388e3c; color: white; }}
        .skyblue {{ background-color: #87ceeb; color: #333; }}
        .btn {{
            background: #007bff; color: white; border: none; padding: 8px 16px;
            border-radius: 5px; cursor: pointer; margin-bottom: 20px;
        }}
        .btn:hover {{ background: #0056b3; }}
        #severityChart {{ max-width: 400px; margin-bottom: 20px; }}
    </style>
</head>
<body>

    <h1>VulnX Scan Report</h1>
    <p><strong>Target:</strong> {target}</p>
    <p><strong>Date:</strong> {timestamp}</p>
    <button class="btn" onclick="window.print()">Export as PDF</button>

    <h2>Vulnerability Summary</h2>
    <canvas id="severityChart" width="300" height="300"></canvas>
    <script>
        const ctx = document.getElementById('severityChart').getContext('2d');
        const chart = new Chart(ctx, {{
            type: 'pie',
            data: {{
                labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                datasets: [{{
                    data: [{severity_counter.get('Critical',0)}, {severity_counter.get('High',0)},
                           {severity_counter.get('Medium',0)}, {severity_counter.get('Low',0)},
                           {severity_counter.get('Info',0)}],
                    backgroundColor: ['#c62828', '#ff9800', '#ffd54f', '#388e3c', '#87ceeb'],
                    borderColor: '#fff',
                    borderWidth: 2
                }}]
            }},
            options: {{
                responsive: false,
                plugins: {{
                    legend: {{ position: 'bottom' }}
                }}
            }}
        }});
    </script>

    <table>
        <tr><th>Severity</th><th>Count</th></tr>
        <tr><td class='red'>Critical</td><td>{severity_counter.get('Critical', 0)}</td></tr>
        <tr><td class='orange'>High</td><td>{severity_counter.get('High', 0)}</td></tr>
        <tr><td class='goldenrod'>Medium</td><td>{severity_counter.get('Medium', 0)}</td></tr>
        <tr><td class='green'>Low</td><td>{severity_counter.get('Low', 0)}</td></tr>
        <tr><td class='skyblue'>Info</td><td>{severity_counter.get('Info', 0)}</td></tr>
    </table>
    <hr>
""")

        for entry in report_data:
            f.write(f"""
    <h3>Port {entry['port']} - {entry['service']}</h3>
    <p><strong>Product:</strong> {entry['product']}<br>
    <strong>Version:</strong> {entry['version']}</p>
    <table>
        <tr>
            <th>CVE ID</th>
            <th>Severity</th>
            <th>Score</th>
            <th>Title</th>
        </tr>""")
            for cve in entry['cves']:
                f.write(f"""
        <tr class="{cve['color']}">
            <td>{cve['id']}</td>
            <td>{cve['severity']}</td>
            <td>{cve['score']}</td>
            <td>{cve['title']}</td>
        </tr>""")
            f.write("</table>")
        f.write("</body></html>")

# Entry point with friendly prompt
if __name__ == "__main__":
    print("Welcome to VulnX - Lightweight Vulnerability Scanner\n")
    target = input("Enter target IP/domain: ")
    report_name = input("Enter report filename (without extension): ")

    if not target or not report_name:
        print("[-] Target and report name required.")
    else:
        scan_target(target, report_name)
