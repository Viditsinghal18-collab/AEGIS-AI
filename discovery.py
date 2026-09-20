import json
from datetime import datetime, timezone
import nmap
import requests

def scan_target(target="127.0.0.1", ports="80,443,3000,8080"):
    nm = nmap.PortScanner()
    # -sV probes open ports to determine service/version info
    nm.scan(target, ports, arguments="-sV")
    discovered_assets = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in nm[host][proto]:
                port_info = nm[host][proto][port]
                discovered_assets.append({
                    "host": host,
                    "port": port,
                    "protocol": proto,
                    "state": port_info.get("state", "unknown"),
                    "service": port_info.get("name", "unknown"),
                    "product": port_info.get("product", ""),
                    "version": port_info.get("version", ""),
                })
    return discovered_assets

def fingerprint_http(url="http://localhost:3000"):
    try:
        resp = requests.get(url, timeout=5)
        return {
            "url": url,
            "status_code": resp.status_code,
            "server_header": resp.headers.get("Server", "None"),
            "powered_by": resp.headers.get("X-Powered-By", "None"),
        }
    except requests.RequestException as e:
        return {"url": url, "error": str(e)}

if __name__ == "__main__":
    print("[*] Scanning target ports on 127.0.0.1...")
    assets = scan_target()
    
    print("[*] Probing HTTP headers on port 3000...")
    http_info = fingerprint_http("http://localhost:3000")

    report = {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "discovered_assets": assets,
        "http_fingerprint": http_info,
    }

    output_path = "discovery_report.json"
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n[+] Scan report generated successfully: {output_path}")
    print(json.dumps(report, indent=2))