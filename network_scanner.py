pip install python-nmap requests

import nmap
import requests

# Network Scanning Function
def scan_network(target):
    nm = nmap.PortScanner()
    nm.scan(target, '1-1024')
    return nm

# Identify Services Running on Open Ports
def identify_services(nm):
    services = {}
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                service = nm[host][proto][port]['name']
                services[port] = service
    return services

# Check for Known Vulnerabilities
def check_vulnerabilities(service):
    url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={service}"
    response = requests.get(url)
    if response.status_code == 200:
        vulnerabilities = response.json().get('result', {}).get('CVE_Items', [])
        return vulnerabilities
    return []

# Main Function to Run the Scanner
if __name__ == "__main__":
    target = input("Enter the target IP address or range: ")
    nm = scan_network(target)
    services = identify_services(nm)
    
    for port, service in services.items():
        print(f"Port {port}: {service}")
        vulnerabilities = check_vulnerabilities(service)
        if vulnerabilities:
            print(f"Found {len(vulnerabilities)} vulnerabilities for {service}:")
            for vuln in vulnerabilities:
                print(f"- {vuln['cve']['CVE_data_meta']['ID']}: {vuln['cve']['description']['description_data'][0]['value']}")
        else:
            print(f"No known vulnerabilities found for {service}.")
