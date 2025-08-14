VulRecon Scanner is a Python-based, all-in-one reconnaissance and vulnerability scanning tool for ethical hacking, penetration testing, and OSINT research.
It performs domain & network reconnaissance and real-time CVE lookups to help identify known vulnerabilities and security misconfigurations.

🚀 Features

WHOIS Lookup – Registrar details, creation & expiry dates, contact info.

DNS Enumeration – A, MX, NS, and TXT records.

Subdomain Scanning – Find hidden endpoints.

Port Scanning – Identify open ports & running services.

HTTP Header Analysis – Detect server version & security headers.

CVE Vulnerability Lookup – Real-time integration with the NVD CVE database to check for known vulnerabilities.

Detailed Reports – Export structured vulnerability reports.

📦 Installation
git clone https://github.com/adi52303/VulRecon-scanner.git
cd VulRecon-scanner
pip install -r requirements.txt

🛠 Usage
python vulrecon.py -t target.com


Example:

python vulrecon.py -t nmap.org

📄 Example Output

⚠️ Disclaimer

This tool is for educational purposes and authorized testing only.
Unauthorized scanning is illegal.
