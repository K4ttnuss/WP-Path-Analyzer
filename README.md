# WP Path Analyzer
WordPress Path Scanner & Version Detector

Python tool to check if a site is running WordPress, try to detect its version, and scan common paths.

---

## Features 
- Detects if a site is running WordPress.  
- Attempts to identify the version.  
- Scans common paths (`/wp-admin`, `/xmlrpc.php`, etc.).  
- Uses realistic headers and random User-Agents.  

---

## Requirements
- requests
- colorama
  
---

## Installation
Tested with Python 3.12+

```bash
git clone https://github.com/K4ttnuss/wp-path-analyzer.git
cd wp-path-analyzer
pip install -r requirements.txt
```

---

## Usage Example
```
python wp_path_analyzer.py -u https://example.com

 _       ______  ____        __  __    ___                __                     
| |     / / __ \/ __ \____ _/ /_/ /_  /   |  ____  ____ _/ /_  ______  ___  _____
| | /| / / /_/ / /_/ / __ `/ __/ __ \/ /| | / __ \/ __ `/ / / / /_  / / _ \/ ___/
| |/ |/ / ____/ ____/ /_/ / /_/ / / / ___ |/ / / / /_/ / / /_/ / / /_/  __/ /    
|__/|__/_/   /_/    \__,_/\__/_/ /_/_/  |_/_/ /_/\__,_/_/\__, / /___/\___/_/     
                                                        /____/                   

[+] WP Path Analyzer - Common Path Scanner for WordPress

[?] Enter the site URL to analyze: https://example.com/

Checking if https://example.com is using WordPress...
[+] WordPress detected on https://example.com via /wp-json/
[+] WordPress detected on https://example.com
[!] Version detected (meta): 6.4.6

Scanning routes on https://example.com...

[-] Unknown status: https://example.com/wp-admin (423)
[-] Unknown status: https://example.com/wp-login.php (502)
[+] Route found: https://example.com/wp-content/ (200 OK)
[!] Route blocked: https://example.com/wp-content/uploads/ (403 Forbidden)

Analysis completed.
```
---

## License
This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.

Use only with explicit authorization.
