import requests
import time
import random
import argparse
import re
from colorama import Fore, Style, init
from urllib.parse import urlparse

# ================== Initialize colorama ==================
init(autoreset=True)

# ================== Colors ==================
GREEN = Fore.GREEN
RED = Fore.RED
YELLOW = Fore.YELLOW
BLUE = Fore.BLUE
RESET = Style.RESET_ALL

# ================== Common WordPress Routes ==================
routes = [
    "/wp-admin", "/wp-login.php", "/wp-content/", "/wp-content/uploads/",
    "/wp-includes/", "/wp-json/", "/xmlrpc.php", "/readme.html",
    "/license.txt", "/wp-config.php", "/wp-cron.php", "/feed/",
    "/sitemap.xml", "/robots.txt", "/wp-admin/admin-ajax.php",
    "/wp-admin/admin-post.php", "/wp-content/debug.log", "/wp-content/db.php",
    "/wp-sitemap.xml"
]

# ================== User-Agents ==================
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36"
]

# ================== Default Headers ==================
DEFAULT_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Connection": "keep-alive",
    "Accept-Language": "en-US,en;q=0.5"
}

# ================== Regex for Version Detection ==================
GENERATOR_RE = re.compile(
    r'<meta\b[^>]*name=["\']generator["\'][^>]*content=["\']\s*WordPress\s+([\d.]+)\s*["\']|'
    r'<meta\b[^>]*content=["\']\s*WordPress\s+([\d.]+)\s*["\'][^>]*name=["\']generator["\']',
    re.IGNORECASE
)
ASSET_VER_RE = re.compile(
    r'(?:wp-includes/[^"\']+\.(?:css|js)|wp-emoji-release\.min\.js)\?ver=([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
    re.IGNORECASE
)

# ================== Banner ==================
def print_banner():
    print(GREEN + """
     _       ______  ____        __  __    ___                __                     
    | |     / / __ \/ __ \____ _/ /_/ /_  /   |  ____  ____ _/ /_  ______  ___  _____
    | | /| / / /_/ / /_/ / __ `/ __/ __ \/ /| | / __ \/ __ `/ / / / /_  / / _ \/ ___/
    | |/ |/ / ____/ ____/ /_/ / /_/ / / / ___ |/ / / / /_/ / / /_/ / / /_/  __/ /    
    |__/|__/_/   /_/    \__,_/\__/_/ /_/_/  |_/_/ /_/\__,_/_/\__, / /___/\___/_/     
                                                        /____/                   
    """ + RESET)
    print(f"{GREEN}[+] WP Path Analyzer - Common Path Scanner for WordPress{RESET}\n")

# ================== Normalize URL ==================
def normalize_url(url):
    url = (url or "").strip()
    if not url:
        return None
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed_url = urlparse(url)
    if not parsed_url.scheme or not parsed_url.netloc:
        print(f"{RED}[-] Malformed URL: {url}. Please ensure it's written correctly.{RESET}")
        return None
    return url.rstrip("/")

# ================== Networking Utilities ==================
def _build_session():
    s = requests.Session()
    try:
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        retry = Retry(
            total=3,
            connect=3,
            read=3,
            status=3,
            backoff_factor=0.5,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=("HEAD", "GET", "OPTIONS"),
            respect_retry_after_header=True,
            raise_on_status=False,
        )
        s.mount("http://", HTTPAdapter(max_retries=retry))
        s.mount("https://", HTTPAdapter(max_retries=retry))
    except Exception:
        pass
    return s

def _get(session, url, headers, timeout=10, **kw):
    """GET request with fallback to HTTP if HTTPS fails due to SSL"""
    try:
        return session.get(url, headers=headers, timeout=timeout, **kw)
    except requests.exceptions.SSLError:
        if url.startswith("https://"):
            return session.get("http://" + url[8:], headers=headers, timeout=timeout, **kw)
        raise

def _content_type_is_html(resp):
    return "text/html" in resp.headers.get("Content-Type", "").lower()

def _blocked_status(code):
    return code in (403, 406, 429, 503)

class UAState:
    """Keeps a stable User-Agent and rotates if blocked."""
    def __init__(self, agents):
        agents = list(agents)
        random.shuffle(agents)
        self.agents = agents
        self.idx = 0

    @property
    def current(self):
        return self.agents[self.idx]

    def rotate(self):
        self.idx = (self.idx + 1) % len(self.agents)

def _pick_headers(base_url, ua):
    return {"User-Agent": ua, "Referer": base_url, **DEFAULT_HEADERS}

def _get_with_rotation(session, url, base_url, ua_state, timeout=10, **kw):
    """Request with current User-Agent; if blocked, wait, rotate UA and retry once."""
    headers = _pick_headers(base_url, ua_state.current)
    resp = _get(session, url, headers=headers, timeout=timeout, **kw)
    try:
        status = resp.status_code
    except Exception:
        return resp

    if _blocked_status(status):
        time.sleep(random.uniform(0.6, 1.2))
        ua_state.rotate()
        headers = _pick_headers(base_url, ua_state.current)
        resp = _get(session, url, headers=headers, timeout=timeout, **kw)
    return resp

# ================== WordPress Detection & Version ==================
def detect_wordpress(base_url, session, ua_state):
    print(f"{BLUE}Checking if {base_url} is using WordPress...{RESET}")

    try:
        # Signal 1: /wp-json/
        wp_json_ok = False
        try:
            r_api = _get_with_rotation(session, f"{base_url}/wp-json/", base_url, ua_state, timeout=10)
            if r_api.status_code == 200 and "application/json" in r_api.headers.get("Content-Type", "").lower():
                t = r_api.text
                if ('"wp/v2"' in t) or ('"routes"' in t) or ('"namespaces"' in t):
                    wp_json_ok = True
                    print(f"{GREEN}[+] WordPress detected on {base_url} via /wp-json/{RESET}")
        except requests.RequestException:
            pass

        # Homepage
        r_home = _get_with_rotation(session, base_url, base_url, ua_state, timeout=10)
        html = r_home.text if r_home.status_code == 200 else ""

        # Common signals
        set_cookie = r_home.headers.get("Set-Cookie", "").lower()
        cookie_wp = any(tok in set_cookie for tok in ("wordpress_", "wp-settings", "wp-postpass"))

        signals = [
            "/wp-content/", "/wp-includes/", "wp-emoji-release.min.js",
            'rel="https://api.w.org/"', "wp-block-library", "wp-embed-responsive"
        ]
        html_signal = any(sig in html for sig in signals)

        if not _content_type_is_html(r_home) or not html:
            try:
                r_login = _get_with_rotation(session, f"{base_url}/wp-login.php", base_url, ua_state, timeout=10)
                if r_login.status_code in (200, 401, 403) and _content_type_is_html(r_login):
                    html = r_login.text
                    html_signal = html_signal or ("name=\"log\"" in html and "wp-submit" in html)
            except requests.RequestException:
                pass

        # Sitemap
        wp_sitemap = False
        try:
            r_smap = _get_with_rotation(session, f"{base_url}/wp-sitemap.xml", base_url, ua_state, timeout=10)
            if r_smap.status_code == 200 and "xml" in r_smap.headers.get("Content-Type", "").lower():
                wp_sitemap = True
        except requests.RequestException:
            pass

        looks_wp = wp_json_ok or html_signal or cookie_wp or wp_sitemap

        if looks_wp:
            print(f"{GREEN}[+] WordPress detected on {base_url}{RESET}")

            # Version from meta
            m = GENERATOR_RE.search(html)
            if m:
                version = m.group(1) or m.group(2)
                print(f"{YELLOW}[!] Version detected (meta): {version}{RESET}")
                return True

            # Version from assets
            vers = ASSET_VER_RE.findall(html)
            if vers:
                def _vkey(v): return tuple(int(x) for x in v.split("."))
                best = sorted(set(vers), key=_vkey, reverse=True)[0]
                print(f"{YELLOW}[!] Version inferred from core assets: {best}{RESET}")
                return True

        # Fallbacks
        for file in ("/readme.html", "/license.txt"):
            try:
                rf = _get_with_rotation(session, base_url + file, base_url, ua_state, timeout=10)
                if rf.status_code == 200:
                    m = re.search(r'WordPress\s+(\d+\.\d+(?:\.\d+)?)', rf.text, re.IGNORECASE)
                    if m:
                        print(f"{YELLOW}[!] Version detected in {file}: {m.group(1)}{RESET}")
                        return True
            except requests.RequestException:
                pass

        if looks_wp:
            print(f"{YELLOW}[!] WordPress detected, but version could not be determined.{RESET}")
            return True

        print(f"{RED}[-] This doesn't appear to be a WordPress site.{RESET}")
        return False

    except requests.exceptions.RequestException as e:
        print(f"{RED}[-] Error connecting to {base_url}: {e}{RESET}")
        return False

# ================== Route Scanning ==================
def scan_wordpress(base_url, session, ua_state):
    print(f"{BLUE}Scanning routes on {base_url}...\n{RESET}")

    for route in routes:
        full_url = base_url + route
        try:
            time.sleep(random.uniform(1, 3))
            response = _get_with_rotation(session, full_url, base_url, ua_state, allow_redirects=True, timeout=10)

            if response.status_code == 200:
                print(f"{GREEN}[+] Route found: {full_url} (200 OK){RESET}")
            elif response.status_code == 403:
                print(f"{YELLOW}[!] Route blocked: {full_url} (403 Forbidden){RESET}")
            elif response.status_code == 401:
                print(f"{YELLOW}[!] Route protected: {full_url} (401 Unauthorized){RESET}")
            elif 300 <= response.status_code < 400:
                print(f"{BLUE}[~] Redirection detected: {full_url} → {response.url} ({response.status_code}){RESET}")
            elif response.status_code == 404:
                print(f"{RED}[-] Route not found: {full_url} (404 Not Found){RESET}")
            else:
                print(f"{RED}[-] Unknown status: {full_url} ({response.status_code}){RESET}")

        except requests.exceptions.Timeout:
            print(f"{RED}[-] Timeout connecting to {full_url}{RESET}")
        except requests.exceptions.ConnectionError:
            print(f"{RED}[-] Connection error with {full_url}{RESET}")
        except requests.exceptions.RequestException as e:
            print(f"{RED}[-] Error connecting to {full_url}: {e}{RESET}")

# ================== CLI ==================
def main():
    parser = argparse.ArgumentParser(description="Common Path Scanner for WordPress with version detection")
    parser.add_argument("-u", "--url", help="Site URL or multiple URLs separated by commas")
    args = parser.parse_args()

    print_banner()

    if not args.url:
        user_input = input(f"{YELLOW}[?] Enter the site URL to analyze: {RESET}").strip()
        if not user_input:
            print(f"{RED}[-] No URL entered. Exiting...{RESET}")
            return
        raw = [user_input]
    else:
        raw = args.url.split(",")

    url_list = []
    for u in raw:
        nu = normalize_url(u.strip())
        if nu and nu not in url_list:
            url_list.append(nu)

    session = _build_session()
    ua_state = UAState(USER_AGENTS)

    for url in url_list:
        if url:
            if detect_wordpress(url, session, ua_state):
                scan_wordpress(url, session, ua_state)

    print("\nAnalysis completed.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Interrupted by user.{RESET}")
