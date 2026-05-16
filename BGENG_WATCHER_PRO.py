import asyncio
import aiohttp
import requests
import socket
import ssl
import dns.resolver
import whois
import phonenumbers
import sqlite3
import json
import os

from bs4 import BeautifulSoup
from colorama import Fore, init
from phonenumbers import geocoder, carrier
from datetime import datetime

init(autoreset=True)

# =========================================================
# CONFIG
# =========================================================

REPORT_DIR = "reports"

if not os.path.exists(REPORT_DIR):
    os.makedirs(REPORT_DIR)

HEADERS = {
    "User-Agent": "BGENG-WATCHER-PRO"
}

SOCIALS = {
    "GitHub": "https://github.com/{}",
    "Instagram": "https://instagram.com/{}",
    "TikTok": "https://www.tiktok.com/@{}",
    "TwitterX": "https://x.com/{}",
    "Reddit": "https://reddit.com/user/{}",
    "Pinterest": "https://pinterest.com/{}",
    "YouTube": "https://youtube.com/@{}",
    "Medium": "https://medium.com/@{}",
    "Steam": "https://steamcommunity.com/id/{}",
    "Twitch": "https://twitch.tv/{}",
    "GitLab": "https://gitlab.com/{}",
    "Facebook": "https://facebook.com/{}",
    "LinkedIn": "https://linkedin.com/in/{}"
}

COMMON_PORTS = [
    21,22,25,53,80,110,
    135,139,143,443,
    445,993,995,3306,
    3389,8080
]

# =========================================================
# BANNER
# =========================================================

def banner():

    print(Fore.Pink + r"""

██████╗  ██████╗ ███████╗███╗   ██╗ ██████╗
██╔══██╗██╔════╝ ██╔════╝████╗  ██║██╔════╝
██████╔╝██║  ███╗█████╗  ██╔██╗ ██║██║  ███╗
██╔══██╗██║   ██║██╔══╝  ██║╚██╗██║██║   ██║
██████╔╝╚██████╔╝███████╗██║ ╚████║╚██████╔╝
╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═══╝ ╚═════╝

        BGENG WATCHER PRO

""")

# =========================================================
# DATABASE
# =========================================================

def init_db():

    conn = sqlite3.connect("bgengwatcher.db")

    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT,
        module TEXT,
        result TEXT,
        created_at TEXT
    )
    """)

    conn.commit()
    conn.close()

def log_result(target, module, result):

    conn = sqlite3.connect("bgengwatcher.db")

    cur = conn.cursor()

    cur.execute("""
    INSERT INTO logs(target,module,result,created_at)
    VALUES(?,?,?,?)
    """, (
        target,
        module,
        json.dumps(result),
        str(datetime.now())
    ))

    conn.commit()
    conn.close()

# =========================================================
# REPORT
# =========================================================

def save_report(name, data):

    filename = f"{REPORT_DIR}/{name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

    print(Fore.GREEN + f"\n[+] Report saved -> {filename}")

# =========================================================
# USERNAME SCAN
# =========================================================

async def check_username(session, site, url):

    try:

        async with session.get(url, timeout=10) as response:

            text = await response.text()

            if response.status == 200:

                bad_patterns = [
                    "Page Not Found",
                    "This account doesn't exist",
                    "User not found"
                ]

                for pattern in bad_patterns:

                    if pattern.lower() in text.lower():
                        return site, url, False

                return site, url, True

    except:
        pass

    return site, url, False

async def username_scan(username):

    print(Fore.YELLOW + f"\n[+] Username Scan: {username}\n")

    results = {}

    connector = aiohttp.TCPConnector(limit=20)

    async with aiohttp.ClientSession(
        headers=HEADERS,
        connector=connector
    ) as session:

        tasks = []

        for site, template in SOCIALS.items():

            url = template.format(username)

            tasks.append(
                check_username(session, site, url)
            )

        responses = await asyncio.gather(*tasks)

        for site, url, found in responses:

            if found:

                print(Fore.GREEN + f"[FOUND] {site} -> {url}")

                results[site] = url

            else:

                print(Fore.RED + f"[MISS] {site}")

    save_report(username, results)

    log_result(username, "username_scan", results)

# =========================================================
# PHONE INTEL
# =========================================================

def phone_intel(number):

    print(Fore.YELLOW + "\n[+] Phone Intelligence\n")

    try:

        parsed = phonenumbers.parse(number)

        result = {

            "valid":
                phonenumbers.is_valid_number(parsed),

            "possible":
                phonenumbers.is_possible_number(parsed),

            "international":
                phonenumbers.format_number(
                    parsed,
                    phonenumbers.PhoneNumberFormat.INTERNATIONAL
                ),

            "country":
                geocoder.description_for_number(parsed, "en"),

            "carrier":
                carrier.name_for_number(parsed, "en")
        }

        print(json.dumps(result, indent=4))

        save_report("phoneintel", result)

    except Exception as e:

        print(Fore.RED + str(e))

# =========================================================
# EMAIL INTEL
# =========================================================

def email_intel(email):

    print(Fore.YELLOW + "\n[+] Email Intelligence\n")

    try:

        domain = email.split("@")[1]

        mx = dns.resolver.resolve(domain, "MX")

        result = {
            "email": email,
            "domain": domain,
            "mx_records": [str(x.exchange) for x in mx]
        }

        print(json.dumps(result, indent=4))

        save_report("emailintel", result)

    except Exception as e:

        print(Fore.RED + str(e))

# =========================================================
# DNS ENUM
# =========================================================

def dns_enum(domain):

    print(Fore.YELLOW + "\n[+] DNS Enumeration\n")

    records = ["A","MX","TXT","NS"]

    result = {}

    for record in records:

        try:

            answers = dns.resolver.resolve(domain, record)

            result[record] = [str(x) for x in answers]

        except:
            pass

    print(json.dumps(result, indent=4))

    save_report("dnsenum", result)

# =========================================================
# WHOIS
# =========================================================

def whois_lookup(domain):

    print(Fore.YELLOW + "\n[+] WHOIS Lookup\n")

    try:

        data = whois.whois(domain)

        result = {
            "domain": domain,
            "registrar": str(data.registrar),
            "creation_date": str(data.creation_date),
            "expiration_date": str(data.expiration_date),
            "emails": str(data.emails),
            "name_servers": str(data.name_servers)
        }

        print(json.dumps(result, indent=4))

        save_report("whois", result)

    except Exception as e:

        print(Fore.RED + str(e))

# =========================================================
# WEB ANALYZER
# =========================================================

def web_analyzer(url):

    print(Fore.YELLOW + "\n[+] Web Analyzer\n")

    try:

        r = requests.get(url, headers=HEADERS, timeout=10)

        soup = BeautifulSoup(r.text, "html.parser")

        result = {

            "url": url,

            "title":
                soup.title.string if soup.title else None,

            "server":
                r.headers.get("Server"),

            "powered_by":
                r.headers.get("X-Powered-By"),

            "security_headers": {

                "CSP":
                    r.headers.get("Content-Security-Policy"),

                "HSTS":
                    r.headers.get("Strict-Transport-Security"),

                "XFO":
                    r.headers.get("X-Frame-Options")
            }
        }

        print(json.dumps(result, indent=4))

        save_report("webintel", result)

    except Exception as e:

        print(Fore.RED + str(e))

# =========================================================
# SSL INFO
# =========================================================

def ssl_info(domain):

    print(Fore.YELLOW + "\n[+] SSL Information\n")

    try:

        context = ssl.create_default_context()

        with context.wrap_socket(
            socket.socket(),
            server_hostname=domain
        ) as s:

            s.settimeout(5)

            s.connect((domain, 443))

            cert = s.getpeercert()

            print(json.dumps(cert, indent=4, default=str))

            save_report("ssl", cert)

    except Exception as e:

        print(Fore.RED + str(e))

# =========================================================
# SUBDOMAIN ENUM
# =========================================================

def subdomain_enum(domain):

    print(Fore.YELLOW + "\n[+] Subdomain Enumeration\n")

    subdomains = [
        "www","mail","ftp","api",
        "admin","dev","test"
    ]

    found = []

    for sub in subdomains:

        target = f"{sub}.{domain}"

        try:

            ip = socket.gethostbyname(target)

            print(Fore.GREEN + f"[FOUND] {target} -> {ip}")

            found.append({
                "subdomain": target,
                "ip": ip
            })

        except:
            pass

    save_report("subdomains", found)

# =========================================================
# PORT SCANNER
# =========================================================

def port_scan(ip):

    print(Fore.YELLOW + "\n[+] Port Scan\n")

    open_ports = []

    for port in COMMON_PORTS:

        try:

            sock = socket.socket()

            sock.settimeout(1)

            result = sock.connect_ex((ip, port))

            if result == 0:

                print(Fore.GREEN + f"[OPEN] {port}")

                open_ports.append(port)

            sock.close()

        except:
            pass

    save_report("ports", open_ports)

# =========================================================
# ROBOTS
# =========================================================

def robots_check(domain):

    print(Fore.YELLOW + "\n[+] robots.txt\n")

    try:

        url = f"https://{domain}/robots.txt"

        r = requests.get(url)

        print(r.text)

    except Exception as e:

        print(Fore.RED + str(e))

# =========================================================
# SITEMAP
# =========================================================

def sitemap_check(domain):

    print(Fore.YELLOW + "\n[+] sitemap.xml\n")

    try:

        url = f"https://{domain}/sitemap.xml"

        r = requests.get(url)

        print(r.text[:3000])

    except Exception as e:

        print(Fore.RED + str(e))

# =========================================================
# MENU
# =========================================================

async def main():

    init_db()

    banner()

    while True:

        print(Fore.CYAN + """

[1] Username Scan
[2] Phone Intelligence
[3] Email Intelligence
[4] WHOIS Lookup
[5] DNS Enumeration
[6] Website Analyzer
[7] SSL Information
[8] Subdomain Enumeration
[9] Port Scanner
[10] robots.txt Analyzer
[11] sitemap.xml Analyzer

[0] Exit

""")

        choice = input(Fore.YELLOW + "BGENG WATCHER > ")

        if choice == "1":

            username = input("Username: ")

            await username_scan(username)

        elif choice == "2":

            number = input("Phone Number: ")

            phone_intel(number)

        elif choice == "3":

            email = input("Email: ")

            email_intel(email)

        elif choice == "4":

            domain = input("Domain: ")

            whois_lookup(domain)

        elif choice == "5":

            domain = input("Domain: ")

            dns_enum(domain)

        elif choice == "6":

            url = input("URL: ")

            web_analyzer(url)

        elif choice == "7":

            domain = input("Domain: ")

            ssl_info(domain)

        elif choice == "8":

            domain = input("Domain: ")

            subdomain_enum(domain)

        elif choice == "9":

            ip = input("IP: ")

            port_scan(ip)

        elif choice == "10":

            domain = input("Domain: ")

            robots_check(domain)

        elif choice == "11":

            domain = input("Domain: ")

            sitemap_check(domain)

        elif choice == "0":

            break

asyncio.run(main())