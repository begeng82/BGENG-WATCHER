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
import re
import hashlib
import random

from bs4 import BeautifulSoup
from colorama import Fore, init
from phonenumbers import geocoder, carrier, timezone
from phonenumbers.phonenumberutil import (
    number_type,
    PhoneNumberType
)
from datetime import datetime

init(autoreset=True)

# =========================================================
# CONFIG
# =========================================================

REPORT_DIR = "reports"

if not os.path.exists(REPORT_DIR):
    os.makedirs(REPORT_DIR)

USER_AGENTS = [

    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",

    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/123.0.0.0 Safari/537.36",

    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",

    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36",

    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edge/123.0.0.0"
]

HEADERS = {
    "User-Agent": random.choice(USER_AGENTS)
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

PHONE_TYPE_MAP = {

    PhoneNumberType.MOBILE:
        "Mobile",

    PhoneNumberType.FIXED_LINE:
        "Fixed Line",

    PhoneNumberType.FIXED_LINE_OR_MOBILE:
        "Fixed Line or Mobile",

    PhoneNumberType.TOLL_FREE:
        "Toll Free",

    PhoneNumberType.PREMIUM_RATE:
        "Premium Rate",

    PhoneNumberType.VOIP:
        "VOIP",

    PhoneNumberType.PAGER:
        "Pager",

    PhoneNumberType.UNKNOWN:
        "Unknown"
}

# =========================================================
# BANNER
# =========================================================

def banner():

    print(Fore.CYAN + r"""

██████╗  ██████╗ ███████╗███╗   ██╗ ██████╗
██╔══██╗██╔════╝ ██╔════╝████╗  ██║██╔════╝
██████╔╝██║  ███╗█████╗  ██╔██╗ ██║██║  ███╗
██╔══██╗██║   ██║██╔══╝  ██║╚██╗██║██║   ██║
██████╔╝╚██████╔╝███████╗██║ ╚████║╚██████╔╝
╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═══╝ ╚═════╝

        BGENG WATCHER
 ADVANCED DEFENSIVE OSINT SUITE

""")

# =========================================================
# DATABASE
# =========================================================

def init_db():

    conn = sqlite3.connect("bgengwatcher.db")

    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS logs (
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

    cursor = conn.cursor()

    cursor.execute("""
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
# REPORT SYSTEM
# =========================================================

def save_report(name, data):

    filename = f"{REPORT_DIR}/{name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    with open(filename, "w", encoding="utf-8") as f:

        json.dump(data, f, indent=4)

    print(Fore.GREEN + f"\n[+] Report saved -> {filename}")

# =========================================================
# ADVANCED USERNAME SCAN
# =========================================================

async def check_username(session, site, url, semaphore):

    async with semaphore:

        retries = 2

        for attempt in range(retries):

            try:

                headers = {

                    "User-Agent":
                        random.choice(USER_AGENTS),

                    "Accept":
                        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",

                    "Accept-Language":
                        "en-US,en;q=0.5"
                }

                async with session.get(
                    url,
                    headers=headers,
                    timeout=12,
                    allow_redirects=True
                ) as response:

                    status = response.status

                    if status == 429:

                        await asyncio.sleep(2)

                        continue

                    if status == 404:

                        return site, url, False, status

                    if status == 200:

                        text = await response.text()

                        bad_patterns = [

                            "page not found",
                            "this account doesn't exist",
                            "user not found",
                            "sorry, nobody on reddit goes by that name",
                            "could not be found"
                        ]

                        if any(
                            pattern in text.lower()
                            for pattern in bad_patterns
                        ):

                            return site, url, False, "Soft 404"

                        return site, url, True, status

                    return site, url, False, status

            except asyncio.TimeoutError:

                if attempt == retries - 1:

                    return site, url, False, "Timeout"

            except Exception:

                return site, url, False, "Error"

        return site, url, False, "Failed"

async def username_scan(username):

    print(Fore.YELLOW + f"\n[+] Username Scan: {username}\n")

    results = {}

    semaphore = asyncio.Semaphore(15)

    connector = aiohttp.TCPConnector(
        limit=0,
        ssl=False
    )

    async with aiohttp.ClientSession(
        connector=connector
    ) as session:

        tasks = []

        for site, template in SOCIALS.items():

            url = template.format(username)

            tasks.append(
                asyncio.create_task(
                    check_username(
                        session,
                        site,
                        url,
                        semaphore
                    )
                )
            )

        for future in asyncio.as_completed(tasks):

            site, url, found, status = await future

            if found:

                print(
                    Fore.GREEN +
                    f"[FOUND] {site:<15} -> {url}"
                )

                results[site] = {

                    "url": url,
                    "status": status
                }

            else:

                print(
                    Fore.RED +
                    f"[MISS]  {site:<15} -> {status}"
                )

    save_report(username, results)

    log_result(username, "username_scan", results)

# =========================================================
# PHONE INTEL
# =========================================================

def phone_intel(number):

    print(Fore.YELLOW + f"\n[+] Phone Intelligence: {number}\n")

    try:

        parsed = phonenumbers.parse(number)

        if not phonenumbers.is_valid_number(parsed):

            print(Fore.RED + "[-] Invalid phone number.")

            return

        result = {

            "validation": {

                "valid":
                    phonenumbers.is_valid_number(parsed),

                "possible":
                    phonenumbers.is_possible_number(parsed)
            },

            "formats": {

                "international":
                    phonenumbers.format_number(
                        parsed,
                        phonenumbers.PhoneNumberFormat.INTERNATIONAL
                    ),

                "national":
                    phonenumbers.format_number(
                        parsed,
                        phonenumbers.PhoneNumberFormat.NATIONAL
                    ),

                "e164":
                    phonenumbers.format_number(
                        parsed,
                        phonenumbers.PhoneNumberFormat.E164
                    )
            },

            "location_data": {

                "country":
                    geocoder.description_for_number(
                        parsed,
                        "en"
                    ),

                "carrier":
                    carrier.name_for_number(
                        parsed,
                        "en"
                    ),

                "timezone":
                    list(
                        timezone.time_zones_for_number(parsed)
                    ),

                "line_type":
                    PHONE_TYPE_MAP.get(
                        number_type(parsed),
                        "Unknown"
                    )
            }
        }

        print(json.dumps(result, indent=4))

        save_report("phone_intel", result)

        log_result(number, "phone_intel", result)

    except Exception as e:

        print(Fore.RED + str(e))

# =========================================================
# EMAIL INTEL
# =========================================================

def smtp_banner(mx_host):

    try:

        server = socket.socket()

        server.settimeout(5)

        server.connect((mx_host, 25))

        banner = server.recv(1024).decode()

        server.close()

        return banner.strip()

    except:

        return "Unavailable"

def email_intel(email):

    print(Fore.YELLOW + f"\n[+] Email Intelligence: {email}\n")

    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):

        print(Fore.RED + "[-] Invalid email format.")

        return

    domain = email.split("@")[1]

    result = {

        "email": email,
        "domain": domain,
        "dns_records": {},
        "security": {},
        "osint": {}
    }

    try:

        # MX
        try:

            mx_records = dns.resolver.resolve(domain, "MX")

            result["dns_records"]["MX"] = [
                str(x.exchange)
                for x in mx_records
            ]

        except:

            result["dns_records"]["MX"] = []

        # SPF
        try:

            txt_records = dns.resolver.resolve(domain, "TXT")

            result["security"]["SPF"] = [

                str(x)

                for x in txt_records

                if "v=spf1" in str(x).lower()
            ]

        except:

            result["security"]["SPF"] = []

        # DMARC
        try:

            dmarc = dns.resolver.resolve(
                f"_dmarc.{domain}",
                "TXT"
            )

            result["security"]["DMARC"] = [
                str(x)
                for x in dmarc
            ]

        except:

            result["security"]["DMARC"] = []

        # Gravatar
        email_hash = hashlib.md5(
            email.lower().encode()
        ).hexdigest()

        result["osint"]["gravatar"] = {

            "profile":
                f"https://en.gravatar.com/{email_hash}.json",

            "avatar":
                f"https://www.gravatar.com/avatar/{email_hash}?d=404"
        }

        print(json.dumps(result, indent=4))

        save_report("email_intel", result)

        log_result(email, "email_intel", result)

    except Exception as e:

        print(Fore.RED + str(e))

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
# DNS ENUM
# =========================================================

def dns_enum(domain):

    print(Fore.YELLOW + "\n[+] DNS Enumeration\n")

    records = [
        "A","AAAA","MX",
        "TXT","NS","CNAME"
    ]

    result = {}

    for record in records:

        try:

            answers = dns.resolver.resolve(domain, record)

            result[record] = [
                str(x)
                for x in answers
            ]

        except:
            pass

    print(json.dumps(result, indent=4))

    save_report("dnsenum", result)

# =========================================================
# WEBSITE ANALYZER
# =========================================================

def web_analyzer(url):

    print(Fore.YELLOW + "\n[+] Website Analyzer\n")

    try:

        r = requests.get(
            url,
            headers=HEADERS,
            timeout=10
        )

        soup = BeautifulSoup(
            r.text,
            "html.parser"
        )

        result = {

            "url": url,

            "title":
                soup.title.string
                if soup.title else None,

            "server":
                r.headers.get("Server"),

            "powered_by":
                r.headers.get("X-Powered-By"),

            "content_type":
                r.headers.get("Content-Type"),

            "security_headers": {

                "CSP":
                    r.headers.get(
                        "Content-Security-Policy"
                    ),

                "HSTS":
                    r.headers.get(
                        "Strict-Transport-Security"
                    ),

                "XFO":
                    r.headers.get(
                        "X-Frame-Options"
                    )
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

            print(
                json.dumps(
                    cert,
                    indent=4,
                    default=str
                )
            )

            save_report("ssl", cert)

    except Exception as e:

        print(Fore.RED + str(e))

# =========================================================
# SUBDOMAIN ENUM
# =========================================================

def subdomain_enum(domain):

    print(Fore.YELLOW + "\n[+] Subdomain Enumeration\n")

    subdomains = [
        "www","mail","ftp",
        "api","admin","dev",
        "test"
    ]

    found = []

    for sub in subdomains:

        target = f"{sub}.{domain}"

        try:

            ip = socket.gethostbyname(target)

            print(
                Fore.GREEN +
                f"[FOUND] {target} -> {ip}"
            )

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

                print(
                    Fore.GREEN +
                    f"[OPEN] {port}"
                )

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

        choice = input(
            Fore.YELLOW +
            "BGENG WATCHER > "
        )

        if choice == "1":

            username = input("Username: ")

            await username_scan(username)

        elif choice == "2":

            number = input(
                "Phone Number (+62xxx): "
            )

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
