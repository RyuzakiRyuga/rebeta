import requests
import re
import argparse
from bs4 import BeautifulSoup
from colorama import Fore, Style

# Initialize a set to store already visited links
visited_links = set()

# Initialize an empty list to store vulnerable links
vulnerable_links = []

def check_link(link, pattern):
    """Check if a link is vulnerable by sending a GET request"""
    global vulnerable_links
    if link in visited_links:
        return
    
    visited_links.add(link)
    
    try:
        response = requests.get(link)
        if response.ok:
            if pattern and re.search(pattern, response.text):
                vulnerability = {"name": pattern, "severity": "high"}
                vulnerable_links.append((link, "vulnerable", vulnerability))
                print(Fore.RED + f"[+] {link} is vulnerable ({pattern} detected)" + Style.RESET_ALL)
                exploit_link(link, vulnerability)
            else:
                vulnerable_links.append((link, "safe", None))
                print(Fore.GREEN + f"[+] {link} is safe" + Style.RESET_ALL)
                
            # Parse the HTML content using BeautifulSoup to find links
            soup = BeautifulSoup(response.text, 'html.parser')
            links = soup.find_all('a')
            for l in links:
                href = l.get('href')
                if href:
                    if 'http' in href and not url in href:
                        continue  # skip external links
                    if '#' in href:
                        href = href.split('#')[0]  # exclude anchor links
                    if not href.startswith('http'):
                        href = url + '/' + href.lstrip('/')
                    check_link(href, pattern)
        else:
            print(f"[-] Failed to retrieve {link}")
    except requests.exceptions.RequestException as e:
        print(f"[-] Error occurred while retrieving {link}: {e}")

def exploit_link(link, vulnerability):
    """Exploit a vulnerable link"""
    print(Fore.RED + f"[-] Exploiting {link} ({vulnerability['name']} detected)" + Style.RESET_ALL)
    # Add code to exploit the vulnerable link here
    try:
        response = requests.post(link, data={'username': 'admin', 'password': 'password'}, verify=False)
        if response.ok:
            print(Fore.GREEN + f"[+] Successfully exploited {link}" + Style.RESET_ALL)
            print(response.content)
        else:
            print(Fore.RED + "[-] Failed to exploit {link}" + Style.RESET_ALL)
        vulnerability["exploited"] = response.ok
    except requests.exceptions.RequestException as e:
        print(f"[-] Error occurred while exploiting {link}: {e}")
        vulnerability["exploited"] = False
    vulnerability["response"] = response

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan a website for vulnerabilities")
    parser.add_argument("-u", "--url", help="The URL of the website to scan")
    parser.add_argument("--pattern", help="The regex pattern to match vulnerable pages")
    args = parser.parse_args()

    url = args.url
    pattern = args.pattern
    
    check_link(url, pattern)
    
    if vulnerable_links:
        print(f"\nFound {len(vulnerable_links)} vulnerable links:")
        for link, status, vulnerability in vulnerable_links:
            if vulnerability:
                print(f"{Fore.RED if status == 'vulnerable' else Fore.GREEN}{link} is {status} ({vulnerability['severity']} risk, vulnerability: {vulnerability['name']}, exploited: {vulnerability['exploited']})" + Style.RESET_ALL)
            else:
                print(f"{Fore.GREEN}{link} is {status}" + Style.RESET_ALL)
    else:
        print("No vulnerabilities found.")
