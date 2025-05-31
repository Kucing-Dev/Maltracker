import argparse
import requests
import os
import hashlib
import csv
from colorama import Fore, Style, init

init(autoreset=True)

VT_API_KEY = "your_API"
VT_BASE_URL = "https://www.virustotal.com/api/v3/files/"
HEADERS = {"x-apikey": VT_API_KEY}

ASCII_BANNER = r'''
 /\     /\
{  `---'  }    M A L T R A C K E R
{  O   O  }     meoOWw !!!
~~>  V  <~~
 \  \|/  /
  `-----'____
  /     \\    \\
 {       }\\  )_\\_   🐾
 |  \\_/  |/ /  /
  \\__/  /(_/ _/
    (__/

         OSINT Malware Tracker Tool
         by @Kucing-Dev / 0xMiawChan
'''

def print_result(data, hash_value):
    stats = data['data']['attributes']['last_analysis_stats']
    link = f"https://www.virustotal.com/gui/file/{hash_value}"

    print(f"🧪 Results from VirusTotal")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"✅ Harmless    : {stats['harmless']}")
    print(f"🔎 Suspicious  : {stats['suspicious']}")
    print(f"☣️  Malicious   : {stats['malicious']}")
    print(f"❓ Undetected  : {stats['undetected']}")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

    if stats['malicious'] > 5:
        verdict = "💀 Highly Malicious"
    elif stats['malicious'] > 0:
        verdict = "☣️ Malicious"
    elif stats['suspicious'] > 0:
        verdict = "⚠️ Suspicious"
    else:
        verdict = "✅ Clean"

    print(f"{Fore.CYAN}🔎 Verdict: {verdict}")
    print(f"🔗 Link: {link}")
    return {
        "hash": hash_value,
        "verdict": verdict,
        "harmless": stats['harmless'],
        "suspicious": stats['suspicious'],
        "malicious": stats['malicious'],
        "undetected": stats['undetected'],
        "link": link
    }

def lookup_hash(hash_value):
    print(ASCII_BANNER)
    print(f"🔍 Querying VirusTotal for: {hash_value}\n")

    url = VT_BASE_URL + hash_value
    response = requests.get(url, headers=HEADERS)

    if response.status_code == 200:
        data = response.json()
        return print_result(data, hash_value)
    else:
        print(f"{Fore.RED}❌ Error: Unable to retrieve data (Status {response.status_code})")
        if response.status_code == 403:
            print(f"{Fore.RED}→ Your API key may be invalid or rate-limited.")
        return None

def hash_file(filepath):
    with open(filepath, "rb") as f:
        bytes = f.read()
        readable_hash = hashlib.sha256(bytes).hexdigest()
    return readable_hash

def export_to_csv(results, filename="results.csv"):
    with open(filename, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=results[0].keys())
        writer.writeheader()
        for result in results:
            writer.writerow(result)
    print(f"{Fore.GREEN}✅ Results exported to {filename}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='MalTrack - OSINT Malware Tracker')
    parser.add_argument('--hash', type=str, help='File hash to lookup (MD5/SHA1/SHA256)')
    parser.add_argument('--file', type=str, help='Path to file to hash and lookup')
    parser.add_argument('--hashlist', type=str, help='Path to file containing list of hashes (one per line)')
    parser.add_argument('--export', type=str, help='Export results to CSV file')
    args = parser.parse_args()

    results = []

    if args.hash:
        res = lookup_hash(args.hash)
        if res: results.append(res)
    elif args.file:
        h = hash_file(args.file)
        res = lookup_hash(h)
        if res: results.append(res)
    elif args.hashlist:
        with open(args.hashlist, 'r') as f:
            for line in f:
                hash_value = line.strip()
                if hash_value:
                    res = lookup_hash(hash_value)
                    if res: results.append(res)
    else:
        print("Usage:")
        print("  python maltracker.py --hash <hash>")
        print("  python maltracker.py --file <filename>")
        print("  python maltracker.py --hashlist <file.txt>")

    if results and args.export:
        export_to_csv(results, args.export)

