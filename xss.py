import asyncio
import sys
import os
import requests
from colorama import init, Fore, Style
import subprocess
import datetime
import urllib.parse

def show_banner(url, wordlist_file):
    # Use Figlet to create the ASCII art banner
    banner = subprocess.check_output(["figlet", "-f", "slant", "XSScan"]).decode("utf-8")
    print(Fore.YELLOW + banner + Style.RESET_ALL)
    print(Fore.CYAN + "🌙🦊 XSScan is a powerful open-source XSS scanner and utility focused on automation.")
    print(f"\n 🎯  Target                 {url}")
    print(f" 🏁  Method                 FILE Mode")
    print(f" 🖥   Worker                 {wordlist_file}")
    print(" 🔦  BAV                    true")
    print(f" 🕰   Started at             {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    print(" >>>>>>>>>>>>>>>>>>>>>>>>>")

def check_xss_vulnerability(url, payload, allow_redirects=True):
    try:
        # Encode the payload before appending it to the URL
        encoded_payload = urllib.parse.quote(payload)

        response = requests.get(url + encoded_payload, allow_redirects=allow_redirects)

        if response.ok:
            if "<script>" in response.text:
                return True
        else:
            print(Fore.RED + f"Error occurred while checking URL '{url + encoded_payload}': Status Code {response.status_code}")
            return False

    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"Error occurred while checking URL '{url + encoded_payload}': {e}")
        return False
    
async def scan_url(url, payloads, allow_redirects):
    return [await asyncio.to_thread(check_xss_vulnerability, url, payload, allow_redirects) for payload in payloads]

async def scanner_with_thread(input_url=None, allow_redirects=True, save_results=False, num_threads=2):
    if not input_url:
        print(Fore.RED + "Please provide a URL to proceed.")
        sys.exit(1)

    # Check if the user input is a valid URL
    if not input_url.startswith(("http://", "https://")):
        print(Fore.RED + "Invalid URL. Please provide a valid URL starting with 'http://' or 'https://'." + Style.RESET_ALL)
        sys.exit(1)

    # Show the banner with the user input
    show_banner(url=input_url, wordlist_file="otomatis")

    # Read URLs from wordlist and run scanning URL and wordlists concurrently
    ex_folder = "ex"
    payloads = []
    for i in range(1, 11):
        file_path = os.path.join(ex_folder, f"XSS_{i}.txt")
        if os.path.isfile(file_path):
            with open(file_path, "r") as f:
                lines = f.readlines()
                payloads.extend([line.strip() for line in lines])

    # Split the payloads into smaller chunks based on the number of threads
    chunk_size = len(payloads) // num_threads
    payload_chunks = [payloads[i:i+chunk_size] for i in range(0, len(payloads), chunk_size)]

    tasks = [scan_url(input_url, payload_chunk, allow_redirects) for payload_chunk in payload_chunks]
    results = await asyncio.gather(*tasks)
    vulnerabilities = [url for chunk_vulnerabilities in results for url, is_vulnerable in zip(payloads, chunk_vulnerabilities) if is_vulnerable]

    sys.stdout.write("\n")
    # Save the results to a file if save_results is True
    if save_results:
        with open("xss_scan_results.txt", "w") as f:
            f.write("Potential XSS vulnerabilities found:\n")
            for vulnerability in vulnerabilities:
                f.write(f" - {input_url + vulnerability}\n")

    # Return the list of potential vulnerabilities
    return vulnerabilities

if __name__ == "__main__":
    init(autoreset=True)  # Initialize colorama

    # Ask the user to input a URL (required)
    user_input_url = input("Enter a URL to scan:|=====---> ").strip()

    # Ask the user if they want to follow redirects during the scan (optional)
    allow_redirects_input = input("Follow redirects during the scan? (Y/N, default: Y): ").strip().lower()
    allow_redirects = True if allow_redirects_input != "n" else False

    # Run scanning with the provided URL and wordlists from 'ex' folder
    asyncio.run(scanner_with_thread(input_url=user_input_url, allow_redirects=allow_redirects))
