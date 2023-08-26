import argparse
import asyncio
import os
import sys
import time
import requests
import subprocess
import datetime
import logging
from colorama import init, Fore, Style
from tabulate import tabulate
from termcolor import colored
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import StaleElementReferenceException, NoSuchElementException, WebDriverException
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

def find_directory(url, directory):
    """
    Fungsi ini mencoba mengakses URL dengan menambahkan direktori yang diberikan.
    Jika responsenya berhasil (kode status 200), maka direktori ditemukan.
    """
    try:
        response = requests.get(url + "/" + directory)
        if response.status_code == 200:
            return url + "/" + directory
    except requests.exceptions.RequestException:
        pass

def scan_directories(url):
    # Membaca wordlist dari file
    wordlist_file = "db/wordlist.txt"
    with open(wordlist_file, "r") as file:
        wordlist = file.read().splitlines()

    # Mencoba setiap direktori dalam wordlist dengan progress bar
    progress_bar = tqdm(total=len(wordlist), desc="Scanning")
    results = []
    for directory in wordlist:
        found_url = find_directory(url, directory)
        if found_url:
            results.append(found_url)
        progress_bar.update(1)
    progress_bar.close()

    return results

def check_xss_vulnerability(url, payload, allow_redirects=True):
    try:
        response = requests.get(url + payload, allow_redirects=allow_redirects)

        if response.ok:
            if "<script>" in response.text:
                return True
        else:
            print(Fore.RED + f"Error occurred while checking URL '{url + payload}': Status Code {response.status_code}")
            return False

    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"Error occurred while checking URL '{url + payload}': {e}")
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

def read_wordlist(wordlist_file):
    with open(wordlist_file, 'r') as file:
        wordlist = file.read().splitlines()
    return wordlist

def brute_force(url, username, wordlists):
    results = []
    total_combinations = sum(len(read_wordlist(file)) for file in wordlists)
    combinations_tried = 0
    password_found = False

    with ThreadPoolExecutor() as executor:
        futures = []
        for wordlist_file in wordlists:
            wordlist = read_wordlist(wordlist_file)
            futures.append(executor.submit(check_login, url, username, wordlist))

        for future in as_completed(futures):
            try:
                success, password = future.result()
            except Exception as e:
                logger.error(f"Error occurred during login check: {e}")
                continue
            
            combinations_tried += len(wordlist)
            progress = combinations_tried / total_combinations * 100
            logger.info(f"Loading: {progress:.2f}% Complete")

            if success:
                results.append((username, password, "Success"))
                password_found = True
                break

    return results, password_found

def show_banner(tool_name):
    banner = colored(r"""
   __     __  __     ______     __    __     ______   __     __   __     ______     __   __     ______     ______  
/\ \  _ \ \/\ \   /\  __ \   /\ "-./  \   /\  __ \ /\ \   /\ "-.\ \   /\  ___\   /\ "-.\ \   /\  __ \   /\__  _\ 
\ \ \/ ".\ \ \ \  \ \  __ \  \ \ \-./\ \  \ \  __ \\ \ \  \ \ \-.  \  \ \___  \  \ \ \-.  \  \ \  __ \  \/_/\ \/ 
 \ \__/".~\_\_\_\  \ \_\ \_\  \ \_\ \ \_\  \ \_\ \_\\ \_\  \ \_\\"\_\  \/\_____\  \ \_\\"\_\  \ \_\ \_\    \ \_\ 
  \/_/   \/_/\_\/_/   \/_/\/_/   \/_/  \/_/   \/_/\/_/ \/_/   \/_/ \/_/   \/_____/   \/_/ \/_/   \/_/\/_/     \/_/ 
    """, "yellow")
    print(banner)
    print(Fore.GREEN + f"========== {tool_name.upper()} - A Powerful Security Tool ==========" + Style.RESET_ALL)

def check_login(url, username, wordlist):
    # Setup Selenium
    service = Service('path/to/chromedriver')  # Ganti dengan path ke chromedriver
    options = Options()
    options.add_argument('--headless')  # Menjalankan Chrome di mode headless
    driver = webdriver.Chrome(service=service, options=options)

    try:
        # Navigasi ke halaman login
        driver.get(url)

        try:
            # Cari elemen input username dan tombol submit
            input_username = driver.find_element(By.ID, "user_login")  # Ganti dengan nama elemen input username pada halaman login
        except NoSuchElementException:
            # If the element is not found by ID, try using other locators
            try:
                input_username = driver.find_element(By.NAME, "username")  # Example: using the name attribute
            except NoSuchElementException:
                # If still not found, try using CSS selector
                try:
                    input_username = driver.find_element(By.CSS_SELECTOR, "input[name='username']")
                except NoSuchElementException:
                    logger.error("Login elements not found. Check the login page structure.")
                    raise

        submit_button = driver.find_element(By.ID, "wp-submit")  # Ganti dengan nama elemen tombol submit pada halaman login

        for password in wordlist:
            try:
                input_password = driver.find_element(By.ID, "user_pass")  # Ganti dengan nama elemen input password pada halaman login
                input_password.clear()
                input_password.send_keys(password)
                submit_button.click()

                # Lakukan pengecekan apakah login berhasil
                # Contoh sederhana menggunakan URL setelah login
                if driver.current_url == "https://example.com/dashboard":  # Ganti dengan URL yang menunjukkan login berhasil
                    return True, password
            except StaleElementReferenceException:
                # Jika terjadi StaleElementReferenceException, cari ulang elemen yang dibutuhkan
                continue
            except WebDriverException as e:
                logger.error(f"Error occurred during login attempt: {e}")
                raise e
    finally:
        driver.quit()

    return False, None

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

def run_xsscan(url):
    init(autoreset=True)  # Initialize colorama

    # Ask the user if they want to follow redirects during the scan (optional)
    allow_redirects_input = input("Follow redirects during the scan? (Y/N, default: Y): ").strip().lower()
    allow_redirects = True if allow_redirects_input != "n" else False

    # Run scanning with the provided URL and wordlists from 'ex' folder
    asyncio.run(scanner_with_thread(input_url=url, allow_redirects=allow_redirects))

def run_directory_scanner(url):
    results = scan_directories(url)

    # Menampilkan hasil pemindaian
    print("\nHasil pemindaian:")
    if results:
        for result in results:
            print("[+] Found directory:", result)
    else:
        print("Tidak ditemukan direktori.")

def run_brute_force(url, username, wordlist):
    # ASCII Art Header with 7 different colors
    banner = """
    ██████   ██████ ███████████    █████ ██████   █████ ██████████      ███████    ██████   ██████ ███████████  
    ░░██████ ██████ ░█░░░███░░░█   ░░███ ░░██████ ░░███ ░░███░░░░███   ███░░░░░███ ░░██████ ██████ ░░███░░░░░███ 
     ░███░█████░███ ░   ░███  ░     ░███  ░███░███ ░███  ░███   ░░███ ███     ░░███ ░███░█████░███  ░███    ░███ 
     ░███░░███ ░███     ░███        ░███  ░███░░███░███  ░███    ░███░███      ░███ ░███░░███ ░███  ░██████████  
     ░███ ░░░  ░███     ░███        ░███  ░███ ░░██████  ░███    ░███░███      ░███ ░███ ░░░  ░███  ░███░░░░░███ 
     ░███      ░███     ░███        ░███  ░███  ░░█████  ░███    ███ ░░███     ███  ░███      ░███  ░███    ░███ 
     █████     █████    █████    ██ █████ █████  ░░█████ ██████████   ░░░███████░   █████     █████ █████   █████
    ░░░░░     ░░░░░    ░░░░░    ░░ ░░░░░ ░░░░░    ░░░░░ ░░░░░░░░░░      ░░░░░░░    ░░░░░     ░░░░░ ░░░░░   ░░░░░ 
    """
    colored_banner = colored(banner, "yellow", attrs=["bold", "underline"])
    print(colored_banner)

    # Buat log file
    log_filename = "brute_force_log.txt"
    log_file = open(log_filename, "a")

    # Tulis informasi ke log file
    log_file.write(f"URL: {url}\n")
    log_file.write(f"Username: {username}\n\n")
    log_file.write("Brute Force Log:\n")

    # Jalankan fungsi brute_force dengan URL, username, dan file wordlist yang diberikan
    start_time = time.time()
    while True:
        brute_force_results, password_found = brute_force(url, username, wordlist)
        if password_found:
            break
        else:
            print("No password found. Restarting brute force...")
            log_file.write("No password found. Restarting brute force...\n")
    end_time = time.time()

    # Tampilkan hasil dalam bentuk tabel
    table_headers = ["Username", "Password", "Status"]
    table_data = brute_force_results
    table = tabulate(table_data, headers=table_headers, tablefmt="fancy_grid")
    print(table)

    # Tampilkan nama wordlist yang digunakan
    print("\nWordlist used:")
    for file in wordlist:
        print(file)

    # Tampilkan waktu yang dibutuhkan
    execution_time = end_time - start_time
    print(f"\nExecution time: {execution_time:.2f} seconds")

    # Tulis waktu eksekusi ke log file
    log_file.write(f"\nExecution time: {execution_time:.2f} seconds\n")

    # Tutup log file
    log_file.close()

    # Tampilkan lokasi log file
    print(f"\nLog file saved: {os.path.abspath(log_filename)}")

def main():
    parser = argparse.ArgumentParser(description="Security Tools Command-line Application")
    parser.add_argument("tool", choices=["xsscan", "directory_scanner", "brute_force"], help="Select the security tool to run")
    parser.add_argument("-u", "--url", help="The URL to scan (for XSScan and Directory Scanner)")
    parser.add_argument("-w", "--wordlist", help="The wordlist file for Brute Force")

    args = parser.parse_args()

    if args.tool == "xsscan":
        if not args.url:
            print("URL is required for XSScan.")
            return
        run_xsscan(args.url)

    elif args.tool == "directory_scanner":
        if not args.url:
            print("URL is required for Directory Scanner.")
            return
        run_directory_scanner(args.url)

    elif args.tool == "brute_force":
        if not args.url or not args.wordlist:
            print("URL and wordlist are required for Brute Force.")
            return
        run_brute_force(args.url, args.wordlist)

    else:
        print("Invalid security tool selected. Please choose one of 'xsscan', 'directory_scanner', or 'brute_force'.")

if __name__ == "__main__":
    init(autoreset=True)  # Initialize colorama

    # ASCII Art Header with 7 different colors
    banner = """
        ██████   ██████ ███████████    █████ ██████   █████ ██████████      ███████    ██████   ██████ ███████████  
        ░░██████ ██████ ░█░░░███░░░█   ░░███ ░░██████ ░░███ ░░███░░░░███   ███░░░░░███ ░░██████ ██████ ░░███░░░░░███ 
         ░███░█████░███ ░   ░███  ░     ░███  ░███░███ ░███  ░███   ░░███ ███     ░░███ ░███░█████░███  ░███    ░███ 
         ░███░░███ ░███     ░███        ░███  ░███░░███░███  ░███    ░███░███      ░███ ░███░░███ ░███  ░██████████  
         ░███ ░░░  ░███     ░███        ░███  ░███ ░░██████  ░███    ░███░███      ░███ ░███ ░░░  ░███  ░███░░░░░███ 
         ░███      ░███     ░███        ░███  ░███  ░░█████  ░███    ███ ░░███     ███  ░███      ░███  ░███    ░███ 
         █████     █████    █████    ██ █████ █████  ░░█████ ██████████   ░░░███████░   █████     █████ █████   █████
        ░░░░░     ░░░░░    ░░░░░    ░░ ░░░░░ ░░░░░    ░░░░░ ░░░░░░░░░░      ░░░░░░░    ░░░░░     ░░░░░ ░░░░░   ░░░░░ 
        """
    colored_banner = colored(banner, "yellow", attrs=["bold", "underline"])
    print(colored_banner)

    # Add a dictionary to map the tool names to their corresponding functions
    tools = {
        "xsscan": run_xsscan,
        "directory_scanner": run_directory_scanner,
        "brute_force": run_brute_force,
    }

    parser = argparse.ArgumentParser(description="Security Tools Command-line Application")
    parser.add_argument("tool", choices=tools.keys(), help="Select the security tool to run")
    parser.add_argument("-u", "--url", help="The URL to scan (for XSScan and Directory Scanner)")
    parser.add_argument("-w", "--wordlist", help="The wordlist file for Brute Force")

    args = parser.parse_args()

    tool_function = tools[args.tool]
    if args.url:
        show_banner(args.tool)
        tool_function(args.url, args.wordlist)
    else:
        print("URL is required for selected security tool.")
