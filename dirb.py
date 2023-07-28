import requests
from tqdm import tqdm

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

def main():
    # Meminta pengguna memasukkan URL
    url = input("Masukkan URL: ")

    # Melakukan pemindaian direktori
    results = scan_directories(url)

    # Menampilkan hasil pemindaian
    print("\nHasil pemindaian:")
    if results:
        for result in results:
            print("[+] Found directory:", result)
    else:
        print("Tidak ditemukan direktori.")

if __name__ == "__main__":
    main()
