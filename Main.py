import tkinter as tk
from tkinter import filedialog, messagebox
import time
import itertools
import string


def brute_force_crack(password):
    characters = string.ascii_letters + string.digits + string.punctuation 
    for length in range(1, 9):  
        for attempt in itertools.product(characters, repeat=length):
            attempt = ''.join(attempt)
            if attempt == password:
                save_to_wordlist(attempt)
                return attempt
    return None

def wordlist_crack(password, filepath):
    try:
        with open(filepath, 'r') as file:
            for line in file:
                attempt = line.strip()  
                if attempt == password:
                    return attempt
    except FileNotFoundError:
        messagebox.showerror("Hata", "Wordlist dosyası bulunamadı!")
    return None

def start_cracking():
    password = password_entry.get()
    if not password:
        messagebox.showwarning("Uyarı", "Lütfen bir şifre girin!")
        return

    method = method_var.get()
    start_time = time.time()
    
    if method == "Brute Force":
        cracked_password = brute_force_crack(password)
    elif method == "Wordlist":
        wordlist_path = filedialog.askopenfilename(title="Wordlist Dosyasını Seç", filetypes=[("Text Files", "*.txt")])
        if not wordlist_path:
            return
        cracked_password = wordlist_crack(password, wordlist_path)
    else:
        messagebox.showerror("Hata", "Geçersiz yöntem seçimi!")
        return

    end_time = time.time()

    if cracked_password:
        result_label.config(text=f"Şifre: {cracked_password} (Süre: {end_time - start_time:.2f} saniye)")
        save_result(password, cracked_password, end_time - start_time)
    else:
        result_label.config(text="Şifre kırma başarısız oldu.")

def save_result(password, cracked_password, duration):
    with open("crack_report.txt", "a") as file:
        file.write(f"Girilen Şifre: {password}\n")
        file.write(f"Kırılan Şifre: {cracked_password}\n")
        file.write(f"Süre: {duration:.2f} saniye\n")
        file.write("-" * 30 + "\n")

def save_to_wordlist(password):
    with open("bruteForce.txt", "a") as file:
        file.write(password + "\n")

def show_info():
    info_text = (
        "Bu uygulama brute force ve wordlist yöntemlerini kullanarak şifre kırar.\n"
        "- Brute Force: Tüm olasılıkları dener.\n"
        "- Wordlist:Kullanıcın seçtiği bir listeden belirli bir kelime listesini kullanır.\n"
        "\nLütfen uygun bir yöntem seçin ve devam edin."
    )
    messagebox.showinfo("Bilgi", info_text)


root = tk.Tk()
root.title("Şifre Kırma Uygulaması")
root.geometry("500x400")


tk.Button(root, text="Bilgi", font=("Arial", 10), command=show_info).pack(pady=5)


tk.Label(root, text="Şifreyi Girin:", font=("Arial", 12)).pack(pady=10)
password_entry = tk.Entry(root, font=("Arial", 12), show="*", width=30)
password_entry.pack(pady=5)


tk.Label(root, text="Kırma Yöntemini Seçin:", font=("Arial", 12)).pack(pady=10)
method_var = tk.StringVar(value="Brute Force")
methods_frame = tk.Frame(root)
methods_frame.pack()
tk.Radiobutton(methods_frame, text="Brute Force", variable=method_var, value="Brute Force", font=("Arial", 10)).pack(side=tk.LEFT, padx=10)
tk.Radiobutton(methods_frame, text="Wordlist", variable=method_var, value="Wordlist", font=("Arial", 10)).pack(side=tk.LEFT, padx=10)

crack_button = tk.Button(root, text="Şifreyi Kır", font=("Arial", 12), command=start_cracking)
crack_button.pack(pady=20)


result_label = tk.Label(root, text="", font=("Arial", 12))
result_label.pack(pady=10)


root.mainloop()
