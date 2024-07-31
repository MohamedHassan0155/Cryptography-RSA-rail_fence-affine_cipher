import tkinter as tk
from tkinter import font
from tkinter import messagebox

from sympy import mod_inverse

import rsa___


# import rail_fence_With_GUI


def open_RSA_window():
    public_key, private_key = rsa___.generate_keypair()

    def close_new_window(window):
        window.destroy()  # Destroy the new window
        root.deiconify()  # Show the main window again

    def call_rsa_encrypt(message):
        if en_E.get() == "":
            messagebox.showwarning("Warning", "enter plain text.")
            return
        rsa_cipher = rsa___.encrypt(public_key, message)
        # cipher_l.config(text="")
        # cipher_l.config(text="cipher text: " + str(rsa_cipher))

        en_D.delete(0, tk.END)
        en_D.insert(0, rsa_cipher)
        en_PU.delete(0, tk.END)
        en_PU.insert(0, public_key)
        en_PR.delete(0, tk.END)
        en_PR.insert(0, private_key)

    root.withdraw()
    rsa_win = tk.Toplevel()
    rsa_win.title("RSA")
    rsa_win.geometry("800x400")

    l1 = tk.Label(rsa_win, text="Enter Plain Text -> ", border=2, width=30, font=font.Font(size=15))
    l1.place(x=10, y=10)
    l2 = tk.Label(rsa_win, text="Enter cipher Text -> ", border=2, width=30, font=font.Font(size=15))
    l2.place(x=10, y=50)
    l3 = tk.Label(rsa_win, text="Enter Public key -> ", border=2, width=30, font=font.Font(size=15))
    l3.place(x=10, y=90)
    l4 = tk.Label(rsa_win, text="Enter Private Key -> ", border=2, width=30, font=font.Font(size=15))
    l4.place(x=10, y=130)

    en_E = tk.Entry(rsa_win, border=2, width=30, font=font.Font(size=12))
    en_E.place(x=300, y=15)
    en_D = tk.Entry(rsa_win, border=2, width=30, font=font.Font(size=12))
    en_D.place(x=300, y=55)
    en_PU = tk.Entry(rsa_win, border=2, width=30, font=font.Font(size=12))
    en_PU.place(x=300, y=95)
    en_PR = tk.Entry(rsa_win, border=2, width=30, font=font.Font(size=12))
    en_PR.place(x=300, y=135)

    bt1 = tk.Button(rsa_win, text="Encrypt", border=5, width=20, command=lambda: call_rsa_encrypt(en_E.get()))
    bt1.place(x=120, y=180)
    # bt2 = tk.Button(rsa_win, text="Decrypt", border=5, width=20, command=lambda: call_rsa_decrypt())
    # bt2.place(x=300, y=180)

    # cipher_l = tk.Label(rsa_win, text="This is a new window!", font=font.Font(size=15))
    # cipher_l.place(x=500, y=400)

    back = tk.Button(rsa_win, text="Back", border=5, width=20, command=lambda: close_new_window(rsa_win))
    back.place(x=300, y=180)


def open_Rail_window():
    def close_new_window(window):
        window.destroy()  # Destroy the new window
        root.deiconify()  # Show the main window again

    def encryption(key, text):
        text = text.replace(' ', '')  # remove spaces from plaintext
        cipherText = [""] * key  # empty num of rows = key
        for row in range(key):
            pointer = row
            while pointer < len(text):
                cipherText[row] += text[pointer]
                pointer += key
        return "".join(cipherText)

    def decryption(key, cipherText):
        numRows = (len(cipherText) + key - 1) // key
        numCols = key
        numBlanks = (numRows * numCols) - len(cipherText)
        plainText = [''] * numRows

        col, row = 0, 0
        for symbol in cipherText:
            plainText[row] += symbol
            row += 1
            if row == numRows or (row == numRows - 1 and col >= numCols - numBlanks):
                row = 0
                col += 1

        return ''.join(plainText)

    def encrypt_decrypt():
        try:
            input_text = input_entry.get()
            input_text = input_text.replace(' ', '')  # remove spaces
            input_key = int(key_entry.get())

            cipher_text = encryption(input_key, input_text)
            cipher_label.config(text="Encrypted Text: " + cipher_text)

            decrypted_text = decryption(input_key, cipher_text)
            decrypted_label.config(text="Decrypted Text: " + decrypted_text)
        except:
            messagebox.showwarning("Warning", "Missing value required!")

    # Creating the tkinter window
    root.withdraw()
    rail_window = tk.Toplevel()
    rail_window.title("Rail Fence")

    # Labels
    input_label = tk.Label(rail_window, text="Enter the text:")
    input_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")

    key_label = tk.Label(rail_window, text="Enter key [2 - text length]:")
    key_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")

    cipher_label = tk.Label(rail_window, text="")
    cipher_label.grid(row=3, column=0, padx=5, pady=5, sticky="w")

    decrypted_label = tk.Label(rail_window, text="")
    decrypted_label.grid(row=4, column=0, padx=5, pady=5, sticky="w")

    # Entries
    input_entry = tk.Entry(rail_window, width=50)
    input_entry.grid(row=0, column=1, padx=5, pady=5)

    key_entry = tk.Entry(rail_window, width=10)
    key_entry.grid(row=1, column=1, padx=5, pady=5)

    # Button
    encrypt_button = tk.Button(rail_window, text="Encrypt/Decrypt", command=encrypt_decrypt)
    encrypt_button.grid(row=2, column=0, columnspan=2, padx=5, pady=5)

    back = tk.Button(rail_window, text="Back", command=lambda: close_new_window(rail_window))
    back.grid(row=3, column=0, columnspan=2, padx=5, pady=5)


def rail_fence_With_GUI():

    def close_new_window(window):
        window.destroy()  # Destroy the new window
        root.deiconify()  # Show the main window again

    from sympy import mod_inverse

    alphabet = "abcdefghijklmnopqrstuvwxyz"

    def affine_encryption(plaintext, a, b):
        ciphertext = ""
        for p_ch in plaintext:
            if p_ch.isalpha():
                p_value = alphabet.index(p_ch)
                c_value = (a * p_value + b) % 26
                c_ch = alphabet[c_value]
                ciphertext += c_ch
            else:
                continue
        return ciphertext

    def decryption(ciphertext, a, b):
        plaintext = ""
        inv = mod_inverse(a, 26)  # Calculate the modular inverse of 'a' modulo 26
        for c_ch in ciphertext:
            c_value = alphabet.index(c_ch)
            p_value = (inv * (c_value - b)) % 26
            p_ch = alphabet[p_value]
            plaintext += p_ch
        return plaintext

    def encrypt_button_click():
        plaintext = plaintext_entry.get()
        a = int(a_entry.get())
        b = int(b_entry.get())
        try:
            ciphertext = affine_encryption(plaintext, a, b)
            ciphertext_label.config(text="Ciphertext: " + ciphertext)
        except ValueError:
            messagebox.showerror("Error", "Invalid input")

    def decrypt_button_click():
        ciphertext = ciphertext_entry.get()
        a = int(a_entry.get())
        b = int(b_entry.get())
        try:
            plaintext = decryption(ciphertext, a, b)
            plaintext_label.config(text="Plaintext: " + plaintext)
        except ValueError:
            messagebox.showerror("Error", "Invalid input")

    root.withdraw()
    affine_window = tk.Toplevel()
    affine_window.title("Affine Encryption and Decryption")

    # Create widgets for encryption
    plaintext_label = tk.Label(affine_window, text="Plaintext:")
    plaintext_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")

    plaintext_entry = tk.Entry(affine_window)
    plaintext_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")

    a_label = tk.Label(affine_window, text="a:")
    a_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")

    a_entry = tk.Entry(affine_window)
    a_entry.grid(row=1, column=1, padx=5, pady=5, sticky="w")

    b_label = tk.Label(affine_window, text="b:")
    b_label.grid(row=2, column=0, padx=5, pady=5, sticky="w")

    b_entry = tk.Entry(affine_window)
    b_entry.grid(row=2, column=1, padx=5, pady=5, sticky="w")

    encrypt_button = tk.Button(affine_window, text="Encrypt", command=encrypt_button_click)
    encrypt_button.grid(row=3, column=0, padx=5, pady=5, sticky="w")

    ciphertext_label = tk.Label(affine_window, text="Ciphertext:")
    ciphertext_label.grid(row=4, column=0, padx=5, pady=5, sticky="w")

    ciphertext_entry = tk.Entry(affine_window)
    ciphertext_entry.grid(row=4, column=1, padx=5, pady=5, sticky="w")

    # Create widgets for decryption
    decrypt_button = tk.Button(affine_window, text="Decrypt", command=decrypt_button_click)
    decrypt_button.grid(row=5, column=0, padx=5, pady=5, sticky="w")

    # plaintext_dec_label = tk.Label(affine_window, text="Plaintext:")
    # plaintext_dec_label.grid(row=6, column=0, padx=5, pady=5, sticky="w")

    # plaintext_dec_entry = tk.Entry(affine_window)
    # plaintext_dec_entry.grid(row=6, column=1, padx=5, pady=5, sticky="w")


root = tk.Tk()
root.title("Main Window")
root.geometry("800x600")

button1 = tk.Button(root, text="Open Window 1", command=open_RSA_window)
button1.pack()

button2 = tk.Button(root, text="Open Window 2", command=open_Rail_window)
button2.pack()

button3 = tk.Button(root, text="Open Window 3", command=open_affine_window)
button3.pack()

root.mainloop()
