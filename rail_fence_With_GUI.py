import tkinter as tk
from tkinter import messagebox



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
window = tk.Tk()
window.title("Rail Fence")

# Labels
input_label = tk.Label(window, text="Enter the text:")
input_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")

key_label = tk.Label(window, text="Enter key [2 - text length]:")
key_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")

cipher_label = tk.Label(window, text="")
cipher_label.grid(row=3, column=0, padx=5, pady=5, sticky="w")

decrypted_label = tk.Label(window, text="")
decrypted_label.grid(row=4, column=0, padx=5, pady=5, sticky="w")

# Entries
input_entry = tk.Entry(window, width=50)
input_entry.grid(row=0, column=1, padx=5, pady=5)

key_entry = tk.Entry(window, width=10)
key_entry.grid(row=1, column=1, padx=5, pady=5)

# Button
encrypt_button = tk.Button(window, text="Encrypt/Decrypt", command=encrypt_decrypt)
encrypt_button.grid(row=2, column=0, columnspan=2, padx=5, pady=5)

# Running the GUI
window.mainloop()
	