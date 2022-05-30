import tkinter as tk
from functools import partial
from util import encrypt 

win = tk.Tk()
win.title("AES-256 ENCRYPTION TOOL")

cipher_text = tk.StringVar()
plain_text = tk.StringVar()


pass_lbl = tk.Label(win, text="Enter password:")
pass_lbl.pack()
pass_entry = tk.Entry(win, show="*")
pass_entry.pack()

plain_lbl = tk.Label(win, text="Enter plaintext:")
plain_lbl.pack()
plain_entry = tk.Entry(win, textvariable = plain_text)
plain_entry.pack()

cipher_lbl = tk.Label(win, text="Ciphertext:")
cipher_lbl.pack()
cipher_entry = tk.Entry(win, textvariable = cipher_text)
cipher_entry.pack()

enc_btn = tk.Button(win, text="Encrypt", command=partial(encrypt.encrypt_msg, plain_text, pass_entry, cipher_entry))
enc_btn.pack()

dec_btn = tk.Button(win, text="Decrypt", command=partial(encrypt.decrypt, cipher_text, pass_entry, plain_entry))
dec_btn.pack()




win.mainloop()