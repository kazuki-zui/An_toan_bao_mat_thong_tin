import tkinter as tk
from tkinter import messagebox
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import os
import binascii

def generate_hex(byte_len=8):
    """Sinh chuỗi Hex ngẫu nhiên"""
    return binascii.hexlify(os.urandom(byte_len)).decode('utf-8')

def encrypt_action():
    plaintext = text_plain.get("1.0", "end-1c").strip()
    if not plaintext:
        messagebox.showwarning("Lỗi", "Vui lòng nhập bản tin cần mã hóa!")
        return

    try:
        # Sinh Key và IV ngẫu nhiên (8 bytes = 64 bit cho DES)
        key_bytes = os.urandom(8)
        iv_bytes = os.urandom(8)

        # Mã hóa DES-CBC với PKCS7 Padding
        cipher = DES.new(key_bytes, DES.MODE_CBC, iv_bytes)
        padded_data = pad(plaintext.encode('utf-8'), DES.block_size)
        ciphertext_bytes = cipher.encrypt(padded_data)

        # Cập nhật lên giao diện (dạng Hex)
        entry_enc_key.delete(0, tk.END)
        entry_enc_key.insert(0, binascii.hexlify(key_bytes).decode('utf-8'))

        entry_enc_iv.delete(0, tk.END)
        entry_enc_iv.insert(0, binascii.hexlify(iv_bytes).decode('utf-8'))

        text_enc_cipher.delete("1.0", tk.END)
        text_enc_cipher.insert("1.0", binascii.hexlify(ciphertext_bytes).decode('utf-8'))

    except Exception as e:
        messagebox.showerror("Lỗi Mã Hóa", str(e))

def copy_to_receiver():
    """Chuyển dữ liệu từ ô Sender sang ô Receiver để test"""
    entry_dec_key.delete(0, tk.END)
    entry_dec_key.insert(0, entry_enc_key.get())
    
    entry_dec_iv.delete(0, tk.END)
    entry_dec_iv.insert(0, entry_enc_iv.get())
    
    text_dec_cipher.delete("1.0", tk.END)
    text_dec_cipher.insert("1.0", text_enc_cipher.get("1.0", "end-1c"))

def decrypt_action():
    key_hex = entry_dec_key.get().strip()
    iv_hex = entry_dec_iv.get().strip()
    cipher_hex = text_dec_cipher.get("1.0", "end-1c").strip()

    if not key_hex or not iv_hex or not cipher_hex:
        messagebox.showwarning("Lỗi", "Vui lòng nhập đủ Key, IV và Ciphertext (dạng Hex)!")
        return

    try:
        # Chuyển từ Hex string sang bytes
        key_bytes = binascii.unhexlify(key_hex)
        iv_bytes = binascii.unhexlify(iv_hex)
        cipher_bytes = binascii.unhexlify(cipher_hex)

        # Giải mã và gỡ padding
        cipher = DES.new(key_bytes, DES.MODE_CBC, iv_bytes)
        decrypted_padded = cipher.decrypt(cipher_bytes)
        plaintext_bytes = unpad(decrypted_padded, DES.block_size)

        # Cập nhật kết quả
        text_dec_result.delete("1.0", tk.END)
        text_dec_result.insert("1.0", plaintext_bytes.decode('utf-8'))

    except ValueError as ve:
        messagebox.showerror("Lỗi Giải Mã", "Khóa, IV, dữ liệu bị sai hoặc Padding không hợp lệ!\nChi tiết: " + str(ve))
    except Exception as e:
        messagebox.showerror("Lỗi", "Có lỗi xảy ra: " + str(e))

# ================= GIAO DIỆN TKINTER =================
root = tk.Tk()
root.title("Công cụ Mã hóa/Giải mã DES-CBC (Python Tkinter)")
root.geometry("800x550")
root.configure(padx=10, pady=10)

# Khung Sender
frame_sender = tk.LabelFrame(root, text="Phía Sender (Mã hóa)", padx=10, pady=10)
frame_sender.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)

tk.Label(frame_sender, text="Nhập bản tin (Plaintext):").pack(anchor="w")
text_plain = tk.Text(frame_sender, height=4, width=40)
text_plain.pack(fill=tk.X, pady=2)

tk.Button(frame_sender, text="Mã hóa (Sinh ngẫu nhiên Key/IV)", command=encrypt_action, bg="#007BFF", fg="white").pack(fill=tk.X, pady=10)

tk.Label(frame_sender, text="Key (Hex):").pack(anchor="w")
entry_enc_key = tk.Entry(frame_sender, font=("Consolas", 10))
entry_enc_key.pack(fill=tk.X, pady=2)

tk.Label(frame_sender, text="IV (Hex):").pack(anchor="w")
entry_enc_iv = tk.Entry(frame_sender, font=("Consolas", 10))
entry_enc_iv.pack(fill=tk.X, pady=2)

tk.Label(frame_sender, text="Ciphertext (Hex):").pack(anchor="w")
text_enc_cipher = tk.Text(frame_sender, height=4, font=("Consolas", 10))
text_enc_cipher.pack(fill=tk.X, pady=2)

tk.Button(frame_sender, text="Chuyển dữ liệu sang Receiver ->", command=copy_to_receiver, bg="#28a745", fg="white").pack(fill=tk.X, pady=10)


# Khung Receiver
frame_receiver = tk.LabelFrame(root, text="Phía Receiver (Giải mã)", padx=10, pady=10)
frame_receiver.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5)

tk.Label(frame_receiver, text="Key (Hex):").pack(anchor="w")
entry_dec_key = tk.Entry(frame_receiver, font=("Consolas", 10))
entry_dec_key.pack(fill=tk.X, pady=2)

tk.Label(frame_receiver, text="IV (Hex):").pack(anchor="w")
entry_dec_iv = tk.Entry(frame_receiver, font=("Consolas", 10))
entry_dec_iv.pack(fill=tk.X, pady=2)

tk.Label(frame_receiver, text="Ciphertext (Hex):").pack(anchor="w")
text_dec_cipher = tk.Text(frame_receiver, height=4, font=("Consolas", 10))
text_dec_cipher.pack(fill=tk.X, pady=2)

tk.Button(frame_receiver, text="Giải mã", command=decrypt_action, bg="#dc3545", fg="white").pack(fill=tk.X, pady=10)

tk.Label(frame_receiver, text="Bản tin gốc (Kết quả):").pack(anchor="w")
text_dec_result = tk.Text(frame_receiver, height=4, bg="#e9ecef", font=("Arial", 10, "bold"))
text_dec_result.pack(fill=tk.X, pady=2)

root.mainloop()