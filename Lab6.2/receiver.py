import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

class ReceiverApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AES-CBC Socket Receiver")
        self.root.geometry("500x450")
        self.root.resizable(False, False)

        # 1. Trạng thái kết nối
        self.status_label = tk.Label(root, text="Trạng thái: Đang chờ kết nối...", fg="blue", font=("Arial", 10, "italic"))
        self.status_label.pack(pady=10)

        # 2. Khu vực hiển thị tin nhắn đã giải mã
        tk.Label(root, text="Tin nhắn nhận được:", font=("Arial", 10, "bold")).pack(anchor="w", padx=20)
        self.msg_area = scrolledtext.ScrolledText(root, width=55, height=10, bg="#e8f5e9")
        self.msg_area.pack(pady=5, padx=20)
        self.msg_area.config(state='disabled')

        # 3. Khu vực Log hệ thống
        tk.Label(root, text="Log hệ thống:").pack(anchor="w", padx=20)
        self.log_area = scrolledtext.ScrolledText(root, width=55, height=8, state='disabled', bg="#f4f4f4", font=("Consolas", 9))
        self.log_area.pack(pady=5, padx=20)

        # Khởi chạy luồng nhận dữ liệu ngầm
        self.server_thread = threading.Thread(target=self.start_socket_server, daemon=True)
        self.server_thread.start()

    def log(self, message):
        """Ghi log hệ thống"""
        self.log_area.config(state='normal')
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.see(tk.END)
        self.log_area.config(state='disabled')

    def display_message(self, text):
        """Hiển thị tin nhắn đã giải mã lên khung chính"""
        self.msg_area.config(state='normal')
        self.msg_area.insert(tk.END, f"📩: {text}\n")
        self.msg_area.see(tk.END)
        self.msg_area.config(state='disabled')

    def recvall(self, sock, n):
        """Hàm hỗ trợ đọc CHÍNH XÁC n bytes từ socket"""
        data = bytearray()
        while len(data) < n:
            packet = sock.recv(n - len(data))
            if not packet:
                return None # Trả về None nếu mất kết nối giữa chừng
            data.extend(packet)
        return bytes(data)

    def start_socket_server(self):
        while True:
            try:
                # BƯỚC 1: Nhận Key/IV (Cổng 5001)
                key_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                key_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                key_socket.bind(('0.0.0.0', 5001))
                key_socket.listen(1)
                
                k_conn, addr = key_socket.accept()
                self.log(f"[*] Kết nối từ {addr[0]} tới kênh khóa...")
                
                # SỬA LỖI Ở ĐÂY: Dùng recvall để đảm bảo nhận đủ 32 bytes
                raw_key_iv = self.recvall(k_conn, 32)
                
                if raw_key_iv and len(raw_key_iv) == 32:
                    key = raw_key_iv[:16]
                    iv = raw_key_iv[16:]
                else:
                    self.log("[-] Lỗi: Không nhận đủ dữ liệu Key/IV.")
                    k_conn.close()
                    key_socket.close()
                    continue

                k_conn.close()
                key_socket.close()

                # BƯỚC 2: Nhận Dữ liệu mã hóa (Cổng 5000)
                data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                data_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                data_socket.bind(('0.0.0.0', 5000))
                data_socket.listen(1)
                
                d_conn, _ = data_socket.accept()
                
                # Dùng recvall để nhận chuẩn 4 bytes header
                header = self.recvall(d_conn, 4)
                
                if header:
                    msg_len = int.from_bytes(header, byteorder='big')
                    
                    # Dùng recvall để nhận CHUẨN ĐỦ số bytes của văn bản mã hóa
                    ciphertext = self.recvall(d_conn, msg_len)
                    
                    if ciphertext:
                        # BƯỚC 3: Giải mã AES-CBC
                        cipher = AES.new(key, AES.MODE_CBC, iv)
                        decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
                        final_text = decrypted.decode('utf-8')
                        
                        # Hiển thị kết quả
                        self.display_message(final_text)
                        self.log(f"[+] Giải mã thành công tin nhắn từ {addr[0]}")
                    else:
                        self.log("[-] Lỗi: Không nhận đủ dữ liệu Ciphertext.")
                
                d_conn.close()
                data_socket.close()

            except Exception as e:
                self.log(f"[-] Lỗi: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = ReceiverApp(root)
    root.mainloop()