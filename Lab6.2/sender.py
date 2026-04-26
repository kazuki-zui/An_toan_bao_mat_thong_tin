import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

# --- LOGIC XỬ LÝ MẠNG VÀ MÃ HÓA ---
def start_sender(dest_ip, msg, log_func):
    """
    Hàm thực hiện gửi dữ liệu.
    log_func: Hàm callback để đẩy nội dung log lên giao diện (Text box)
    """
    key = get_random_bytes(16) 
    iv = get_random_bytes(16)
    
    k_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    d_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Thiết lập timeout
    k_sock.settimeout(5.0)
    d_sock.settimeout(5.0)

    try:
        # 1. Gửi Key/IV qua kênh khóa (Port 5001)
        log_func(f"[*] Đang kết nối kênh khóa tới {dest_ip}:5001...\n")
        k_sock.connect((dest_ip, 5001))
        k_sock.sendall(key)
        k_sock.sendall(iv)
        log_func("[+] Đã gửi Key và IV thành công.\n")

        # 2. Mã hóa dữ liệu 
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(msg.encode('utf-8'), AES.block_size))
        
        # 3. Gửi dữ liệu mã hóa kèm Header qua kênh dữ liệu (Port 5000)
        log_func(f"[*] Đang kết nối kênh dữ liệu tới {dest_ip}:5000...\n")
        d_sock.connect((dest_ip, 5000))
        
        d_sock.sendall(len(ciphertext).to_bytes(4, byteorder='big'))
        d_sock.sendall(ciphertext)
        log_func(f"[+] Đã gửi dữ liệu mã hóa thành công ({len(ciphertext)} bytes).\n")

    except socket.timeout:
        log_func("[-] Lỗi: Kết nối bị quá hạn (Timeout). Vui lòng kiểm tra Server.\n")
    except ConnectionRefusedError:
        log_func("[-] Lỗi: Server từ chối kết nối. Đảm bảo IP và Port đang lắng nghe.\n")
    except Exception as e:
        log_func(f"[-] Lỗi mạng không xác định: {e}\n")
    finally:
        k_sock.close()
        d_sock.close()
        log_func("[*] Đã đóng kết nối.\n")


# --- XÂY DỰNG GIAO DIỆN NGƯỜI DÙNG ---
class SenderApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AES-CBC Socket Sender")
        self.root.geometry("500x400")
        self.root.resizable(False, False)

        # 1. Input: IP Máy nhận
        frame_ip = tk.Frame(root)
        frame_ip.pack(pady=10, fill=tk.X, padx=20)
        tk.Label(frame_ip, text="IP Server: ", width=10, anchor="w").pack(side=tk.LEFT)
        self.entry_ip = tk.Entry(frame_ip, width=20)
        self.entry_ip.insert(0, "10.82.212.76") # Default IP
        self.entry_ip.pack(side=tk.LEFT)

        # 2. Input: Thông điệp
        frame_msg = tk.Frame(root)
        frame_msg.pack(pady=5, fill=tk.X, padx=20)
        tk.Label(frame_msg, text="Thông điệp: ", width=10, anchor="w").pack(side=tk.LEFT)
        self.entry_msg = tk.Entry(frame_msg, width=40)
        self.entry_msg.insert(0, "Day la thong diep bi mat!")
        self.entry_msg.pack(side=tk.LEFT)

        # 3. Nút Gửi
        self.btn_send = tk.Button(root, text="Mã hóa & Gửi đi", command=self.on_send, bg="#4CAF50", fg="white", font=("Arial", 10, "bold"))
        self.btn_send.pack(pady=15)

        # 4. Khu vực Log kết quả
        tk.Label(root, text="Trạng thái hệ thống:").pack(anchor="w", padx=20)
        self.log_area = scrolledtext.ScrolledText(root, width=55, height=12, state='disabled', bg="#f4f4f4")
        self.log_area.pack(pady=5, padx=20)

    def log(self, message):
        """Hàm ghi log lên màn hình giao diện"""
        self.log_area.config(state='normal')
        self.log_area.insert(tk.END, message)
        self.log_area.see(tk.END) # Tự động cuộn xuống dòng mới nhất
        self.log_area.config(state='disabled')

    def on_send(self):
        """Xử lý sự kiện khi bấm nút Gửi"""
        ip = self.entry_ip.get().strip()
        msg = self.entry_msg.get().strip()
        
        if not ip or not msg:
            messagebox.showwarning("Thiếu thông tin", "Vui lòng nhập đầy đủ IP và Thông điệp!")
            return

        # Vô hiệu hóa nút gửi trong lúc đang xử lý để tránh spam click
        self.btn_send.config(state=tk.DISABLED)
        self.log(f"\n--- Bắt đầu tiến trình gửi tới {ip} ---\n")
        
        # Tạo luồng (Thread) riêng cho mạng để giao diện không bị treo
        thread = threading.Thread(target=self.run_socket_task, args=(ip, msg))
        thread.daemon = True
        thread.start()

    def run_socket_task(self, ip, msg):
        """Chạy logic mạng, sau khi xong thì bật lại nút Gửi"""
        start_sender(ip, msg, self.log)
        
        # Cập nhật lại UI sau khi thread chạy xong (phải dùng root.after để đảm bảo an toàn)
        self.root.after(0, lambda: self.btn_send.config(state=tk.NORMAL))

if __name__ == "__main__":
    # Khởi tạo form
    root = tk.Tk()
    app = SenderApp(root)
    root.mainloop()