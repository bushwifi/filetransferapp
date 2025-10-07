import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import socket
import threading
import json
import os
import zipfile
import struct
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import time

class ModernButton(tk.Button):
    def __init__(self, parent, text, command, bg="#2563eb", fg="white", hover_bg="#1d4ed8", width=15, **kwargs):
        super().__init__(parent, text=text, command=command, bg=bg, fg=fg, 
                        activebackground=hover_bg, activeforeground=fg,
                        font=("Segoe UI", 10, "bold"), relief="flat", 
                        borderwidth=0, cursor="hand2", width=width,
                        height=1, padx=10, pady=8, **kwargs)
        
        self.default_bg = bg
        self.hover_bg = hover_bg
        
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)
        
    def on_enter(self, e):
        self.config(bg=self.hover_bg)
        
    def on_leave(self, e):
        self.config(bg=self.default_bg)

class FileShareApp:
    def __init__(self, root):
        self.root = root
        self.root.title("FileShare Pro")
        self.root.geometry("950x700")
        self.root.configure(bg="#0f172a")
        self.root.minsize(800, 600)
        
        # Network settings
        self.broadcast_port = 5555
        self.transfer_port = 5556
        self.pc_name = socket.gethostname()
        self.local_ip = self.get_local_ip()
        
        # Connection state
        self.discovered_peers = {}
        self.connected_peer = None
        self.encryption_key = None
        self.cipher = None
        
        # Transfer settings
        self.chunk_size = 65536  # 64KB chunks for high speed
        self.max_file_size = 200 * 1024 * 1024 * 1024  # 200GB
        
        # Transfer stats
        self.transfer_start_time = 0
        self.bytes_transferred = 0
        self.last_update_time = 0
        self.speed_samples = []
        
        # Threads
        self.broadcast_thread = None
        self.discovery_thread = None
        self.server_thread = None
        self.running = False
        
        self.setup_styles()
        self.setup_ui()
        self.start_services()
        
    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        bg_dark = "#0f172a"
        bg_card = "#1e293b"
        bg_input = "#334155"
        text_color = "#e2e8f0"
        accent = "#3b82f6"
        
        style.configure("Dark.TFrame", background=bg_dark)
        style.configure("Card.TFrame", background=bg_card, relief="flat")
        style.configure("Dark.TLabel", background=bg_dark, foreground=text_color, font=("Segoe UI", 10))
        style.configure("Card.TLabel", background=bg_card, foreground=text_color, font=("Segoe UI", 10))
        style.configure("Title.TLabel", background=bg_dark, foreground="white", font=("Segoe UI", 16, "bold"))
        style.configure("Header.TLabel", background=bg_card, foreground="white", font=("Segoe UI", 12, "bold"))
        style.configure("Status.TLabel", background=bg_card, foreground="#22c55e", font=("Segoe UI", 10, "bold"))
        
        style.configure("Dark.TNotebook", background=bg_dark, borderwidth=0)
        style.configure("Dark.TNotebook.Tab", background=bg_card, foreground=text_color, 
                       padding=[20, 10], font=("Segoe UI", 10, "bold"))
        style.map("Dark.TNotebook.Tab", background=[("selected", accent)], 
                 foreground=[("selected", "white")])
        
        style.configure("Modern.Horizontal.TProgressbar", background=accent, 
                       troughcolor=bg_input, borderwidth=0, thickness=8)
        
    def setup_ui(self):
        # Header
        header = ttk.Frame(self.root, style="Dark.TFrame")
        header.pack(fill=tk.X, padx=20, pady=(15, 10))
        
        ttk.Label(header, text="📁 FileShare Pro", style="Title.TLabel").pack(side=tk.LEFT)
        
        # Status indicator
        status_container = ttk.Frame(header, style="Dark.TFrame")
        status_container.pack(side=tk.RIGHT)
        
        self.status_dot = tk.Canvas(status_container, width=12, height=12, bg="#0f172a", highlightthickness=0)
        self.status_dot.pack(side=tk.LEFT, padx=(0, 8))
        self.status_dot.create_oval(2, 2, 10, 10, fill="#ef4444", outline="")
        
        self.connection_status = ttk.Label(status_container, text="Disconnected", style="Dark.TLabel")
        self.connection_status.pack(side=tk.LEFT)
        
        # Main notebook
        notebook = ttk.Notebook(self.root, style="Dark.TNotebook")
        notebook.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 15))
        
        # Network tab
        self.create_network_tab(notebook)
        
        # File transfer tab
        self.create_transfer_tab(notebook)
        
        # Chat tab
        self.create_chat_tab(notebook)
        
        self.selected_path = None
        
    def create_network_tab(self, notebook):
        network_frame = ttk.Frame(notebook, style="Dark.TFrame")
        notebook.add(network_frame, text="🌐 Network")
        
        # Info card
        info_card = ttk.Frame(network_frame, style="Card.TFrame")
        info_card.pack(fill=tk.X, padx=10, pady=(10, 8))
        
        info_inner = ttk.Frame(info_card, style="Card.TFrame")
        info_inner.pack(fill=tk.X, padx=20, pady=12)
        
        ttk.Label(info_inner, text="Your Device", style="Header.TLabel").pack(anchor=tk.W, pady=(0, 8))
        
        info_grid = ttk.Frame(info_inner, style="Card.TFrame")
        info_grid.pack(fill=tk.X)
        
        ttk.Label(info_grid, text=f"💻 {self.pc_name}", style="Card.TLabel").grid(row=0, column=0, sticky=tk.W, pady=3)
        ttk.Label(info_grid, text=f"🌍 {self.local_ip}", style="Card.TLabel").grid(row=1, column=0, sticky=tk.W, pady=3)
        ttk.Label(info_grid, text=f"⚡ Max File Size: 200 GB", style="Card.TLabel").grid(row=2, column=0, sticky=tk.W, pady=3)
        
        # Peers card
        peers_card = ttk.Frame(network_frame, style="Card.TFrame")
        peers_card.pack(fill=tk.BOTH, expand=True, padx=10, pady=(8, 10))
        
        peers_inner = ttk.Frame(peers_card, style="Card.TFrame")
        peers_inner.pack(fill=tk.BOTH, expand=True, padx=20, pady=12)
        
        ttk.Label(peers_inner, text="Available Devices", style="Header.TLabel").pack(anchor=tk.W, pady=(0, 8))
        
        # Listbox with custom style
        list_container = tk.Frame(peers_inner, bg="#334155", relief="flat")
        list_container.pack(fill=tk.BOTH, expand=True, pady=(0, 12))
        
        scrollbar = tk.Scrollbar(list_container, bg="#475569", troughcolor="#334155", 
                                activebackground="#64748b", width=12)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, padx=2, pady=2)
        
        self.peers_listbox = tk.Listbox(list_container, yscrollcommand=scrollbar.set,
                                        bg="#334155", fg="#e2e8f0", selectbackground="#3b82f6",
                                        selectforeground="white", font=("Segoe UI", 10),
                                        borderwidth=0, highlightthickness=0, relief="flat")
        self.peers_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=2, pady=2)
        scrollbar.config(command=self.peers_listbox.yview)
        
        # Buttons
        btn_frame = ttk.Frame(peers_inner, style="Card.TFrame")
        btn_frame.pack(fill=tk.X)
        
        self.refresh_btn = ModernButton(btn_frame, "🔄 Refresh", self.refresh_peers, 
                                        bg="#8b5cf6", hover_bg="#7c3aed", width=12)
        self.refresh_btn.pack(side=tk.LEFT, padx=(0, 8))
        
        self.connect_btn = ModernButton(btn_frame, "🔗 Connect", self.connect_to_peer,
                                       bg="#10b981", hover_bg="#059669", width=12)
        self.connect_btn.pack(side=tk.LEFT, padx=(0, 8))
        
        self.disconnect_btn = ModernButton(btn_frame, "❌ Disconnect", self.disconnect,
                                          bg="#ef4444", hover_bg="#dc2626", width=13)
        self.disconnect_btn.pack(side=tk.LEFT)
        
    def create_transfer_tab(self, notebook):
        transfer_frame = ttk.Frame(notebook, style="Dark.TFrame")
        notebook.add(transfer_frame, text="📤 Transfer")
        
        # Send card
        send_card = ttk.Frame(transfer_frame, style="Card.TFrame")
        send_card.pack(fill=tk.X, padx=10, pady=(10, 8))
        
        send_inner = ttk.Frame(send_card, style="Card.TFrame")
        send_inner.pack(fill=tk.X, padx=20, pady=12)
        
        ttk.Label(send_inner, text="Send Files", style="Header.TLabel").pack(anchor=tk.W, pady=(0, 8))
        
        btn_row = ttk.Frame(send_inner, style="Card.TFrame")
        btn_row.pack(fill=tk.X, pady=(0, 8))
        
        self.file_btn = ModernButton(btn_row, "📄 Select File", self.select_file, width=13)
        self.file_btn.pack(side=tk.LEFT, padx=(0, 8))
        
        self.folder_btn = ModernButton(btn_row, "📁 Select Folder", self.select_folder, width=15)
        self.folder_btn.pack(side=tk.LEFT, padx=(0, 8))
        
        self.send_btn = ModernButton(btn_row, "🚀 Send", self.send_selected,
                                     bg="#10b981", hover_bg="#059669", width=8)
        self.send_btn.pack(side=tk.LEFT)
        
        self.selected_label = ttk.Label(send_inner, text="No file selected", 
                                       style="Card.TLabel", font=("Segoe UI", 9, "italic"))
        self.selected_label.pack(anchor=tk.W)
        
        # Progress card
        progress_card = ttk.Frame(transfer_frame, style="Card.TFrame")
        progress_card.pack(fill=tk.X, padx=10, pady=(8, 8))
        
        progress_inner = ttk.Frame(progress_card, style="Card.TFrame")
        progress_inner.pack(fill=tk.X, padx=20, pady=12)
        
        ttk.Label(progress_inner, text="Transfer Progress", style="Header.TLabel").pack(anchor=tk.W, pady=(0, 8))
        
        self.progress_bar = ttk.Progressbar(progress_inner, mode='determinate', 
                                           style="Modern.Horizontal.TProgressbar")
        self.progress_bar.pack(fill=tk.X, pady=(0, 8))
        
        # Progress stats container
        stats_frame = ttk.Frame(progress_inner, style="Card.TFrame")
        stats_frame.pack(fill=tk.X)
        
        # Left side stats
        left_stats = ttk.Frame(stats_frame, style="Card.TFrame")
        left_stats.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.progress_label = ttk.Label(left_stats, text="Idle", style="Card.TLabel")
        self.progress_label.pack(anchor=tk.W)
        
        self.speed_label = ttk.Label(left_stats, text="Speed: -- MB/s", 
                                     style="Card.TLabel", font=("Segoe UI", 9))
        self.speed_label.pack(anchor=tk.W, pady=(3, 0))
        
        # Right side stats
        right_stats = ttk.Frame(stats_frame, style="Card.TFrame")
        right_stats.pack(side=tk.RIGHT)
        
        self.time_label = ttk.Label(right_stats, text="Time remaining: --", 
                                    style="Card.TLabel", font=("Segoe UI", 9))
        self.time_label.pack(anchor=tk.E)
        
        self.percent_label = ttk.Label(right_stats, text="0%", 
                                       style="Card.TLabel", font=("Segoe UI", 11, "bold"))
        self.percent_label.pack(anchor=tk.E, pady=(3, 0))
        
        # Received card
        received_card = ttk.Frame(transfer_frame, style="Card.TFrame")
        received_card.pack(fill=tk.BOTH, expand=True, padx=10, pady=(8, 10))
        
        received_inner = ttk.Frame(received_card, style="Card.TFrame")
        received_inner.pack(fill=tk.BOTH, expand=True, padx=20, pady=12)
        
        ttk.Label(received_inner, text="Received Files", style="Header.TLabel").pack(anchor=tk.W, pady=(0, 8))
        
        text_container = tk.Frame(received_inner, bg="#334155", relief="flat")
        text_container.pack(fill=tk.BOTH, expand=True)
        
        self.received_text = scrolledtext.ScrolledText(text_container, height=5, state=tk.DISABLED,
                                                      bg="#334155", fg="#e2e8f0", 
                                                      font=("Consolas", 9), borderwidth=0,
                                                      highlightthickness=0, relief="flat",
                                                      wrap=tk.WORD)
        self.received_text.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        
    def create_chat_tab(self, notebook):
        chat_frame = ttk.Frame(notebook, style="Dark.TFrame")
        notebook.add(chat_frame, text="💬 Chat")
        
        # Chat card
        chat_card = ttk.Frame(chat_frame, style="Card.TFrame")
        chat_card.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        chat_inner = ttk.Frame(chat_card, style="Card.TFrame")
        chat_inner.pack(fill=tk.BOTH, expand=True, padx=20, pady=15)
        
        ttk.Label(chat_inner, text="Messages", style="Header.TLabel").pack(anchor=tk.W, pady=(0, 10))
        
        # Chat display
        chat_container = tk.Frame(chat_inner, bg="#334155", relief="flat", bd=0)
        chat_container.pack(fill=tk.BOTH, expand=True, pady=(0, 12))
        
        self.chat_display = scrolledtext.ScrolledText(chat_container, state=tk.DISABLED,
                                                     bg="#334155", fg="#e2e8f0",
                                                     font=("Segoe UI", 10), borderwidth=0,
                                                     highlightthickness=0, relief="flat",
                                                     wrap=tk.WORD, padx=8, pady=8)
        self.chat_display.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        
        # Chat input container
        input_frame = ttk.Frame(chat_inner, style="Card.TFrame")
        input_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        # Entry field
        entry_container = tk.Frame(input_frame, bg="#334155", relief="flat", bd=0)
        entry_container.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        self.chat_entry = tk.Entry(entry_container, bg="#334155", fg="#e2e8f0",
                                   font=("Segoe UI", 10), borderwidth=0,
                                   insertbackground="#3b82f6", relief="flat")
        self.chat_entry.pack(fill=tk.BOTH, expand=True, padx=12, pady=10)
        self.chat_entry.bind("<Return>", lambda e: self.send_message())
        
        # Send button
        self.send_msg_btn = ModernButton(input_frame, "📤 Send", self.send_message,
                                        bg="#10b981", hover_bg="#059669", width=10)
        self.send_msg_btn.pack(side=tk.RIGHT)
        
    def format_size(self, bytes_size):
        """Convert bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_size < 1024.0:
                return f"{bytes_size:.2f} {unit}"
            bytes_size /= 1024.0
        return f"{bytes_size:.2f} PB"
    
    def format_time(self, seconds):
        """Convert seconds to human readable format"""
        if seconds < 60:
            return f"{int(seconds)}s"
        elif seconds < 3600:
            minutes = int(seconds / 60)
            secs = int(seconds % 60)
            return f"{minutes}m {secs}s"
        else:
            hours = int(seconds / 3600)
            minutes = int((seconds % 3600) / 60)
            return f"{hours}h {minutes}m"
    
    def calculate_speed(self):
        """Calculate current transfer speed"""
        current_time = time.time()
        if self.last_update_time > 0:
            time_diff = current_time - self.last_update_time
            if time_diff > 0:
                speed = (self.bytes_transferred / time_diff) / (1024 * 1024)  # MB/s
                self.speed_samples.append(speed)
                # Keep last 10 samples for smoothing
                if len(self.speed_samples) > 10:
                    self.speed_samples.pop(0)
                return sum(self.speed_samples) / len(self.speed_samples)
        return 0
    
    def start_services(self):
        self.running = True
        
        # Start broadcasting
        self.broadcast_thread = threading.Thread(target=self.broadcast_presence, daemon=True)
        self.broadcast_thread.start()
        
        # Start discovery
        self.discovery_thread = threading.Thread(target=self.discover_peers, daemon=True)
        self.discovery_thread.start()
        
        # Start server
        self.server_thread = threading.Thread(target=self.run_server, daemon=True)
        self.server_thread.start()
        
    def broadcast_presence(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        
        message = json.dumps({
            'name': self.pc_name,
            'ip': self.local_ip
        }).encode()
        
        while self.running:
            try:
                sock.sendto(message, ('<broadcast>', self.broadcast_port))
                time.sleep(2)
            except:
                pass
                
        sock.close()
        
    def discover_peers(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', self.broadcast_port))
        sock.settimeout(1)
        
        while self.running:
            try:
                data, addr = sock.recvfrom(1024)
                info = json.loads(data.decode())
                
                if info['ip'] != self.local_ip:
                    peer_id = f"💻 {info['name']} - {info['ip']}"
                    if peer_id not in self.discovered_peers:
                        self.discovered_peers[peer_id] = info
                        self.update_peers_list()
            except socket.timeout:
                continue
            except:
                pass
                
        sock.close()
        
    def update_peers_list(self):
        self.peers_listbox.delete(0, tk.END)
        for peer in self.discovered_peers.keys():
            self.peers_listbox.insert(tk.END, peer)
    
    def refresh_peers(self):
        """Clear and rescan for peers"""
        self.discovered_peers.clear()
        self.update_peers_list()
        self.progress_label.config(text="🔍 Scanning for peers...")
        self.root.after(2000, lambda: self.progress_label.config(text="Idle"))
            
    def run_server(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Increase socket buffer for better performance
        server.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
        server.bind(('0.0.0.0', self.transfer_port))
        server.listen(5)
        server.settimeout(1)
        
        while self.running:
            try:
                client, addr = server.accept()
                # Set socket options for high-speed transfer
                client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
                threading.Thread(target=self.handle_connection, args=(client, addr), daemon=True).start()
            except socket.timeout:
                continue
            except:
                pass
                
        server.close()
        
    def handle_connection(self, client, addr):
        try:
            data = client.recv(1024).decode()
            request = json.loads(data)
            
            if request['type'] == 'connect_request':
                result = messagebox.askyesno("Connection Request", 
                    f"{request['name']} ({request['ip']}) wants to connect. Accept?")
                
                if result:
                    password = f"{self.pc_name}{request['name']}".encode()
                    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b'static_salt', iterations=100000)
                    key = base64.urlsafe_b64encode(kdf.derive(password))
                    self.encryption_key = key
                    self.cipher = Fernet(key)
                    
                    response = {'status': 'accepted'}
                    client.send(json.dumps(response).encode())
                    
                    self.connected_peer = {'socket': client, 'name': request['name'], 'ip': request['ip']}
                    self.update_connection_status(True, request['name'])
                    
                    threading.Thread(target=self.receive_data, args=(client,), daemon=True).start()
                else:
                    response = {'status': 'rejected'}
                    client.send(json.dumps(response).encode())
                    client.close()
        except Exception as e:
            print(f"Error handling connection: {e}")
            client.close()
            
    def connect_to_peer(self):
        selection = self.peers_listbox.curselection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a computer to connect to")
            return
            
        peer_id = self.peers_listbox.get(selection[0])
        peer_info = self.discovered_peers[peer_id]
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Set socket options for high-speed transfer
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024 * 1024)
            sock.connect((peer_info['ip'], self.transfer_port))
            
            request = {
                'type': 'connect_request',
                'name': self.pc_name,
                'ip': self.local_ip
            }
            sock.send(json.dumps(request).encode())
            
            response = json.loads(sock.recv(1024).decode())
            
            if response['status'] == 'accepted':
                password = f"{peer_info['name']}{self.pc_name}".encode()
                kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b'static_salt', iterations=100000)
                key = base64.urlsafe_b64encode(kdf.derive(password))
                self.encryption_key = key
                self.cipher = Fernet(key)
                
                self.connected_peer = {'socket': sock, 'name': peer_info['name'], 'ip': peer_info['ip']}
                self.update_connection_status(True, peer_info['name'])
                
                threading.Thread(target=self.receive_data, args=(sock,), daemon=True).start()
            else:
                messagebox.showinfo("Connection Rejected", "The other user rejected the connection")
                sock.close()
        except Exception as e:
            messagebox.showerror("Connection Error", f"Failed to connect: {e}")
            
    def disconnect(self):
        if self.connected_peer:
            try:
                self.connected_peer['socket'].close()
            except:
                pass
            self.connected_peer = None
            self.encryption_key = None
            self.cipher = None
            self.update_connection_status(False)
            
    def update_connection_status(self, connected, peer_name=None):
        if connected:
            self.status_dot.delete("all")
            self.status_dot.create_oval(2, 2, 10, 10, fill="#22c55e", outline="")
            self.connection_status.config(text=f"Connected to {peer_name}")
        else:
            self.status_dot.delete("all")
            self.status_dot.create_oval(2, 2, 10, 10, fill="#ef4444", outline="")
            self.connection_status.config(text="Disconnected")
            
    def select_file(self):
        path = filedialog.askopenfilename()
        if path:
            file_size = os.path.getsize(path)
            if file_size > self.max_file_size:
                messagebox.showerror("File Too Large", 
                    f"File size ({self.format_size(file_size)}) exceeds maximum limit of 200 GB")
                return
            
            self.selected_path = path
            self.selected_label.config(text=f"📄 {os.path.basename(path)} ({self.format_size(file_size)})")
            
    def select_folder(self):
        path = filedialog.askdirectory()
        if path:
            # Calculate folder size
            total_size = 0
            for dirpath, dirnames, filenames in os.walk(path):
                for filename in filenames:
                    filepath = os.path.join(dirpath, filename)
                    total_size += os.path.getsize(filepath)
            
            if total_size > self.max_file_size:
                messagebox.showerror("Folder Too Large", 
                    f"Folder size ({self.format_size(total_size)}) exceeds maximum limit of 200 GB")
                return
                
            self.selected_path = path
            self.selected_label.config(text=f"📁 {os.path.basename(path)} ({self.format_size(total_size)}, folder)")
            
    def send_selected(self):
        if not self.connected_peer:
            messagebox.showwarning("Not Connected", "Please connect to a peer first")
            return
            
        if not self.selected_path:
            messagebox.showwarning("No Selection", "Please select a file or folder first")
            return
            
        threading.Thread(target=self.send_file, daemon=True).start()
        
    def send_file(self):
        try:
            path = self.selected_path
            is_folder = os.path.isdir(path)
            
            # Reset transfer stats
            self.transfer_start_time = time.time()
            self.bytes_transferred = 0
            self.last_update_time = time.time()
            self.speed_samples = []
            
            if is_folder:
                self.progress_label.config(text="📦 Zipping folder...")
                zip_path = path + '.zip'
                with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                    for root, dirs, files in os.walk(path):
                        for file in files:
                            file_path = os.path.join(root, file)
                            arcname = os.path.relpath(file_path, os.path.dirname(path))
                            zipf.write(file_path, arcname)
                path = zip_path
                
            filename = os.path.basename(path)
            filesize = os.path.getsize(path)
            
            metadata = {
                'type': 'file',
                'filename': filename,
                'filesize': filesize
            }
            encrypted = self.cipher.encrypt(json.dumps(metadata).encode())
            self.connected_peer['socket'].send(struct.pack('>I', len(encrypted)) + encrypted)
            
            self.progress_bar['value'] = 0
            self.progress_label.config(text=f"📤 Sending {filename}...")
            
            sent = 0
            with open(path, 'rb') as f:
                while sent < filesize:
                    chunk = f.read(self.chunk_size)
                    if not chunk:
                        break
                    
                    encrypted_chunk = self.cipher.encrypt(chunk)
                    self.connected_peer['socket'].send(struct.pack('>I', len(encrypted_chunk)) + encrypted_chunk)
                    
                    sent += len(chunk)
                    self.bytes_transferred = len(chunk)
                    
                    # Update progress
                    progress = (sent / filesize) * 100
                    self.progress_bar['value'] = progress
                    self.percent_label.config(text=f"{progress:.1f}%")
                    
                    # Calculate speed
                    speed = self.calculate_speed()
                    self.speed_label.config(text=f"Speed: {speed:.2f} MB/s")
                    
                    # Calculate time remaining
                    if speed > 0:
                        remaining_bytes = filesize - sent
                        remaining_seconds = remaining_bytes / (speed * 1024 * 1024)
                        self.time_label.config(text=f"Time remaining: {self.format_time(remaining_seconds)}")
                    
                    self.last_update_time = time.time()
                    self.root.update_idletasks()
                    
            if is_folder:
                os.remove(zip_path)
                
            # Calculate total time
            total_time = time.time() - self.transfer_start_time
            avg_speed = (filesize / total_time) / (1024 * 1024)
            
            self.progress_label.config(text="✅ Transfer complete!")
            self.speed_label.config(text=f"Avg Speed: {avg_speed:.2f} MB/s")
            self.time_label.config(text=f"Total time: {self.format_time(total_time)}")
            messagebox.showinfo("Success", f"Sent {filename} successfully!\nAverage speed: {avg_speed:.2f} MB/s")
            
        except Exception as e:
            messagebox.showerror("Transfer Error", f"Failed to send file: {e}")
            self.progress_label.config(text="❌ Transfer failed")
            self.speed_label.config(text="Speed: -- MB/s")
            self.time_label.config(text="Time remaining: --")
            
    def receive_data(self, sock):
        try:
            while self.connected_peer and self.running:
                length_data = sock.recv(4)
                if not length_data:
                    break
                    
                msg_length = struct.unpack('>I', length_data)[0]
                
                encrypted_data = b''
                while len(encrypted_data) < msg_length:
                    chunk = sock.recv(min(msg_length - len(encrypted_data), self.chunk_size))
                    if not chunk:
                        break
                    encrypted_data += chunk
                    
                data = self.cipher.decrypt(encrypted_data)
                
                try:
                    message = json.loads(data.decode())
                    if message['type'] == 'chat':
                        self.display_chat_message(message['sender'], message['text'])
                    elif message['type'] == 'file':
                        self.receive_file(sock, message)
                except:
                    pass
                    
        except Exception as e:
            print(f"Error receiving data: {e}")
            self.disconnect()
            
    def receive_file(self, sock, metadata):
        try:
            filename = metadata['filename']
            filesize = metadata['filesize']
            
            downloads_dir = Path.home() / 'Desktop' / 'FileShare'
            downloads_dir.mkdir(parents=True, exist_ok=True)
            
            filepath = downloads_dir / filename
            
            # Reset transfer stats
            self.transfer_start_time = time.time()
            self.bytes_transferred = 0
            self.last_update_time = time.time()
            self.speed_samples = []
            
            self.progress_bar['value'] = 0
            self.progress_label.config(text=f"📥 Receiving {filename}...")
            
            received = 0
            with open(filepath, 'wb') as f:
                while received < filesize:
                    # Receive length
                    length_data = sock.recv(4)
                    chunk_length = struct.unpack('>I', length_data)[0]
                    
                    # Receive encrypted chunk
                    encrypted_chunk = b''
                    while len(encrypted_chunk) < chunk_length:
                        part = sock.recv(min(chunk_length - len(encrypted_chunk), self.chunk_size))
                        encrypted_chunk += part
                        
                    chunk = self.cipher.decrypt(encrypted_chunk)
                    f.write(chunk)
                    
                    received += len(chunk)
                    self.bytes_transferred = len(chunk)
                    
                    # Update progress
                    progress = (received / filesize) * 100
                    self.progress_bar['value'] = progress
                    self.percent_label.config(text=f"{progress:.1f}%")
                    
                    # Calculate speed
                    speed = self.calculate_speed()
                    self.speed_label.config(text=f"Speed: {speed:.2f} MB/s")
                    
                    # Calculate time remaining
                    if speed > 0:
                        remaining_bytes = filesize - received
                        remaining_seconds = remaining_bytes / (speed * 1024 * 1024)
                        self.time_label.config(text=f"Time remaining: {self.format_time(remaining_seconds)}")
                    
                    self.last_update_time = time.time()
                    self.root.update_idletasks()
                    
            # Calculate total time
            total_time = time.time() - self.transfer_start_time
            avg_speed = (filesize / total_time) / (1024 * 1024)
            
            self.progress_label.config(text="✅ Receive complete!")
            self.speed_label.config(text=f"Avg Speed: {avg_speed:.2f} MB/s")
            self.time_label.config(text=f"Total time: {self.format_time(total_time)}")
            self.log_received_file(filename, str(filepath))
            
        except Exception as e:
            print(f"Error receiving file: {e}")
            self.progress_label.config(text="❌ Receive failed")
            self.speed_label.config(text="Speed: -- MB/s")
            self.time_label.config(text="Time remaining: --")
            
    def log_received_file(self, filename, path):
        self.received_text.config(state=tk.NORMAL)
        self.received_text.insert(tk.END, f"📥 Received: {filename}\n💾 Saved to: {path}\n\n")
        self.received_text.config(state=tk.DISABLED)
        self.received_text.see(tk.END)
        
    def send_message(self):
        if not self.connected_peer:
            messagebox.showwarning("Not Connected", "Please connect to a peer first")
            return
            
        text = self.chat_entry.get().strip()
        if not text:
            return
            
        try:
            message = {
                'type': 'chat',
                'sender': self.pc_name,
                'text': text
            }
            encrypted = self.cipher.encrypt(json.dumps(message).encode())
            self.connected_peer['socket'].send(struct.pack('>I', len(encrypted)) + encrypted)
            
            self.display_chat_message("You", text)
            self.chat_entry.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send message: {e}")
            
    def display_chat_message(self, sender, text):
        self.chat_display.config(state=tk.NORMAL)
        timestamp = time.strftime("%H:%M")
        if sender == "You":
            self.chat_display.insert(tk.END, f"[{timestamp}] You: {text}\n", "you")
        else:
            self.chat_display.insert(tk.END, f"[{timestamp}] {sender}: {text}\n", "them")
        
        self.chat_display.tag_config("you", foreground="#60a5fa")
        self.chat_display.tag_config("them", foreground="#34d399")
        
        self.chat_display.config(state=tk.DISABLED)
        self.chat_display.see(tk.END)
        
    def on_close(self):
        self.running = False
        self.disconnect()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = FileShareApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()