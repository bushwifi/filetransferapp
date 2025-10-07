# FileShare Pro

**FileShare Pro** is a modern, high-speed, cross-platform file and folder transfer tool with a beautiful GUI, built using Python and Tkinter. It supports encrypted peer-to-peer transfers, real-time progress, speed stats, and chat messaging between devices on the same network.

---

## 🚀 Features

- **Ultra-fast file & folder transfer** (up to 200GB per transfer)
- **End-to-end encryption** using Fernet (AES)
- **Folder zipping** for easy sharing of directories
- **Live progress bar, speed, and time remaining**
- **Built-in chat** between connected peers
- **Automatic peer discovery** on local network
- **Modern, responsive UI** with dark mode
- **Transfer logs** for received files

---

## 🛠️ Getting Started

### Prerequisites

- Python 3.8+
- `pip install -r requirements.txt`

### Installation

1. **Clone the repository:**
    ```sh
    https://github.com/bushwifi/filetransferapp/releases
    ```


---

## 💡 Usage

1. Launch **FileShare Pro** on two or more devices connected to the same local network.
2. Each device will appear in the "Available Devices" list.
3. Select a device and click **Connect**.
4. Once connected, select a file or folder and click **Send**.
5. Monitor transfer progress, speed, and chat in real time.

---

## 🔒 Security

- All transfers are encrypted using a password-derived key (Fernet/AES).
- No data leaves your local network.

---

## 📄 License

MIT License

---

## 🤝 Contributions

Contributions are welcome!  
Feel free to open issues or submit pull requests.

---

## 👤 Author

[bushwifis](https://github.com/yourusername)

---

> **Note:**  
> This tool is for educational and personal use. Always verify files before opening.

---

You can find the main application code in [`Transferwiz.py`](Transferwiz.py).  
The ModernButton and main UI logic are implemented in the [`FileShareApp`](Transferwiz.py) class.
