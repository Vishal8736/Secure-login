# Secure-Login 🛡️
> **Automated. Encrypted. Undetected.**

<p align="center">
  <img src="https://img.shields.io/badge/Developed%20By-Vishal%20%E2%9D%A4%EF%B8%8F%20Subhi-brightgreen" alt="Vishal ❤️ Subhi">
  <img src="https://img.shields.io/badge/Security-AES--256-blue" alt="AES-256">
  <img src="https://img.shields.io/badge/Language-Python%203-yellow" alt="Python">
</p>

## 👤 Developer Info
* **Name:** Vishal ❤️ Subhi
* **GitHub:** [github.com/vishal8736](https://github.com/vishal8736)
* **Email:** vishalsharma852863@gmail.com

---

## 📖 Overview
**Secure-Login** is a high-performance automation tool designed for Bug Bounty hunters and Cybersecurity professionals. It automates the login process for **Bugcrowd, GitHub, and HackerOne** in a single browser instance while maintaining maximum security.

Unlike standard scripts, **Secure-Login** features **Military-Grade Encryption (AES-256)** to protect your credentials and **Code Obfuscation** to prevent reverse engineering.

## ✨ Key Features

* **🔒 AES-256 Encryption:** Your credentials are never stored in plain text. They are encrypted using a Master Password.
* **👁️ Anti-Bot Detection:** Uses advanced `undetected-chromedriver` to bypass Cloudflare, Akamai, and Human Verification checks.
* **🛡️ Source Code Protection:** The core logic is obfuscated (hidden), making the code unreadable to unauthorized users.
* **🚀 Multi-Tab Automation:** Opens Bugcrowd, GitHub, and HackerOne simultaneously in one window.
* **⚡ Smart Network Handling:** Adapts to slow internet connections automatically.
* **🔑 OTP Support:** Built-in prompt to handle 2FA/OTP inputs seamlessly.

---

## ⚙️ Installation

### Prerequisites
* Kali Linux / Ubuntu / Termux (with GUI)
* Python 3.x
* Google Chrome installed

### Auto-Setup
We have provided an automated setup script to install dependencies and secure the tool.

1.  **Open Terminal** in the project directory.
2.  **Run the Setup Script:**
    ```bash
    chmod +x setup.sh
    ./setup.sh
    ```
    *(This script will create a virtual environment, install libraries, and compile the code into a secure `dist` folder.)*

---

## 💻 Usage

Once the installation is complete, use the generated launcher to start the tool.

### Start the Tool
```bash
./run_tool.sh
