# 🛡️ Zero MAL Scanner

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-success)

---

## 🔍 About

Zero MAL Scanner is a Python-based parallel malware scanning engine designed for cybersecurity research and educational purposes.

It performs hash-based verification, pattern detection, and forensic logging to identify potentially malicious files in real time.

---

## ⚙️ Features

- ⚡ Parallel scanning using ThreadPoolExecutor
- 🔐 MD5 & SHA256 hash verification
- 🧠 Malware pattern detection (Regex-based)
- 📁 Folder & file recursive scanning
- 🛑 Stop scan control
- 📊 Scan history tracking
- 📤 Export results to JSON
- 🧾 File metadata analysis
- 🖥️ Graphical interface (Tkinter)

---

## 🧪 Detection Methods

- Cryptographic hash comparison
- Known malware signature matching
- Regex-based attack pattern detection
- File behavior heuristics
- Safe file filtering

---

## 🚀 Installation

```bash
git clone https://github.com/Ahmed77Elboshy/zero-mal-scanner.git
cd zero-mal-scanner
python zero_mal_scanner.py
