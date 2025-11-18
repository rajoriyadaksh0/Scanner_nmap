# ⚡ ShadowSweep — Command-line Host & Port Recon Toolkit

ShadowSweep is a sleek wrapper over `python-nmap` that brings fast host discovery, customizable scan profiles, and pretty terminal output together. Point it at any IP or domain, toggle the scan flavors you need, and ShadowSweep turns the raw `nmap` output into a neat, timestamped report you can read or export.

---

## 🧰 Features at a Glance
- Toggleable scan presets: SYN, UDP, default scripts, service + version detection.
- Human-friendly report with protocol grouping and optional file export.
- Works cross-platform anywhere `nmap` + Python 3.10+ are available.

---

## 🚀 Quick Start

### 1. Clone the repo
```bash
git clone https://github.com/your-username/shadowsweep.git
cd shadowsweep
```

### 2. Ensure Python is ready
- Install Python 3.10+ from [python.org](https://www.python.org/downloads/) or your package manager.
- Confirm it’s on your `PATH`:
  ```bash
  python --version
  ```

### 3. Install Nmap (required by `python-nmap`)

| Platform | Command |
| --- | --- |
| **Debian / Ubuntu** | `sudo apt update && sudo apt install nmap` |
| **Fedora** | `sudo dnf install nmap` |
| **Arch / Manjaro** | `sudo pacman -S nmap` |
| **macOS (Homebrew)** | `brew install nmap` |
| **Windows (winget)** | `winget install nmap` |
| **Windows (manual)** | Download the latest self-installer from [nmap.org/download.html](https://nmap.org/download.html) and follow the wizard (be sure to tick “Add to PATH”). |

> ✅ Tip: Run `nmap --version` afterwards to verify the installation.

### 4. Install Python dependencies
```bash
python -m venv .venv
source .venv/bin/activate          # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

---

## 🕹️ Usage
```bash
python test.py <target> [flags]
```

**Common combos**
- Full TCP reconnaissance: `python test.py 192.168.1.10 -sS -sV -p 1-65535`
- UDP spotlight: `python test.py example.com -sU`
- Scripted sweep with export: `python test.py scanme.nmap.org -sC -oN scan.txt`

Flags available:
- `-sS` → TCP SYN scan  
- `-sU` → UDP scan  
- `-sV` → Service & version detection  
- `-sC` → Default NSE scripts  
- `-p`  → Port range (default `1-1024`)  
- `-oN` → Save output to a text file

---

## 🧪 Sample Output
```
[+] Starting Scan on scanme.nmap.org (Ports: 1-1024)
[+] Arguments -sS-sV
========================================
Host: scanme.nmap.org ()
State: UP
Protocol: tcp
PORT       STATE      SERVICE              VERSION
22         open       ssh                  OpenSSH 7.9p1
80         open       http                 Apache httpd 2.4.38
...
========================================
Scan finished with duration 7.42
```

---

## 📦 Project Structure
- `test.py` — CLI entrypoint, argument parsing, report generation.
- `requirements.txt` — pinned Python dependencies.

---

## 🧭 Roadmap Ideas
- JSON/HTML report exporters.
- Async multi-target mode.
- Predefined scan presets for pentests, uptime checks, etc.

---

Happy scanning! If you ship improvements, drop a PR or tag `#ShadowSweep` so we can see it in action.

