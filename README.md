# 🖥️ Windows Maintenance Toolkit

![Version](https://img.shields.io/badge/version-v2-green)
![Platform](https://img.shields.io/badge/platform-Windows-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-blue)

A powerful all-in-one Windows maintenance and automation script.  
Built for power users, sysadmins, and curious tinkerers – **smarter, safer, and fully native**.

---

> ⚠️ Some outputs may appear in your system language (e.g., English, Danish). This is expected behavior.

---

## 🚀 Quick Start

### 🔹 PowerShell (Offline)

Download the `.ps1` file from the [Releases](https://github.com/catsmoker/cs_script/releases) page and run with powershell.

### 🔹 PowerShell (Online)

Run this in **PowerShell (as Administrator)**:

powershell:
```
irm https://catsmoker.github.io/w | iex
```

### 🔹 Executable (Online)

Download the `.exe` installer from the [Releases](https://github.com/catsmoker/cs_script/releases) page and install it.

> 🛑 Only for **Windows 10 & 11**

---

## 🛠️ Features

### 🧹 System Maintenance

* Clean temp files, Recycle Bin, event logs, and DNS cache
* Scan & fix with `chkdsk`, `sfc`, and `DISM`
* Run full malware scan with **MRT**

### 📦 Software Management

* Install/update 30+ apps using **winget**
* Activate **IDM**, **Windows**, and **Office**

### 🌐 Network Tools

* Configure DNS (Google, Cloudflare, or custom)
* Reset adapters, view IP config, flush DNS, etc.
* View routing tables and perform Winsock reset

### 🧠 Registry Tools

* Safe cleaner: history, recent docs, open/save dialogs
* Backup & restore full registry
* Optimize performance with smart tweaks

### ⚙️ System Utilities

* Full Windows Update via `PSWindowsUpdate`
* Generate detailed system report
* Launch Chris Titus Tech's optimization tool
* Create desktop shortcuts for easy access

---

## 📁 Output Files

Saved to `Desktop\SystemReports` by default:

* `System_Info_YYYY-MM-DD.txt`
* `Network_Info_YYYY-MM-DD.txt`
* `Driver_List_YYYY-MM-DD.txt`
* `Routing_Table_YYYY-MM-DD.txt`

---

## 📋 System Requirements

* Windows 10 or 11
* PowerShell 5.1+
* Admin privileges
* Internet connection (for updates/tools)

---

## ❓ FAQ

**Q: Script didn’t restart as Admin?**
A: Make sure UAC is enabled. Or right-click the script → **Run as Administrator**.

**Q: Winget install/upgrade fails?**
A: Ensure `winget` is up to date. Script validates most input and handles common errors.

**Q: Why was Registry Defrag removed?**
A: It used **NTREGOPT**, a deprecated external tool. All features are now offline and native to Windows.

---

## 📦 Nativly Supported Applications for Download (use CTT Tool for more apps)
`I may remove this in the future`

| Category    | Examples                         |
| ----------- | -------------------------------- |
| Browsers    | Chrome, Firefox, Brave, Tor      |
| Media       | VLC, Spotify, foobar2000         |
| Utilities   | 7-Zip, Everything, ShareX        |
| Development | Git, VSCode, Notepad++           |
| Gaming      | Steam, Playnite, Heroic Launcher |

---

## 🧪 Diagnostics & Repair

| Task             | Command(s) Used                              |
| ---------------- | -------------------------------------------- |
| Disk Check       | `chkdsk /scan /perf`                         |
| File Integrity   | `sfc /scannow`                               |
| System Image Fix | `DISM /Online /Cleanup-Image /RestoreHealth` |
| Malware Scan     | `mrt.exe` (full system scan)                 |

---

## ✍️ Changelog

See [`CHANGELOG.md`](CHANGELOG.md) for full details of recent changes.

---

## 🤝 Contributing

Contributions, bug reports, and suggestions are welcome!
Check out [`CONTRIBUTING.md`](CONTRIBUTING.md) before submitting a PR.

---

## 📜 License

Licensed under the [MIT License](LICENSE).
Free for personal and professional use.

---

## 🧑‍💻 Credits

Developed by [catsmoker](https://catsmoker.github.io)
Inspired by:

* Microsoft PowerShell Team
* [Chris Titus Tech](https://christitus.com/)
* Open-source community contributors

---
