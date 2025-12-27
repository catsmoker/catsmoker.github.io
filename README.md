# 🖥️ FreeMixKit v5.5 (Dev Choice Edition)

![Platform](https://img.shields.io/badge/platform-Windows-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-blue)
[![GitHub stars](https://img.shields.io/github/stars/catsmoker/FreeMixKit?style=social)](https://github.com/catsmoker/FreeMixKit/stargazers)

An advanced, all-in-one Windows maintenance and automation script with a full-featured Text-based User Interface (TUI). Built for power users, developers, and sysadmins who want smarter, safer, and fully native system control.

---

## 🚀 Getting Started

**Prerequisites:** Administrator privileges are required to run this script. It will automatically attempt to elevate itself if not run as admin.

1.  **Download:**
    *   Go to the [FreeMixKit GitHub Repository](https://github.com/catsmoker/FreeMixKit).
    *   Download the `w` PowerShell script.
2.  **Run:**
    *   Right-click on the `w` script.
    *   Select **"Run with PowerShell"**.

The script will open in a new console window with the TUI menu.

## ✨ Core Features

*   **Text-based User Interface (TUI):** A clean, keyboard-driven menu for easy navigation and execution of all modules.
*   **Developer Toolkit:** A one-click setup for a complete development environment.
*   **System Maintenance & Repair:** Powerful tools to clean, repair, and optimize your Windows OS.
*   **Software Management & Automation:** Streamlined access to install, update, and manage essential software, including some typically paid applications and specialized utilities.
*   **Privacy & Tweaks:** Quickly apply popular tweaks to disable telemetry, manage updates, and more.
*   **Activation Utilities:** Includes shortcuts to well-known activation scripts.

## 🛠️ Modules Overview

The script is divided into several modules, each targeting a specific area of system management.

| Category              | Module                  | Description                                                      |
| --------------------- | ----------------------- | ---------------------------------------------------------------- |
| **Developer**         | DEV CHOICE (Full)       | Installs .NET, Node, Python, Java, Git, Tools & Bibata Cursor.   |
| **Maintenance**       | Clean System Junk       | Clears Temp files, Prefetch, and flushes DNS.                    |
|                       | System Repair           | Runs SFC & DISM to fix OS corruption.                            |
|                       | Malware Scan            | Executes the Microsoft Malicious Software Removal Tool (MRT).    |
|                       | System Report           | Generates a hardware and OS specs report on your Desktop.        |
| **Software & Apps**   | Adobe Free (GenP)       | Opens the download portal for the GenP utility.                  |
|                       | Software Update         | Upgrades all installed applications using Winget.                |
|                       | Spotify Pro             | Installs Spicetify for a customized Spotify experience.          |
|                       | Discord Pro             | Installs LegCord (a Better Discord alternative).                 |
| **Activation**        | Activate Windows        | Launches the Microsoft Activation Scripts (MAS) utility.         |
|                       | Activate IDM            | Launches the Internet Download Manager activation script.        |
| **Tweaks & Privacy**  | Toggle Updates          | Enables or disables the Windows Update service.                  |
|                       | Toggle Defender         | Toggles Microsoft Defender's real-time protection.               |
|                       | Disable Telemetry       | Blocks Windows data collection policies.                         |
|                       | Registry Optimize       | Applies common registry tweaks for system responsiveness.        |
| **Network**           | Set Google/Cloudflare DNS | Quickly switch your DNS to trusted public resolvers.             |
|                       | Reset Network           | Resets IP, Winsock, and DNS settings to default.                 |
| **Utilities**         | CTT WinUtil             | Launches the popular Chris Titus Tech Windows Utility.           |
|                       | Registry Backup         | Creates a full backup of the HKLM registry hive to the Desktop.  |
|                       | Fix Resolution          | Downloads and runs the Custom Resolution Utility (CRU).          |
|                       | Add Shortcut            | Creates an admin shortcut for FreeMixKit on your Desktop.        |

---

### Disclaimer

This script includes tools that can modify your system extensively. It also contains modules that automate the download and execution of third-party software and activation scripts. Please use these features responsibly and at your own risk. The author is not responsible for any data loss or system instability.

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the [issues page](https://github.com/catsmoker/FreeMixKit/issues).

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
