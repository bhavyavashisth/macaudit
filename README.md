# 🛡️ Macaudit

> **A powerful, local-first macOS security audit CLI with an interactive Terminal UI.**

`macaudit` is designed to help you quickly assess the security posture of your Mac. Whether you are running an older **Intel Mac** or the latest **Apple Silicon (M1/M2/M3)**, `macaudit` ships as a **Universal Binary** to work flawlessly across all modern macOS architectures.

![macOS Supported](https://img.shields.io/badge/macOS-Intel_%7C_Apple_Silicon-000000?style=for-the-badge&logo=apple)
![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=for-the-badge&logo=go)
![Version](https://img.shields.io/badge/version-0.1.0-blue?style=for-the-badge)

---

## ✨ Features

- **Interactive TUI:** A beautiful, arrow-key navigable terminal GUI with detailed descriptions for each audit module.
- **Universal Compatibility:** Natively compiled for both `darwin/amd64` (Intel) and `darwin/arm64` (Apple Silicon).
- **Comprehensive Core Security Checks:**
  - FileVault, Firewall, and Gatekeeper status
  - System Integrity Protection (SIP)
  - Automatic update schedules
  - Remote Login / SSH & Guest user status
- **Deep System Audits:**
  - **Startup & Persistence:** Reviews LaunchAgents, LaunchDaemons, shell startup files, and crontabs.
  - **Network Exposure:** Flags listening TCP services and unexpected DNS servers.
  - **App & Developer Checks:** Scans for unsigned/quarantined `/Applications`, and checks for weak SSH private key permissions.
  - **Browser & Brew:** Audits Homebrew packages/services and risky browser extension permissions (Chrome, Brave, Edge, Firefox).
  - **Secrets Scanner:** Scans local directories for exposed API keys, tokens, and private keys.
- **Exportable Reports:** Generate detailed audits in JSON, HTML, or Markdown for automation or compliance tracking.
- **Incident Response (IR):** Quick triage signals capturing recent logins, network activity, processes, and downloads.

---

## 🚀 Quick Install

You can easily download, build, and install the universal binary directly to your local path:

```bash
git clone https://github.com/bhavyavashisth/macaudit.git
cd macaudit
make build-all
./dist/macaudit-darwin-universal install
```
### By default, it installs to ~/.local/bin/macaudit.
> Note: If ~/.local/bin is not in your shell path, the installer will conveniently print the exact export PATH=... command you need to add to your profile).

## Once installed, simply type the following from anywhere to launch the UI:
```bash
macaudit
```
## 🛠️ Command Reference
Run audits directly from the CLI without opening the UI:
```bash
Command                      Description

macaudit                 Open the interactive terminal UI.

macaudit install         Install the tool locally.

macaudit scan	         Run the full audit (outputs readable issues and fixes).

macaudit scan --json	 Print the full audit in JSON format.

macaudit report --html	 Save an HTML audit report (macaudit-report.html).

macaudit report --md	 Save a Markdown audit report (macaudit-report.md).

macaudit brew	         Check Homebrew version, outdated packages, and running services.

macaudit browsers	     Inspect browser extension manifests for risky permissions.

macaudit startup	     Run deep startup/persistence checks.

macaudit apps	         Audit the /Applications directory.

macaudit secrets <dir>	 Scan a target folder for possible leaked secrets.

```

## 🔐 macOS Permissions
To get the most accurate results (especially for Startup, Apps, and IR checks), macaudit requires Full Disk Access.

    Open System Settings > Privacy & Security > Full Disk Access.

    Click the + to add your terminal app (Terminal, iTerm, Codex, etc.).

    Toggle it ON.

    Restart your terminal application.

## 🏗️ Building from Source
Build for your current Mac's architecture:
```bash
make build
```
Build release binaries for Intel, Apple Silicon, and the Universal macOS binary:
```bash
make build-all
```
> Compiled outputs will be located in the dist/ folder
## 🗺️ Roadmap
- [ ] Deeper TCC (Transparency, Consent, and Control) privacy parsing.

- [ ] Signed release packages.

- [ ] Optional privileged helper for safe, automated fixes.

- [ ] Richer app notarization checks.
## 🤝 Ethics & Usage
This tool is designed purely for defensive auditing on systems you own or have explicit permission to inspect. It is local-first, privacy-respecting, and does not exploit targets.

Author: Bhavya Sharma
