<!--
  PortHunter - README
  Copyright (C) 2026 Leproide
  SPDX-License-Identifier: GPL-3.0-or-later
  Author: https://github.com/Leproide
-->

# 🛡️ PortHunter - Port, Process & Firewall Hunter for Windows

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207%2B-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)
![License](https://img.shields.io/badge/License-GPL%20v3-green.svg)

PortHunter is a PowerShell tool that maps every open port on a Windows machine to the process, service and binary behind it, checks whether Windows Firewall actually lets it through, finds ports that are intercepted or redirected without a visible listener, and produces a self-contained HTML report.

## 📋 Overview

| File | Purpose |
|------|---------|
| **PortHunter.ps1** | The engine. Full analysis by default, passive mode with `-Passive`. |
| **PortHunter_Scan.ps1** | Compatibility wrapper: runs `PortHunter.ps1` in full mode. |
| **PortHunter_Established.ps1** | Compatibility wrapper: runs `PortHunter.ps1 -Passive`. |
| **LICENSE** | GNU GPL v3.0 full text. |
| **.gitignore** | Keeps generated reports (which contain host details) out of the repository. |

| Mode | Opens connections to local services | Speed | Best for |
|------|-------------------------------------|-------|----------|
| **Full** (default) | Yes: hidden-port scan on loopback + banner grabbing | Seconds with the default port list, longer with `-FullScan` | Security audits, service discovery, finding interception |
| **Passive** (`-Passive` / `-FastScan`) | No | Seconds | Quick inventory, production machines, troubleshooting |

## 🎯 Features

- **🔗 Exact socket-to-process mapping** — TCP listeners, UDP endpoints and established connections from the OS socket table, grouped per port and owning process, with all bound addresses.
- **⚙️ Process context** — hosted Windows services (which services live in each `svchost`), command line, image path (including protected processes such as `lsass`, `wininit`, `services` via `QueryFullProcessImageName`).
- **✍️ Signature check** — Authenticode/catalog signatures; MSIX apps (`WindowsApps`) are verified through their package signature and publisher.
- **🧱 Windows Firewall evaluation** — for every port bound to a non-loopback address: active profiles, enabled inbound rules of the active store (protocol, local port/ranges/RPC keywords, program, service, package), block-over-allow precedence (block rules limited to specific remote addresses, e.g. ban lists, are reported as *partial block* and do not close the port), default inbound policy, disabled profiles. The report shows the matching rule and its scope; when several rules share the same display name the internal rule name is appended, and rules with a GUID name (created by hand or by third-party software, not Windows defaults) are marked `<custom {GUID}>`.
- **🚨 Sensitive ports** — RDP, SMB, RPC, databases, WinRM, VNC, Docker API... flagged as *reachable*, *blocked by firewall* or *loopback only*.
- **🕵️ Hidden-port detection** — a parallel connect scan on `127.0.0.1` (and `::1` with `-ScanIPv6`) finds ports that accept connections although no process owns a visible listening socket: VPN/WFP redirection, transparent proxies, port forwarding. For each one, PortHunter opens a test connection and looks for the **peer socket** to identify the intercepting process; if none exists, the interception happens at packet level (NDIS/WFP driver), inside a VM (WSL2 mirrored networking, Docker-in-WSL, Hyper-V: reported as a hint) or off-host.
- **🚩 Banner grabbing** — parallel; server-first protocols (SMTP, POP3, IMAP, FTP, SSH...) only wait for the greeting and are never probed, so anti-spam pregreet checks are not triggered; otherwise passive read first (FTP, SSH, SMTP, POP3, IMAP...), then HTTP probe; automatic **TLS retry** when a TLS record or an "HTTP request to an HTTPS server" reply is detected; **TLS fallback** for silent ports; certificate CN, expiry, protocol and self-signed flag. Session cookies, auth headers and tokens are redacted before being written to the report.
- **🌐 Established connections** — grouped per process and remote endpoint, optional reverse DNS.
- **📊 HTML report** — summary cards, section index, light/dark theme toggle (follows the OS theme by default, choice remembered by the browser), all content HTML-encoded.
- **⚡ Fast** — runspace pool, works on Windows PowerShell 5.1 and PowerShell 7+.

## 📦 Requirements

- Windows 10 / 11 or Windows Server 2016+
- Windows PowerShell 5.1 or PowerShell 7+
- **Administrator** privileges (required for complete process, service and firewall data; `-NoAdminCheck` runs with partial data)

## 🚀 Usage

```powershell
# Full analysis (hidden-port scan on the default port list + banners + firewall)
.\PortHunter.ps1

# Full analysis on all 65535 ports, IPv4 and IPv6 loopback, open report at the end
.\PortHunter.ps1 -FullScan -ScanIPv6 -OpenReport

# Passive inventory: no connections to local services, TCP only, unattended
.\PortHunter.ps1 -Passive -SkipUDP -NoPrompt

# Also treat web and mail ports as sensitive
.\PortHunter.ps1 -SensitivePorts 21,22,23,25,53,80,135,139,443,445,993,995,1433,3306,3389,5900,6379,27017

# Custom port list for the hidden-port scan, reverse DNS on established connections
.\PortHunter.ps1 -ScanPorts 25,110,143,993,995,8080 -ResolveDns

# Legacy names still work
.\PortHunter_Scan.ps1 -OpenReport
.\PortHunter_Established.ps1 -SkipUDP
```

If script execution is blocked, run it for the current session only:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

### Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-OutputPath` | `PortScanReport_<timestamp>.html` | Report path |
| `-Passive` (alias `-FastScan`) | off | No connections to local services: disables hidden-port scan and banners |
| `-SkipUDP` | off | Do not enumerate UDP endpoints |
| `-SensitivePorts` | built-in list | Replaces the sensitive TCP port list, e.g. `-SensitivePorts 21,22,25,80,443,3389` |
| `-SensitiveUdpPorts` | `69,161,1434` | Replaces the sensitive UDP port list |
| `-FullScan` | off | Hidden-port scan on ports 1-65535 |
| `-ScanPorts` | built-in list (66 ports) | Custom port list for the hidden-port scan |
| `-ScanIPv6` | off | Also scan `::1` |
| `-ScanTimeoutMs` | 300 | Connect timeout of the hidden-port scan |
| `-TimeoutMs` | 2000 | Connect/read timeout of banner grabbing |
| `-ThrottleLimit` | 32 | Parallel workers |
| `-NoActiveScan` | off | Skip only the hidden-port scan |
| `-NoBanner` | off | Skip only banner grabbing |
| `-NoFirewallCheck` | off | Skip Windows Firewall evaluation |
| `-NoSignatureCheck` | off | Skip signature verification |
| `-ResolveDns` | off | Reverse DNS for remote addresses |
| `-IncludeLoopbackConnections` | off | Include loopback established connections |
| `-OpenReport` | off | Open the report without asking |
| `-NoPrompt` | off | Never prompt |
| `-NoAdminCheck` | off | Run without Administrator privileges |

## 📁 Report

`PortScanReport_YYYYMMDD_HHMMSS.html`, a single self-contained file:

- **📈 Summary** — hidden ports, sensitive ports reachable, listeners, firewall-allowed ports, UDP endpoints, established connections, processes, banners, unsigned binaries
- **🕵️ Hidden Ports** — port, owner (when identified), correlation method, banner, TLS
- **🔄 TCP Listening Ports** — addresses, exposure, process, services, firewall verdict, notes, banner, TLS, signature
- **🔊 UDP Endpoints** — addresses, exposure, process, services, firewall verdict
- **🌐 Established Connections** — process, remote endpoint, host name, connection count
- **⚙️ Process Summary** — ports per process, services, signature, command line

## 🔍 How to read the results

| Finding | Meaning | What to do |
|---------|---------|------------|
| `SENSITIVE PORT REACHABLE` | Sensitive service bound to the network and allowed by the firewall for any remote address |
| `Sensitive (scoped firewall allow)` | Allowed only for specific remote addresses, subnets or interfaces | Verify the scope is what you expect | Restrict the rule scope (e.g. `LocalSubnet`/VPN), bind to loopback, or disable the service |
| `Sensitive (blocked by firewall)` | Bound to the network but blocked | Fine; binding to loopback is still cleaner |
| Hidden port with owner | Traffic redirected to a local process | Verify the process is expected (VPN client, proxy, security software) |
| Hidden port, unresolved | Packet-level interception or off-host forwarding | Check VPN/NDIS/WFP drivers and security software |
| `NotSigned` binary with open ports | Unsigned executable exposing services | Verify origin and version |

## ⚠️ Limitations

- Firewall evaluation is an approximation of the effective policy: edge traversal, IPsec/authenticated bypass and third-party firewalls are not evaluated. Rules limited by remote address, local address or interface type are reported as *scoped* (`Restricted`) instead of open. AppContainer rules apply only to processes actually running in an AppContainer (read from the process token); full-trust MSIX apps are not matched by them. Rules whose filters cannot be read are skipped and counted in the report header.
- UDP endpoints are listed but not probed: UDP probes are unreliable without protocol-specific payloads.
- The hidden-port scan targets loopback only: it inspects this machine, it is not a network scanner.

## 🔧 Customization

The sensitive port lists can be replaced at run time with `-SensitivePorts` / `-SensitiveUdpPorts`. The defaults and the other lists are at the top of `PortHunter.ps1`:

```powershell
$SensitiveTcpPorts = @(21, 23, 135, 139, 445, 1433, 1521, 2375, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 9200, 11211, 27017)
$SensitiveUdpPortsDefault = @(69, 161, 1434)
$TlsPorts          = @(443, 465, 636, 990, 993, 995, 2376, 5986, 6443, 8443)
$ServerFirstPorts  = @(21, 22, 23, 25, 110, 143, 587, 2525, 3306, 5900)   # wait for greeting, never probe
$DefaultScanPorts  = @( ... )
```

## 📷 Screenshot
<img width="1219" height="832" alt="PortHunter report" src="https://github.com/user-attachments/assets/d6df22ef-a1fe-4c6d-8ef0-8a6da7231a3b" />

<img width="1914" height="920" alt="immagine" src="https://github.com/user-attachments/assets/3fced634-fa68-48e8-a534-76318f31775e" />


## ⚠️ Disclaimer

PortHunter is intended for authorized security audits and system troubleshooting on machines you own or are permitted to analyze. It is released as is, without any warranty. The author assumes no responsibility for misuse.

## License

PortHunter is free software released under the **GNU General Public License v3.0** (GPL-3.0-or-later). See the [`LICENSE`](LICENSE) file or <https://www.gnu.org/licenses/gpl-3.0.html>.

## Author

**Leproide** — <https://github.com/Leproide>

---

**PortHunter** - Your Port & Process Hunting Companion 🔍
