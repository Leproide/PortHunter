# 🛡️ PortHunter - Advanced Port & Process Scanner

![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)
![License](https://img.shields.io/badge/License-GPL%20v2-green.svg)

PortHunter is an advanced PowerShell tool suite for network port analysis and process correlation. It generates professional HTML reports for security audits and system troubleshooting.

## 📋 Overview

PortHunter includes two complementary scripts designed for different use cases:

| Script | Purpose | Method | Speed | Best For |
|--------|---------|--------|--------|----------|
| **PortHunter_Scan.ps1** | Active service discovery & port scanning | Active probing of common ports (TCP/UDP) + banner grabbing | 🐢 Slow (minutes) | Service discovery, penetration testing |
| **PortHunter_Established.ps1** | Advanced process-port correlation | Local socket inspection (listening + established) — no active probes | 🚀 Fast (seconds) | Security audits, troubleshooting |

## 🎯 PortHunter_Scan.ps1

### Key Features
- **📡 Active Port Scanning** - TCP/UDP scanning of common ports
- **🚩 Banner Grabbing** - Service identification via banners
- **🔗 Process Correlation** - Attempts to map discovered/open ports to processes when possible
- **📈 Comprehensive Reporting** - Detailed statistics and service analysis

### Scanning Behavior
- Performs active probes (TCP connect/SYN, UDP probes) against a predefined list of common ports (`$commonPorts`).
- Attempts banner grabbing to identify service and version information.
- When possible, correlates discovered open ports to local processes (if the target is local or the probe establishes a connection that can be mapped).

### Usage
```powershell
# Basic active scan (TCP + UDP common ports)
.\PortHunter_Scan.ps1

# TCP ports only
.\PortHunter_Scan.ps1 -SkipUDP

# Fast scan mode (reduce ports / parallelism)
.\PortHunter_Scan.ps1 -FastScan
```

## 🌐 PortHunter_Established.ps1

### Key Features
- **🔍 Multi-Method Correlation** - 4 different techniques to identify processes
- **🎯 Confidence System** - High/Medium/Low reliability ratings
- **📊 Advanced Reporting** - Method details and confidence levels
- **⚡ Optimized Performance** - Analyzes only listening ports and established connections (local socket inspection)

### Correlation Methods
1. **NetStat Analysis** - Most reliable native method (parses existing socket table)
2. **Active Connection Enumeration** - Uses `Get-NetTCPConnection` / `Get-NetUDPEndpoint` and related APIs
3. **Handle Analysis** - System handle inspection (requires admin; uses handle enumeration)
4. **Network Statistics** - Alternative correlation method (supplemental data)

### Usage
```powershell
# Basic local socket inspection (TCP + UDP)
.\PortHunter_Established.ps1

# Skip UDP endpoints
.\PortHunter_Established.ps1 -SkipUDP

# Fast mode (limited correlation methods)
.\PortHunter_Established.ps1 -FastScan
```

## 📊 Detailed Comparison

| Feature | PortHunter_Scan | PortHunter_Established |
|---------|-----------------|------------------------|
| **Primary Purpose** | Service discovery & active scanning | Process-port correlation (local sockets) |
| **Methodology** | Active probing of common ports (TCP/UDP) + banner grabbing | Local socket inspection (listening + established) — no active probes |
| **Ports Analyzed** | Common ports + active scanning | Listening ports and established connections only |
| **Speed** | Minutes (depends on ports/parallelism) | Seconds |
| **Banner Grabbing** | Comprehensive for scanned ports | Limited to existing connections where banner data is available |
| **Confidence Levels** | ❌ Not available | ✅ Implemented (High/Medium/Low) |
| **Multi-Method** | ❌ Primary method only | ✅ 4 methods |
| **Admin Required** | Recommended for certain probes (raw socket/UDP) | Recommended for handle analysis and full correlation |
| **Use Case** | Penetration testing, discovery | Security audits, troubleshooting |

## 📁 Output Structure

Each script generates timestamped HTML reports:
- **AdvancedPortScan_YYYYMMDD_HHMMSS.html** (PortHunter_Scan)
- **PortScanReport_YYYYMMDD_HHMMSS.html** (PortHunter_Established)

### Report Sections
- **📈 Summary** - Scan statistics
- **🔍 Detailed Analysis** - Port and process table
- **🚨 High-Risk Ports** - Critical ports highlighted
- **⚙️ Process Summary** - Grouped by process
- **🚩 Service Banners** - Service identification banners

## Best Practices
- Always run as Administrator for complete results
- Verify unknown processes on high-risk ports
- Analyze service banners for vulnerable versions
- Keep reports for audits and future comparisons

## 🔧 Customization

### Modifying High-Risk Ports

```powershell
# Edit the $HighRiskPorts variable in scripts
$HighRiskPorts = @(21, 22, 23, 25, 53, 135, 139, 443, 445, 993, 995, 1433, 3389, 5900)
```

## 📷 Screenshot
<img width="1219" height="832" alt="immagine" src="https://github.com/user-attachments/assets/d6df22ef-a1fe-4c6d-8ef0-8a6da7231a3b" />

<img width="1848" height="917" alt="immagine" src="https://github.com/user-attachments/assets/04b954a9-0db1-44ac-9abf-2b40ded0d0eb" />

## ⚠️ Disclaimer

These tools are designed for authorized security audits and system troubleshooting. Malicious use is strictly prohibited. The authors assume no responsibility for misuse of these tools.

---

**PortHunter** - Your Advanced Port & Process Hunting Companion 🔍
