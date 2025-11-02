# 🛡️ PortHunter - Advanced Port & Process Scanner

![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)
![License](https://img.shields.io/badge/License-GPL%20v2-green.svg)

PortHunter is an advanced PowerShell tool suite for network port analysis and process correlation. It generates professional HTML reports for security audits and system troubleshooting.

## 📋 Overview

PortHunter includes two complementary scripts designed for different use cases:

| Script | Purpose | Method | Speed | Best For |
|--------|---------|---------|--------|----------|
| **PortHunter_Scan.ps1** | Advanced process-port correlation | Existing connection analysis | 🚀 Fast (seconds) | Security audits, troubleshooting |
| **PortHunter_Estabilished.ps1** | Comprehensive service discovery | Active port scanning | 🐢 Slow (minutes) | Service discovery, penetration testing |

## 🎯 PortHunter_Scan.ps1

### Key Features
- **🔍 Multi-Method Correlation** - 4 different techniques to identify processes
- **🎯 Confidence System** - High/Medium/Low reliability ratings
- **📊 Advanced Reporting** - Method details and confidence levels
- **⚡ Optimized Performance** - Analyzes only listening ports

### Correlation Methods
1. **NetStat Analysis** - Most reliable native method
2. **Active Connection** - Your original idea with active connections
3. **Handle Analysis** - System handle analysis (requires admin)
4. **Network Statistics** - Alternative correlation method

### Usage
```powershell
# Basic scan (TCP + UDP)
.\PortHunter_Scan.ps1

# TCP ports only
.\PortHunter_Scan.ps1 -SkipUDP

# Fast scan mode
.\PortHunter_Scan.ps1 -FastScan
```

## 🌐 PortHunter_Estabilished.ps1

### Key Features

- ** 📡 Active Port Scanning - TCP/UDP scanning of common ports
- ** 🚩 Banner Grabbing - Service identification via banners
- ** 🔗 Process Correlation - Port-to-process mapping
- ** 📈 Comprehensive Reporting - Detailed statistics and service analysis

## 📊 Detailed Comparison

| Feature | PortHunter_Scan | PortHunter_Estabilished |
|---------|-----------------|-------------------------|
| **Primary Purpose** | Process-port correlation | Service discovery |
| **Methodology** | Existing connection analysis | Active port scanning |
| **Ports Analyzed** | Listening ports only | Common ports + active scanning |
| **Speed** | Seconds | Minutes |
| **Banner Grabbing** | Limited to existing ports | Comprehensive for scanned ports |
| **Confidence Levels** | ✅ Implemented | ❌ Not available |
| **Multi-Method** | ✅ 4 methods | ❌ Primary method only |
| **Admin Required** | Recommended | Mandatory |
| **Use Case** | Security audits, troubleshooting | Penetration testing, discovery |

## 🔧 Customization

### Modifying High-Risk Ports

```powershell
# Edit the $HighRiskPorts variable in scripts
$HighRiskPorts = @(21, 22, 23, 25, 53, 135, 139, 443, 445, 993, 995, 1433, 3389, 5900)
```
