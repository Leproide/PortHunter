<#
.SYNOPSIS
    PortHunter - Local TCP/UDP port, process, firewall and service scanner with HTML report.

.DESCRIPTION
    - Enumerates listening TCP ports, UDP endpoints and established TCP connections,
      grouped per port and owning process.
    - Correlates each socket with process, hosted Windows services, command line and
      signature (Authenticode, catalog or MSIX package signature). Resolves the image
      path of protected processes (lsass, wininit, services...).
    - Actively scans loopback to find "hidden" ports: ports that accept connections
      although no process owns a visible listening socket (VPN/WFP redirection,
      transparent proxies, port forwarding), and identifies the intercepting
      process through its peer socket when one exists.
    - Grabs banners in parallel: passive read, HTTP probe, automatic TLS retry when a
      TLS service is detected, TLS fallback for silent ports, certificate details.
    - Evaluates Windows Firewall (active store, active profiles, allow/block rules,
      default inbound policy) to tell whether an exposed port is actually reachable.
    - Produces a self-contained HTML report with light/dark theme toggle.

.PARAMETER OutputPath
    Path of the HTML report. Default: .\PortScanReport_<timestamp>.html

.PARAMETER TimeoutMs
    Connect/read timeout for banner grabbing, in milliseconds (200-30000).

.PARAMETER ScanTimeoutMs
    Connect timeout for the loopback port scan, in milliseconds (50-5000).

.PARAMETER ThrottleLimit
    Maximum number of parallel workers (1-128).

.PARAMETER ScanPorts
    Custom list of ports for the hidden-port scan (replaces the default list).

.PARAMETER FullScan
    Hidden-port scan on all ports 1-65535.

.PARAMETER ScanIPv6
    Also scan ::1 for hidden ports.

.PARAMETER Passive
    Passive mode (alias: -FastScan): no connection is opened towards local services.
    Disables hidden-port scan and banner grabbing; socket, process, signature and
    firewall analysis are still performed. Runs in seconds.

.PARAMETER SkipUDP
    Do not enumerate UDP endpoints.

.PARAMETER SensitivePorts
    Replaces the default list of sensitive TCP ports (flagged when reachable).

.PARAMETER SensitiveUdpPorts
    Replaces the default list of sensitive UDP ports (flagged when reachable).

.PARAMETER NoActiveScan
    Skip the hidden-port scan.

.PARAMETER NoBanner
    Skip banner grabbing.

.PARAMETER NoFirewallCheck
    Skip Windows Firewall evaluation.

.PARAMETER ResolveDns
    Reverse-resolve remote addresses of established connections (slower).

.PARAMETER NoSignatureCheck
    Skip signature verification of process executables.

.PARAMETER IncludeLoopbackConnections
    Include established connections to/from loopback addresses.

.PARAMETER OpenReport
    Open the report at the end without prompting.

.PARAMETER NoPrompt
    Never prompt (useful for scheduled/unattended runs).

.PARAMETER NoAdminCheck
    Run without Administrator privileges (process and firewall details will be incomplete).

.EXAMPLE
    .\PortHunter.ps1

.EXAMPLE
    .\PortHunter.ps1 -FullScan -ResolveDns -OpenReport -ThrottleLimit 64

.EXAMPLE
    .\PortHunter.ps1 -Passive -SkipUDP -NoPrompt

.NOTES
    PortHunter
    Copyright (C) 2026 Leproide

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program. If not, see <https://www.gnu.org/licenses/>.

    SPDX-License-Identifier: GPL-3.0-or-later
    Author:  https://github.com/Leproide
    Contact: leproide@paranoici.org
    Project: https://github.com/Leproide/PortHunter

    Compatible with Windows PowerShell 5.1 and PowerShell 7+.
    This file is intentionally pure ASCII so it runs correctly under
    Windows PowerShell 5.1 regardless of the file encoding.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ("PortScanReport_{0}.html" -f (Get-Date -Format 'yyyyMMdd_HHmmss')),
    [ValidateRange(200, 30000)][int]$TimeoutMs = 2000,
    [ValidateRange(50, 5000)][int]$ScanTimeoutMs = 300,
    [ValidateRange(1, 128)][int]$ThrottleLimit = 32,
    [ValidateRange(1, 65535)][int[]]$ScanPorts,
    [switch]$FullScan,
    [switch]$ScanIPv6,
    [Alias('FastScan')][switch]$Passive,
    [switch]$SkipUDP,
    [ValidateRange(1, 65535)][int[]]$SensitivePorts,
    [ValidateRange(1, 65535)][int[]]$SensitiveUdpPorts,
    [switch]$NoActiveScan,
    [switch]$NoBanner,
    [switch]$NoFirewallCheck,
    [switch]$ResolveDns,
    [switch]$NoSignatureCheck,
    [switch]$IncludeLoopbackConnections,
    [switch]$OpenReport,
    [switch]$NoPrompt,
    [switch]$NoAdminCheck
)

# ---------------------------------------------------------------------------
# Privilege check
# ---------------------------------------------------------------------------
if (-not $NoAdminCheck) {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Warning "Administrator privileges are required for complete process and firewall information."
        Write-Host "Run PowerShell as Administrator, or use -NoAdminCheck to continue with partial data." -ForegroundColor Yellow
        exit 1
    }
}

# Passive mode disables everything that opens connections to local services
$DoActiveScan = -not ($NoActiveScan -or $Passive)
$DoBanner     = -not ($NoBanner -or $Passive)

# ---------------------------------------------------------------------------
# Static data
# NOTE: LocalPort values from Get-Net* cmdlets are UInt16; always cast to [int]
#       before looking them up in these Int32-keyed tables.
# ---------------------------------------------------------------------------
$KnownTcpServices = @{
    20 = 'FTP-Data'; 21 = 'FTP'; 22 = 'SSH'; 23 = 'Telnet'; 25 = 'SMTP'; 53 = 'DNS'; 80 = 'HTTP'
    88 = 'Kerberos'; 110 = 'POP3'; 111 = 'RPCbind'; 135 = 'MS-RPC'; 139 = 'NetBIOS-SSN'; 143 = 'IMAP'
    389 = 'LDAP'; 443 = 'HTTPS'; 445 = 'SMB'; 465 = 'SMTPS'; 587 = 'SMTP Submission'; 636 = 'LDAPS'
    873 = 'rsync'; 990 = 'FTPS'; 993 = 'IMAPS'; 995 = 'POP3S'; 1080 = 'SOCKS'; 1433 = 'MSSQL'
    1521 = 'Oracle'; 1723 = 'PPTP'; 1883 = 'MQTT'; 2049 = 'NFS'; 2375 = 'Docker API'
    2376 = 'Docker API (TLS)'; 3128 = 'HTTP Proxy'; 3306 = 'MySQL'; 3389 = 'RDP'; 5040 = 'CDPSvc'
    5357 = 'WSDAPI'; 5432 = 'PostgreSQL'; 5672 = 'AMQP'; 5900 = 'VNC'; 5985 = 'WinRM HTTP'
    5986 = 'WinRM HTTPS'; 6379 = 'Redis'; 6443 = 'Kubernetes API'; 8080 = 'HTTP-Alt'
    8443 = 'HTTPS-Alt'; 9200 = 'Elasticsearch'; 11211 = 'Memcached'; 27017 = 'MongoDB'
}
$KnownUdpServices = @{
    53 = 'DNS'; 67 = 'DHCP Server'; 68 = 'DHCP Client'; 69 = 'TFTP'; 123 = 'NTP'; 137 = 'NetBIOS-NS'
    138 = 'NetBIOS-DGM'; 161 = 'SNMP'; 500 = 'IKE'; 514 = 'Syslog'; 1434 = 'SQL Browser'
    1900 = 'SSDP/UPnP'; 3389 = 'RDP (UDP)'; 3702 = 'WS-Discovery'; 4500 = 'IPsec NAT-T'
    5353 = 'mDNS'; 5355 = 'LLMNR'
}

# Ports that should normally not be reachable from the network
$SensitiveTcpPorts = @(21, 23, 135, 139, 445, 1433, 1521, 2375, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 9200, 11211, 27017)
$SensitiveUdpPortsDefault = @(69, 161, 1434)

# Command-line overrides
if ($SensitivePorts) { $SensitiveTcpPorts = @($SensitivePorts | Sort-Object -Unique) }
if ($SensitiveUdpPorts) { $SensitiveUdpPorts = @($SensitiveUdpPorts | Sort-Object -Unique) } else { $SensitiveUdpPorts = $SensitiveUdpPortsDefault }

# Ports probed with a TLS handshake first
$TlsPorts = @(443, 465, 636, 990, 993, 995, 2376, 5986, 6443, 8443)

# TLS ports that speak HTTP (an HTTP HEAD is sent after the handshake)
$TlsHttpPorts = @(443, 2376, 5986, 6443, 8443)

# Binary protocols: a text probe is useless, skip banner grabbing
$BannerSkipPorts = @(135, 139, 445, 3389)

# Default port list for the hidden-port scan on loopback
$DefaultScanPorts = @(
    20, 21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 389, 443, 445, 465, 514, 587,
    636, 873, 990, 993, 995, 1080, 1194, 1433, 1434, 1521, 1723, 1883, 2049, 2375, 2376, 3000,
    3128, 3306, 3389, 4443, 5000, 5001, 5432, 5601, 5672, 5900, 5985, 5986, 6379, 6443, 7001,
    8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9090, 9200, 9443, 10000, 11211, 15672, 27017
)

# Protocols where the server speaks first: wait for the greeting and never
# send a probe (e.g. Postfix postscreen flags clients that talk first)
$ServerFirstPorts = @(21, 22, 23, 25, 110, 143, 587, 2525, 3306, 5900)

# Maximum banner length stored in the report
$MaxBannerLength = 600

# ---------------------------------------------------------------------------
# Native helper: image path of protected processes (PPL) via
# PROCESS_QUERY_LIMITED_INFORMATION, which WMI cannot provide.
# ---------------------------------------------------------------------------
$script:NativeAvailable = $false
try {
    if (-not ('PortHunterNativeV3' -as [type])) {
        Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class PortHunterNativeV3
{
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(IntPtr handle, int flags, StringBuilder buffer, ref int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
    private static extern int DeriveAppContainerSidFromAppContainerName(string name, out IntPtr sid);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool ConvertSidToStringSid(IntPtr sid, out string sidString);

    [DllImport("advapi32.dll")]
    private static extern IntPtr FreeSid(IntPtr sid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr token, int infoClass, IntPtr buffer, int length, out int returned);

    private const uint TOKEN_QUERY = 0x0008;
    private const int TokenIsAppContainer = 29;
    private const int TokenAppContainerSid = 31;

    // AppContainer SID of a running process, read from its token.
    // Returns null when the token cannot be read, "" when the process is
    // not an AppContainer (e.g. full-trust MSIX apps), the SID otherwise.
    public static string GetProcessAppContainerSid(int pid)
    {
        IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero) { return null; }
        try
        {
            IntPtr tok;
            if (!OpenProcessToken(h, TOKEN_QUERY, out tok)) { return null; }
            try
            {
                int ret;
                IntPtr flag = Marshal.AllocHGlobal(4);
                int isAc;
                try
                {
                    if (!GetTokenInformation(tok, TokenIsAppContainer, flag, 4, out ret)) { return null; }
                    isAc = Marshal.ReadInt32(flag);
                }
                finally { Marshal.FreeHGlobal(flag); }
                if (isAc == 0) { return ""; }

                int len;
                GetTokenInformation(tok, TokenAppContainerSid, IntPtr.Zero, 0, out len);
                if (len <= 0) { return null; }
                IntPtr buf = Marshal.AllocHGlobal(len);
                try
                {
                    if (!GetTokenInformation(tok, TokenAppContainerSid, buf, len, out len)) { return null; }
                    IntPtr sid = Marshal.ReadIntPtr(buf);
                    string str;
                    return ConvertSidToStringSid(sid, out str) ? str : null;
                }
                finally { Marshal.FreeHGlobal(buf); }
            }
            finally { CloseHandle(tok); }
        }
        finally { CloseHandle(h); }
    }

    // AppContainer SID of a package family (fallback when the token is unreadable)
    public static string GetAppContainerSid(string packageFamilyName)
    {
        IntPtr sid;
        if (DeriveAppContainerSidFromAppContainerName(packageFamilyName, out sid) != 0) { return null; }
        try
        {
            string str;
            return ConvertSidToStringSid(sid, out str) ? str : null;
        }
        finally { FreeSid(sid); }
    }

    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    public static string GetImagePath(int pid)
    {
        IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero) { return null; }
        try
        {
            StringBuilder sb = new StringBuilder(1024);
            int size = sb.Capacity;
            if (QueryFullProcessImageName(h, 0, sb, ref size)) { return sb.ToString(0, size); }
            return null;
        }
        finally { CloseHandle(h); }
    }
}
'@
    }
    $script:NativeAvailable = $true
} catch {
    Write-Verbose "Native helper unavailable: $($_.Exception.Message)"
}

# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

# Classifies a bound/remote address
function Get-AddressScope {
    param([string]$Address)
    if ($Address -eq '0.0.0.0' -or $Address -eq '::') { return 'All interfaces' }
    if ($Address -like '127.*' -or $Address -eq '::1' -or $Address -like '::ffff:127.*') { return 'Loopback' }
    return 'Specific IP'
}

# Ranking used to pick the widest exposure of a group of addresses
function Get-ScopeRank {
    param([string]$Scope)
    switch ($Scope) { 'All interfaces' { return 3 } 'Specific IP' { return 2 } default { return 1 } }
}

# Picks the best address to connect to for a group of listening addresses
function Get-BestProbeTarget {
    param([string[]]$Addresses)
    foreach ($a in $Addresses) { if ($a -eq '0.0.0.0') { return '127.0.0.1' } }
    foreach ($a in $Addresses) { if ($a -like '127.*') { return $a } }
    foreach ($a in $Addresses) { if ($a -eq '::' -or $a -eq '::1') { return '::1' } }
    foreach ($a in $Addresses) { if ($a -notmatch ':') { return $a } }
    return $Addresses[0]
}

# HTML-encodes any value (prevents HTML injection from banners/command lines)
function ConvertTo-SafeHtml {
    param($Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

# Splits a port list into chunks for the runspace pool
function Get-PortChunks {
    param([int[]]$Ports, [int]$ChunkSize)
    $chunks = New-Object System.Collections.Generic.List[object]
    for ($i = 0; $i -lt $Ports.Count; $i += $ChunkSize) {
        $end = [Math]::Min($i + $ChunkSize, $Ports.Count) - 1
        $chunks.Add([int[]]$Ports[$i..$end])
    }
    return , $chunks.ToArray()
}

# Runs a scriptblock for each item in a runspace pool (works on PS 5.1 and 7+).
# The scriptblock must declare a parameter named $Item; extra parameters are
# passed through -Parameters.
function Invoke-RunspaceBatch {
    param(
        [object[]]$Items,
        [Parameter(Mandatory = $true)][scriptblock]$ScriptBlock,
        [hashtable]$Parameters = @{},
        [int]$ThrottleLimit = 16,
        [string]$Activity = 'Processing'
    )

    $results = New-Object System.Collections.Generic.List[object]
    if (-not $Items -or $Items.Count -eq 0) { return , $results.ToArray() }

    $pool = [runspacefactory]::CreateRunspacePool(1, $ThrottleLimit)
    $pool.Open()
    $jobs = New-Object System.Collections.Generic.List[object]

    try {
        foreach ($item in $Items) {
            $ps = [powershell]::Create()
            $ps.RunspacePool = $pool
            [void]$ps.AddScript($ScriptBlock.ToString()).AddParameter('Item', $item)
            foreach ($key in $Parameters.Keys) { [void]$ps.AddParameter($key, $Parameters[$key]) }
            $jobs.Add([PSCustomObject]@{ PowerShell = $ps; Handle = $ps.BeginInvoke() })
        }

        $done = 0
        foreach ($job in $jobs) {
            try {
                foreach ($o in $job.PowerShell.EndInvoke($job.Handle)) { $results.Add($o) }
            } catch {
                Write-Verbose "Worker failed: $($_.Exception.Message)"
            } finally {
                $job.PowerShell.Dispose()
                $done++
                Write-Progress -Activity $Activity -Status "$done / $($jobs.Count)" -PercentComplete (($done / $jobs.Count) * 100)
            }
        }
    } finally {
        Write-Progress -Activity $Activity -Completed
        $pool.Close()
        $pool.Dispose()
    }

    return , $results.ToArray()
}

# ---------------------------------------------------------------------------
# Signatures (Authenticode / catalog / MSIX package)
# ---------------------------------------------------------------------------

# MSIX executables are not Authenticode-signed individually: the package is.
# A package installed under WindowsApps carries AppxSignature.p7x, verified by
# Windows at install time.
function Get-MsixSignature {
    param([string]$Path)
    if ($Path -notmatch '^(.*\\WindowsApps\\[^\\]+)\\') { return $null }
    $root = $Matches[1]

    if (-not [System.IO.File]::Exists([System.IO.Path]::Combine($root, 'AppxSignature.p7x'))) {
        return 'NotSigned (MSIX, no package signature)'
    }

    $publisher = ''
    try {
        [xml]$manifest = [System.IO.File]::ReadAllText([System.IO.Path]::Combine($root, 'AppxManifest.xml'))
        $display = [string]$manifest.Package.Properties.PublisherDisplayName
        $pub = [string]$manifest.Package.Identity.Publisher
        if ($display -and $display -notmatch '^ms-resource:') { $publisher = $display }
        elseif ($pub -match 'CN=("?)([^",]+)\1') { $publisher = $Matches[2] }
        else { $publisher = $pub }
    } catch { }

    if ($publisher) { return "Valid (MSIX package: $publisher)" }
    return 'Valid (MSIX package)'
}

$script:SignatureCache = @{}
function Get-SignatureStatus {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    if ($script:SignatureCache.ContainsKey($Path)) { return $script:SignatureCache[$Path] }

    $status = 'N/A'
    try {
        $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction Stop
        if ($sig.Status -eq 'Valid') {
            $signer = $sig.SignerCertificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
            $status = "Valid ($signer)"
        } else {
            $status = [string]$sig.Status
            $msix = Get-MsixSignature -Path $Path
            if ($msix) { $status = $msix }
        }
    } catch {
        $status = 'Error'
    }

    $script:SignatureCache[$Path] = $status
    return $status
}

# ---------------------------------------------------------------------------
# Process ownership
# ---------------------------------------------------------------------------

# Image path of processes that WMI cannot read (protected processes)
function Get-ProtectedProcessPath {
    param([int]$ProcessId, [string]$Name)
    if ($script:NativeAvailable) {
        try {
            $p = [PortHunterNativeV3]::GetImagePath($ProcessId)
            if ($p) { return $p }
        } catch { }
    }
    if ($Name -and $Name -ne 'N/A') {
        if ($env:SystemRoot) {
            $candidate = [System.IO.Path]::Combine($env:SystemRoot, 'System32', $Name)
            if ([System.IO.File]::Exists($candidate)) { return $candidate }
        }
    }
    return ''
}

# Resolves PID -> process/service/signature info, with per-PID cache
$script:OwnerCache = @{}
function Get-OwnerInfo {
    param([int]$ProcessId)
    if ($script:OwnerCache.ContainsKey($ProcessId)) { return $script:OwnerCache[$ProcessId] }

    $proc = $script:ProcessTable[$ProcessId]
    $name = 'N/A'; $path = ''; $cmd = ''

    if ($ProcessId -eq 0) { $name = 'System Idle' }
    elseif ($ProcessId -eq 4) { $name = 'System (kernel)' }
    else {
        if ($proc) {
            $name = [string]$proc.Name
            $path = [string]$proc.ExecutablePath
            $cmd  = [string]$proc.CommandLine
        }
        if (-not $path) { $path = Get-ProtectedProcessPath -ProcessId $ProcessId -Name $name }
    }

    $sig = ''
    if (-not $NoSignatureCheck -and $path) { $sig = Get-SignatureStatus -Path $path }

    # MSIX package family (Name_PublisherId) and its AppContainer SID
    $packageSid = ''
    $isPackaged = $false
    if ($path -match '\\WindowsApps\\([^\\]+)\\') {
        $isPackaged = $true
        $full = $Matches[1]
        if ($full -match '^([^_]+)_[^_]+_[^_]*_[^_]*_([^_]+)$' -and $script:NativeAvailable) {
            try { $packageSid = [string][PortHunterNativeV3]::GetAppContainerSid("$($Matches[1])_$($Matches[2])") } catch { }
        }
    }

    # AppContainer state from the process token: '' = not an AppContainer,
    # SID = AppContainer, $null = unknown (token unreadable)
    $appContainerSid = $null
    if ($ProcessId -gt 4 -and $script:NativeAvailable) {
        try { $appContainerSid = [PortHunterNativeV3]::GetProcessAppContainerSid($ProcessId) } catch { }
    }

    $info = [PSCustomObject]@{
        ProcessId   = $ProcessId
        ProcessName = $name
        ProcessPath = $path
        CommandLine = $cmd
        Services    = [string]$script:ServiceTable[$ProcessId]
        Signature   = $sig
        IsPackaged      = $isPackaged
        PackageSid      = $packageSid
        AppContainerSid = $appContainerSid
    }
    $script:OwnerCache[$ProcessId] = $info
    return $info
}

# ---------------------------------------------------------------------------
# Windows Firewall evaluation
# Approximation of the effective policy: enabled inbound rules of the active
# store for the active profiles (protocol, local port, program, service,
# package), block-over-allow precedence, then default inbound action.
# ---------------------------------------------------------------------------
$script:Fw = [PSCustomObject]@{
    Available        = $false
    Error            = ''
    ActiveProfiles   = @()
    DisabledProfiles = @()
    DefaultAllow     = $false
    Rules            = @()
    Summary          = ''
    UnresolvedRules  = 0
}
$script:FwCache = @{}

function Initialize-FirewallData {
    try {
        # Active profiles from the current network connections
        $cats = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object {
            switch ([string]$_.NetworkCategory) {
                'DomainAuthenticated' { 'Domain' }
                'Private'             { 'Private' }
                default               { 'Public' }
            }
        } | Select-Object -Unique)
        if ($cats.Count -eq 0) { $cats = @('Domain', 'Private', 'Public') }
        $script:Fw.ActiveProfiles = $cats

        $summaryParts = @()
        foreach ($p in @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)) {
            $pname = [string]$p.Name
            if ($cats -notcontains $pname) { continue }
            $enabled = ([string]$p.Enabled -ne 'False')
            if (-not $enabled) { $script:Fw.DisabledProfiles += $pname }
            if ([string]$p.DefaultInboundAction -eq 'Allow') { $script:Fw.DefaultAllow = $true }
            $summaryParts += ("{0}: {1}, default inbound {2}" -f $pname, $(if ($enabled) { 'ON' } else { 'OFF' }), [string]$p.DefaultInboundAction)
        }
        $script:Fw.Summary = $summaryParts -join ' | '

        # Bulk-load filters once and index them by rule InstanceID
        $portIdx = @{}; foreach ($f in @(Get-NetFirewallPortFilter -All -PolicyStore ActiveStore -ErrorAction Stop)) { $portIdx[[string]$f.InstanceID] = $f }
        $appIdx  = @{}; foreach ($f in @(Get-NetFirewallApplicationFilter -All -PolicyStore ActiveStore -ErrorAction Stop)) { $appIdx[[string]$f.InstanceID] = $f }
        $svcIdx  = @{}; foreach ($f in @(Get-NetFirewallServiceFilter -All -PolicyStore ActiveStore -ErrorAction Stop)) { $svcIdx[[string]$f.InstanceID] = $f }
        $addrIdx = @{}; foreach ($f in @(Get-NetFirewallAddressFilter -All -PolicyStore ActiveStore -ErrorAction Stop)) { $addrIdx[[string]$f.InstanceID] = $f }
        $ifIdx   = @{}; foreach ($f in @(Get-NetFirewallInterfaceTypeFilter -All -PolicyStore ActiveStore -ErrorAction SilentlyContinue)) { $ifIdx[[string]$f.InstanceID] = $f }
        $ifaIdx  = @{}; foreach ($f in @(Get-NetFirewallInterfaceFilter -All -PolicyStore ActiveStore -ErrorAction SilentlyContinue)) { $ifaIdx[[string]$f.InstanceID] = $f }
        $script:Fw.UnresolvedRules = 0

        $rules = foreach ($r in @(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Inbound -ErrorAction Stop)) {
            # Keep only rules that apply to at least one active profile
            $profile = [string]$r.Profile
            $profileOk = ($profile -eq 'Any' -or $profile -eq '' -or $profile -eq '0')
            if (-not $profileOk) {
                foreach ($ap in $cats) { if ($profile -match "\b$ap\b") { $profileOk = $true; break } }
            }
            if (-not $profileOk) { continue }

            $id = [string]$r.InstanceID
            if (-not $id) { $id = [string]$r.Name }
            $pf = $portIdx[$id]; $af = $appIdx[$id]; $sf = $svcIdx[$id]; $adf = $addrIdx[$id]; $itf = $ifIdx[$id]

            # Filters missing from the bulk index: query them for this rule only.
            # A rule whose filters cannot be read is skipped instead of being
            # treated as "applies to everything".
            if (-not $pf -or -not $af -or -not $adf) {
                try {
                    if (-not $pf)  { $pf  = $r | Get-NetFirewallPortFilter -ErrorAction Stop }
                    if (-not $af)  { $af  = $r | Get-NetFirewallApplicationFilter -ErrorAction Stop }
                    if (-not $adf) { $adf = $r | Get-NetFirewallAddressFilter -ErrorAction Stop }
                    if (-not $sf)  { $sf  = $r | Get-NetFirewallServiceFilter -ErrorAction SilentlyContinue }
                    if (-not $itf) { $itf = $r | Get-NetFirewallInterfaceTypeFilter -ErrorAction SilentlyContinue }
                } catch { }
                if (-not $pf -or -not $af -or -not $adf) { $script:Fw.UnresolvedRules++; continue }
            }

            $proto = 'Any'
            if ($pf -and $pf.Protocol) { $proto = [string]$pf.Protocol }
            $tcp = @('Any', 'TCP', '6') -contains $proto
            $udp = @('Any', 'UDP', '17') -contains $proto
            if (-not ($tcp -or $udp)) { continue }

            $ports = @('Any')
            if ($pf -and $pf.LocalPort) { $ports = @($pf.LocalPort | ForEach-Object { [string]$_ }) }

            $program = 'Any'
            if ($af -and $af.Program -and [string]$af.Program -ne 'Any') {
                $program = [Environment]::ExpandEnvironmentVariables([string]$af.Program)
            }
            $package = ''
            if ($af -and $af.Package -and [string]$af.Package -ne 'Any') { $package = [string]$af.Package }

            $service = 'Any'
            if ($sf -and $sf.Service) { $service = [string]$sf.Service }

            # Remote scope: 'Any' means the rule applies to every remote address.
            # Long lists (e.g. ban lists) are shortened for display.
            $remoteAll = @('Any')
            if ($adf -and $adf.RemoteAddress) { $remoteAll = @($adf.RemoteAddress | ForEach-Object { [string]$_ }) }
            $remoteAny = ($remoteAll.Count -eq 0 -or $remoteAll -contains 'Any' -or $remoteAll -contains '*')
            $remote = 'Any'
            if (-not $remoteAny) {
                $remote = (@($remoteAll | Select-Object -First 3) -join ',')
                if ($remoteAll.Count -gt 3) { $remote += " (+$($remoteAll.Count - 3) more)" }
            }

            # Other scope limits: local address and interface type
            $localAll = @('Any')
            if ($adf -and $adf.LocalAddress) { $localAll = @($adf.LocalAddress | ForEach-Object { [string]$_ }) }
            $localAny = ($localAll.Count -eq 0 -or $localAll -contains 'Any' -or $localAll -contains '*')
            $ifType = 'Any'
            if ($itf -and $itf.InterfaceType) { $ifType = [string]$itf.InterfaceType }
            $ifAny = ($ifType -eq 'Any' -or $ifType -eq '')

            # Specific interfaces (e.g. Wi-Fi Direct virtual adapter for "WFD driver-only" rules)
            $ifaf = $ifaIdx[$id]
            $aliasAll = @('Any')
            if ($ifaf -and $ifaf.InterfaceAlias) { $aliasAll = @($ifaf.InterfaceAlias | ForEach-Object { [string]$_ }) }
            $aliasAny = ($aliasAll.Count -eq 0 -or $aliasAll -contains 'Any')
            if (-not $aliasAny) { $ifAny = $false; if ($ifType -eq 'Any' -or $ifType -eq '') { $ifType = 'alias ' + (@($aliasAll | Select-Object -First 2) -join ',') } }

            $scopeParts = @()
            if (-not $remoteAny) { $scopeParts += "remote: $remote" }
            if (-not $localAny)  { $scopeParts += "local: " + (@($localAll | Select-Object -First 2) -join ',') }
            if (-not $ifAny)     { $scopeParts += "iface: $ifType" }
            $scope = 'any'
            if ($scopeParts.Count -gt 0) { $scope = $scopeParts -join '; ' }

            # Per-user AppContainer rules carry an Owner SID
            $ownerSid = ''
            try { if ($r.Owner) { $ownerSid = [string]$r.Owner } } catch { }

            [PSCustomObject]@{
                Name    = [string]$r.DisplayName
                RuleId  = [string]$r.Name
                Action  = [string]$r.Action
                Tcp     = $tcp
                Udp     = $udp
                Ports   = $ports
                Program = $program
                Package = $package
                Service   = $service
                Remote    = $remote
                RemoteAny = $remoteAny
                Open      = ($remoteAny -and $localAny -and $ifAny)
                Scope     = $scope
                OwnerSid  = $ownerSid
            }
        }

        $script:Fw.Rules = @($rules)

        # Make rules distinguishable in the report: append the internal rule
        # Name when the display name is shared by several rules, and mark
        # rules with a GUID Name (created by hand or by third-party software,
        # not Windows defaults).
        $nameCount = @{}
        foreach ($rule in $script:Fw.Rules) { $nameCount[$rule.Name] = 1 + [int]$nameCount[$rule.Name] }
        foreach ($rule in $script:Fw.Rules) {
            $isGuid = ($rule.RuleId -match '^\{[0-9A-Fa-f-]{36}\}$')
            if ($isGuid) { $rule.Name = "$($rule.Name) <custom $($rule.RuleId)>" }
            elseif ($nameCount[$rule.Name] -gt 1) { $rule.Name = "$($rule.Name) <$($rule.RuleId)>" }
        }
        $script:Fw.Available = $true
    } catch {
        $script:Fw.Error = $_.Exception.Message
    }
}

# True when the rule's LocalPort spec covers the port
function Test-FwPortSpec {
    param([string[]]$Specs, [int]$Port)
    foreach ($s in $Specs) {
        if ($s -eq 'Any' -or $s -eq '') { return $true }
        if ($s -match '^\d+$') { if ([int]$s -eq $Port) { return $true }; continue }
        if ($s -match '^(\d+)-(\d+)$') {
            if ($Port -ge [int]$Matches[1] -and $Port -le [int]$Matches[2]) { return $true }
            continue
        }
        if ($s -eq 'RPCEPMap' -and $Port -eq 135) { return $true }
        if ($s -eq 'RPC' -and $Port -ge 49152) { return $true }
    }
    return $false
}

# True when the rule applies to this protocol/port/owner
function Test-FwRuleMatch {
    param($Rule, [string]$Protocol, [int]$Port, $Owner)

    if ($Protocol -eq 'TCP' -and -not $Rule.Tcp) { return $false }
    if ($Protocol -eq 'UDP' -and -not $Rule.Udp) { return $false }
    if (-not (Test-FwPortSpec -Specs $Rule.Ports -Port $Port)) { return $false }

    if ($Rule.Program -ne 'Any') {
        if ($Rule.Program -eq 'System') {
            if ($Owner.ProcessId -ne 4) { return $false }
        } elseif (-not $Owner.ProcessPath -or $Rule.Program -ne $Owner.ProcessPath) {
            return $false
        }
    }

    if ($Rule.Service -ne 'Any') {
        $svcs = @($Owner.Services -split ',\s*' | Where-Object { $_ })
        if ($Rule.Service -eq '*') {
            if ($svcs.Count -eq 0) { return $false }
        } elseif ($svcs -notcontains $Rule.Service) {
            return $false
        }
    }

    # AppContainer rules (package filter or per-user owner) apply only to
    # processes running inside an AppContainer. Full-trust MSIX apps (e.g.
    # Store Python, LocalSend) are NOT AppContainers.
    if ($Rule.Package -or $Rule.OwnerSid) {
        $acSid = $Owner.AppContainerSid
        if ($null -ne $acSid) {
            if ($acSid -eq '') { return $false }
            if ($Rule.Package -and $Rule.Package -ne '*' -and $Rule.Package -ne $acSid) { return $false }
        } else {
            # Token unreadable: fall back to the package SID derived from the path
            if (-not $Owner.IsPackaged) { return $false }
            if ($Rule.Package -and $Rule.Package -ne '*') {
                if (-not $Owner.PackageSid -or $Rule.Package -ne $Owner.PackageSid) { return $false }
            }
        }
    }

    return $true
}

# Returns Status (Reachable / Blocked / N/A / Unknown) and a human-readable detail
function Get-FirewallVerdict {
    param([string]$Protocol, [int]$Port, $Owner, [string]$Exposure)

    if ($Exposure -eq 'Loopback') { return [PSCustomObject]@{ Status = 'N/A'; Detail = 'Loopback only' } }
    if ($NoFirewallCheck) { return [PSCustomObject]@{ Status = 'Unknown'; Detail = 'Not checked' } }
    if (-not $script:Fw.Available) { return [PSCustomObject]@{ Status = 'Unknown'; Detail = "Firewall query failed: $($script:Fw.Error)" } }

    $key = "$Protocol|$Port|$($Owner.ProcessId)"
    if ($script:FwCache.ContainsKey($key)) { return $script:FwCache[$key] }

    $verdict = $null
    if ($script:Fw.DisabledProfiles.Count -gt 0) {
        $verdict = [PSCustomObject]@{ Status = 'Reachable'; Detail = "Firewall OFF on active profile: $($script:Fw.DisabledProfiles -join ', ')" }
    } else {
        $blocks = @(); $allows = @()
        foreach ($r in $script:Fw.Rules) {
            if (Test-FwRuleMatch -Rule $r -Protocol $Protocol -Port $Port -Owner $Owner) {
                if ($r.Action -eq 'Block') { $blocks += $r } else { $allows += $r }
            }
        }

        # Only an unrestricted block rule (any remote, any local address, any
        # interface) closes the port; scoped block rules (e.g. ban lists) only
        # remove part of the traffic.
        $fullBlocks    = @($blocks | Where-Object { $_.Open })
        $partialBlocks = @($blocks | Where-Object { -not $_.Open })
        $openAllows    = @($allows | Where-Object { $_.Open })
        $scopedAllows  = @($allows | Where-Object { -not $_.Open })

        $partialNote = ''
        if ($partialBlocks.Count -gt 0) {
            $partialNote = " | partial block: $($partialBlocks[0].Name) [$($partialBlocks[0].Scope)]"
            if ($partialBlocks.Count -gt 1) { $partialNote += " (+$($partialBlocks.Count - 1) more)" }
        }

        # Formats up to $Max rule names with their scope
        $fmt = {
            param($list, [int]$Max)
            $txt = (@($list | Select-Object -First $Max | ForEach-Object {
                if ($_.Open) { $_.Name } else { "$($_.Name) [$($_.Scope)]" }
            }) -join '; ')
            if ($list.Count -gt $Max) { $txt += " (+$($list.Count - $Max) more)" }
            $txt
        }

        if ($fullBlocks.Count -gt 0) {
            $verdict = [PSCustomObject]@{ Status = 'Blocked'; Detail = "Blocked by rule: $($fullBlocks[0].Name)" }
        } elseif ($openAllows.Count -gt 0) {
            $detail = "Open to any remote: " + (& $fmt $openAllows 2)
            if ($scopedAllows.Count -gt 0) { $detail += " | scoped: " + (& $fmt $scopedAllows 1) }
            $verdict = [PSCustomObject]@{ Status = 'Reachable'; Detail = $detail + $partialNote }
        } elseif ($scopedAllows.Count -gt 0) {
            $verdict = [PSCustomObject]@{ Status = 'Restricted'; Detail = "Scoped allow only: " + (& $fmt $scopedAllows 3) + $partialNote }
        } elseif ($script:Fw.DefaultAllow) {
            $verdict = [PSCustomObject]@{ Status = 'Reachable'; Detail = 'No rule matched, default inbound policy: Allow' + $partialNote }
        } else {
            $verdict = [PSCustomObject]@{ Status = 'Blocked'; Detail = 'No allow rule matched (default inbound: Block)' + $partialNote }
        }
    }

    $script:FwCache[$key] = $verdict
    return $verdict
}

# Builds the Notes text for sensitive ports
function Get-SensitiveNote {
    param([bool]$Sensitive, [string]$Exposure, $Verdict)
    if (-not $Sensitive) { return '' }
    if ($Exposure -eq 'Loopback') { return 'Sensitive (loopback only)' }
    switch ($Verdict.Status) {
        'Reachable'  { return 'SENSITIVE PORT REACHABLE' }
        'Restricted' { return 'Sensitive (scoped firewall allow)' }
        'Blocked'    { return 'Sensitive (blocked by firewall)' }
        default     { return 'SENSITIVE PORT EXPOSED (firewall state unknown)' }
    }
}

# ---------------------------------------------------------------------------
# Hidden-port owner correlation (main thread, only for the few hidden ports).
# Connects to the port and keeps the connection open, then looks for a socket
# whose remote endpoint is our client's local port: when the connection is
# redirected to a local proxy (WFP connect-redirect, transparent proxy, port
# forwarder) that peer socket belongs to the intercepting process.
# ---------------------------------------------------------------------------
# Hint for unresolved hidden ports: WSL2 (mirrored networking / localhost
# forwarding) and Hyper-V deliver loopback traffic to a VM without any
# Windows listening socket. Computed once in Start-PortHunterScan.
$script:VirtHint = ''
function Initialize-VirtualizationHint {
    $names = @($script:ProcessTable.Values | ForEach-Object { [string]$_.Name })
    $parts = @()
    if ($names -contains 'wslservice.exe' -or $names -contains 'vmmemWSL' -or $names -contains 'wslhost.exe') {
        $mode = ''
        try {
            $cfg = [System.IO.Path]::Combine([Environment]::GetFolderPath('UserProfile'), '.wslconfig')
            if ([System.IO.File]::Exists($cfg)) {
                $m = [regex]::Match([System.IO.File]::ReadAllText($cfg), '(?im)^\s*networkingMode\s*=\s*(\S+)')
                if ($m.Success) { $mode = " (.wslconfig networkingMode=$($m.Groups[1].Value))" }
            }
        } catch { }
        $parts += "WSL2 is running${mode}: ports published inside WSL/Docker-in-WSL are reachable on localhost without a Windows listener (check: wsl -l -v, docker ps inside the distro)"
    }
    if ($names -contains 'vmmem' -or $names -contains 'vmwp.exe') {
        $parts += 'Hyper-V VMs are running'
    }
    if ($parts.Count -gt 0) { $script:VirtHint = ' | Hint: ' + ($parts -join '; ') }
}

function Find-HiddenPortOwner {
    param([string]$Target, [int]$Port)

    $res = [PSCustomObject]@{ ProcessId = $null; Detail = '' }
    $client = $null
    try {
        $ip = [System.Net.IPAddress]::Parse($Target)
        $client = New-Object System.Net.Sockets.TcpClient($ip.AddressFamily)
        $ar = $client.BeginConnect($ip, $Port, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne([Math]::Max($ScanTimeoutMs * 3, 1000), $false)) {
            $res.Detail = 'Unresolved: connect timeout during correlation'
            return $res
        }
        $client.EndConnect($ar)
        $clientPort = ([System.Net.IPEndPoint]$client.Client.LocalEndPoint).Port

        # The peer socket may take a moment to appear in the table
        $peers = @()
        for ($i = 0; $i -lt 5 -and $peers.Count -eq 0; $i++) {
            Start-Sleep -Milliseconds 100
            $peers = @(Get-NetTCPConnection -RemotePort $clientPort -ErrorAction SilentlyContinue | Where-Object {
                [int]$_.OwningProcess -ne $PID -and (Get-AddressScope ([string]$_.RemoteAddress)) -eq 'Loopback'
            })
        }

        if ($peers.Count -gt 0) {
            $peer = $peers[0]
            $res.ProcessId = [int]$peer.OwningProcess
            if ([int]$peer.LocalPort -eq $Port) {
                $res.Detail = "Peer socket on port $Port owned by a process without a visible listener"
            } else {
                $res.Detail = "Peer socket: connection redirected from port $Port to local port $($peer.LocalPort)"
            }
        } else {
            $res.Detail = 'Unresolved: no local peer socket (packet-level interception by an NDIS/WFP driver, or traffic forwarded off-host)' + $script:VirtHint
        }
    } catch {
        $res.Detail = "Unresolved: $($_.Exception.Message)"
    } finally {
        if ($client) { $client.Close() }
    }
    return $res
}

# ---------------------------------------------------------------------------
# Worker: loopback connect scan (executed inside runspaces)
# $Item is an int[] chunk of ports; outputs the open ports.
# ---------------------------------------------------------------------------
$PortScanWorker = {
    param($Item, [string]$Target, [int]$ConnectTimeoutMs)
    $ip = [System.Net.IPAddress]::Parse($Target)
    foreach ($port in $Item) {
        $client = New-Object System.Net.Sockets.TcpClient($ip.AddressFamily)
        try {
            $ar = $client.BeginConnect($ip, [int]$port, $null, $null)
            if ($ar.AsyncWaitHandle.WaitOne($ConnectTimeoutMs, $false)) {
                try { $client.EndConnect($ar); [int]$port } catch { }
            }
        } catch {
        } finally {
            $client.Close()
        }
    }
}

# ---------------------------------------------------------------------------
# Worker: banner grabbing (executed inside runspaces, must be self-contained)
# ---------------------------------------------------------------------------
$BannerWorker = {
    param($Item, [int]$TimeoutMs, [int]$MaxBannerLength)

    # Reads the data available on the stream, polling the socket so that no
    # blocking Read() is issued when nothing has been received.
    function Read-Available {
        param([System.IO.Stream]$Stream, [System.Net.Sockets.Socket]$Socket, [int]$WaitMs)
        $buffer = New-Object byte[] 2048
        $ms = New-Object System.IO.MemoryStream
        $deadline = [DateTime]::UtcNow.AddMilliseconds($WaitMs)

        while ($Socket.Available -le 0 -and [DateTime]::UtcNow -lt $deadline) {
            Start-Sleep -Milliseconds 50
        }
        try {
            while ($Socket.Available -gt 0 -and $ms.Length -lt 4096) {
                $n = $Stream.Read($buffer, 0, $buffer.Length)
                if ($n -le 0) { break }
                $ms.Write($buffer, 0, $n)
                # Short grace period for multi-line banners
                Start-Sleep -Milliseconds 150
            }
        } catch { }
        return , $ms.ToArray()
    }

    # Converts raw bytes to printable, trimmed, length-limited text
    function ConvertTo-Printable {
        param([byte[]]$Bytes, [int]$MaxLength)
        if (-not $Bytes -or $Bytes.Length -eq 0) { return '' }
        $text = [System.Text.Encoding]::ASCII.GetString($Bytes)
        $text = ($text -replace '[^\x20-\x7E\r\n\t]', '.').Trim()
        # Never store secrets in the report: session cookies, auth headers, tokens
        $text = $text -replace '(?im)^(set-cookie:\s*[^=;\r\n]+=)[^;\r\n]*', '$1<redacted>'
        $text = $text -replace '(?im)^((?:www-authenticate|authorization|proxy-authorization|x-[a-z-]*token[a-z-]*|x-csrf[a-z-]*):\s*).*$', '$1<redacted>'
        if ($text.Length -gt $MaxLength) { $text = $text.Substring(0, $MaxLength) + ' [...]' }
        return $text
    }

    # Opens a TCP connection within the timeout; returns $null on timeout
    function Open-Connection {
        param([System.Net.IPAddress]$Ip, [int]$Port)
        $c = New-Object System.Net.Sockets.TcpClient($Ip.AddressFamily)
        $ar = $c.BeginConnect($Ip, $Port, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { $c.Close(); return $null }
        try { $c.EndConnect($ar) } catch { $c.Close(); throw }
        return $c
    }

    # Plain-text probe: passive read first, HTTP HEAD if the service is silent
    function Invoke-PlainProbe {
        param([System.Net.IPAddress]$Ip, [int]$Port, [byte[]]$HttpProbe, [bool]$ServerFirst)
        $r = @{ Bytes = [byte[]]@(); Mode = ''; Error = '' }
        $c = $null
        try {
            $c = Open-Connection -Ip $Ip -Port $Port
            if (-not $c) { $r.Error = 'Connect timeout'; return $r }
            $s = $c.GetStream()
            $s.ReadTimeout = $TimeoutMs
            $s.WriteTimeout = $TimeoutMs

            # Server-first protocols may delay the greeting (tarpit/postscreen)
            $wait = [Math]::Min($TimeoutMs, 1500)
            if ($ServerFirst) { $wait = [Math]::Max($TimeoutMs, 8000) }
            $bytes = Read-Available -Stream $s -Socket $c.Client -WaitMs $wait
            $mode = 'passive'
            if ($bytes.Length -eq 0 -and -not $ServerFirst) {
                $s.Write($HttpProbe, 0, $HttpProbe.Length)
                $s.Flush()
                $bytes = Read-Available -Stream $s -Socket $c.Client -WaitMs $TimeoutMs
                $mode = 'HTTP probe'
            }
            $r.Bytes = $bytes
            $r.Mode = $mode
        } catch {
            $r.Error = $_.Exception.Message
        } finally {
            if ($c) { $c.Close() }
        }
        return $r
    }

    # TLS probe: handshake, certificate details, optional HTTP HEAD
    function Invoke-TlsProbe {
        param([System.Net.IPAddress]$Ip, [int]$Port, [bool]$SendHttp, [byte[]]$HttpProbe)
        $r = @{ Bytes = [byte[]]@(); Tls = ''; Error = '' }
        $c = $null; $ssl = $null
        try {
            $c = Open-Connection -Ip $Ip -Port $Port
            if (-not $c) { $r.Error = 'Connect timeout'; return $r }
            $s = $c.GetStream()
            $s.ReadTimeout = $TimeoutMs
            $s.WriteTimeout = $TimeoutMs

            # Accept any certificate: we only want to read it
            $callback = [System.Net.Security.RemoteCertificateValidationCallback] { param($a, $b, $d, $e) $true }
            $ssl = New-Object System.Net.Security.SslStream($s, $false, $callback)
            $ssl.ReadTimeout = $TimeoutMs
            $ssl.WriteTimeout = $TimeoutMs

            # SslProtocols.None = OS default (.NET 4.7+ / .NET Core); explicit fallback for older runtimes
            try {
                $ssl.AuthenticateAsClient('localhost', $null, [System.Security.Authentication.SslProtocols]::None, $false)
            } catch [System.ArgumentException], [System.NotSupportedException] {
                $legacy = [System.Security.Authentication.SslProtocols]::Tls12 -bor [System.Security.Authentication.SslProtocols]::Tls11 -bor [System.Security.Authentication.SslProtocols]::Tls
                $ssl.AuthenticateAsClient('localhost', $null, $legacy, $false)
            }

            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
            $cn = $cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
            $selfSigned = ''
            if ($cert.Subject -eq $cert.Issuer) { $selfSigned = ' | self-signed' }
            $r.Tls = "{0} | CN: {1} | Expires: {2:yyyy-MM-dd}{3}" -f $ssl.SslProtocol, $cn, $cert.NotAfter, $selfSigned

            if ($SendHttp) {
                $ssl.Write($HttpProbe, 0, $HttpProbe.Length)
                $ssl.Flush()
            }
            $r.Bytes = Read-Available -Stream $ssl -Socket $c.Client -WaitMs $TimeoutMs
        } catch {
            $msg = $_.Exception.Message
            if ($_.Exception.InnerException) { $msg = $_.Exception.InnerException.Message }
            $r.Error = $msg
        } finally {
            if ($ssl) { $ssl.Dispose() }
            if ($c) { $c.Close() }
        }
        return $r
    }

    $result = [PSCustomObject]@{
        Key    = [string]$Item.Key
        Port   = [int]$Item.Port
        Target = [string]$Item.Target
        Banner = ''
        Tls    = ''
        Status = ''
    }

    try {
        $ip = [System.Net.IPAddress]::Parse($Item.Target)
        $port = [int]$Item.Port

        $hostHeader = $Item.Target
        if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) { $hostHeader = "[$($Item.Target)]" }
        $httpProbe = [System.Text.Encoding]::ASCII.GetBytes("HEAD / HTTP/1.0`r`nHost: $hostHeader`r`nUser-Agent: PortHunter`r`nConnection: close`r`n`r`n")

        # Messages returned by HTTP servers when plain HTTP hits a TLS port
        $httpsHint = 'HTTP request to an HTTPS server|plain HTTP request was sent to HTTPS port|speaking plain HTTP to an SSL-enabled server|sent an HTTP request to an HTTPS server'

        if ($Item.Tls) {
            # Known TLS port: TLS first, plain text as fallback
            $t = Invoke-TlsProbe -Ip $ip -Port $port -SendHttp ([bool]$Item.Http) -HttpProbe $httpProbe
            if ($t.Tls) {
                $result.Tls = $t.Tls
                $result.Banner = ConvertTo-Printable -Bytes $t.Bytes -MaxLength $MaxBannerLength
                $result.Status = 'OK (TLS)'
            } else {
                $p = Invoke-PlainProbe -Ip $ip -Port $port -HttpProbe $httpProbe -ServerFirst ([bool]$Item.ServerFirst)
                if ($p.Error) { $result.Status = "Error: $($p.Error)" }
                elseif ($p.Bytes.Length -gt 0) {
                    $result.Banner = ConvertTo-Printable -Bytes $p.Bytes -MaxLength $MaxBannerLength
                    $result.Status = "OK ($($p.Mode), TLS failed: $($t.Error))"
                } else { $result.Status = "No response (TLS failed: $($t.Error))" }
            }
        } else {
            $p = Invoke-PlainProbe -Ip $ip -Port $port -HttpProbe $httpProbe -ServerFirst ([bool]$Item.ServerFirst)
            if ($p.Error) {
                $result.Status = "Error: $($p.Error)"
            } else {
                $isTlsRecord = ($p.Bytes.Length -gt 0 -and ($p.Bytes[0] -eq 0x15 -or $p.Bytes[0] -eq 0x16))
                $plainText = ''
                if (-not $isTlsRecord) { $plainText = ConvertTo-Printable -Bytes $p.Bytes -MaxLength $MaxBannerLength }
                $httpsDetected = ($plainText -match $httpsHint)
                $silent = ($p.Bytes.Length -eq 0)
                if ($silent -and $Item.ServerFirst) {
                    $result.Status = 'No greeting'
                    return $result
                }

                if ($isTlsRecord -or $httpsDetected -or $silent) {
                    # TLS retry (TLS detected) or TLS fallback (silent service)
                    $t = Invoke-TlsProbe -Ip $ip -Port $port -SendHttp $true -HttpProbe $httpProbe
                    if ($t.Tls) {
                        $result.Tls = $t.Tls
                        $result.Banner = ConvertTo-Printable -Bytes $t.Bytes -MaxLength $MaxBannerLength
                        if ($silent) { $result.Status = 'OK (TLS fallback)' } else { $result.Status = 'OK (TLS retry)' }
                    } elseif ($isTlsRecord -or $httpsDetected) {
                        $result.Tls = "TLS detected, handshake failed: $($t.Error)"
                        $result.Banner = $plainText
                        $result.Status = 'TLS service'
                    } else {
                        $result.Status = 'No response'
                    }
                } else {
                    $result.Banner = $plainText
                    $result.Status = "OK ($($p.Mode))"
                }
            }
        }
    } catch {
        $result.Status = "Error: $($_.Exception.Message)"
    }

    return $result
}

# ---------------------------------------------------------------------------
# Worker: reverse DNS (executed inside runspaces)
# ---------------------------------------------------------------------------
$DnsWorker = {
    param($Item)
    $name = ''
    try {
        $name = ([System.Net.Dns]::GetHostEntry([string]$Item)).HostName
        if ($name -eq $Item) { $name = '' }
    } catch { }
    [PSCustomObject]@{ Address = [string]$Item; HostName = $name }
}

# ---------------------------------------------------------------------------
# Data collection
# ---------------------------------------------------------------------------
function Start-PortHunterScan {

    Write-Host "`n[*] Loading process and service tables..." -ForegroundColor Cyan
    $script:ProcessTable = @{}
    foreach ($p in @(Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue)) {
        $script:ProcessTable[[int]$p.ProcessId] = $p
    }

    $script:ServiceTable = @{}
    foreach ($s in @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.ProcessId -gt 0 })) {
        $procId = [int]$s.ProcessId
        if ($script:ServiceTable.ContainsKey($procId)) { $script:ServiceTable[$procId] += ", $($s.Name)" }
        else { $script:ServiceTable[$procId] = [string]$s.Name }
    }

    if (-not $NoFirewallCheck) {
        Write-Host "[*] Loading Windows Firewall policy..." -ForegroundColor Cyan
        Initialize-FirewallData
        if (-not $script:Fw.Available) { Write-Warning "Firewall evaluation unavailable: $($script:Fw.Error)" }
    }

    # --- TCP listeners, grouped per port + process --------------------------
    Write-Host "[*] Enumerating TCP listeners..." -ForegroundColor Cyan
    $tcpListen = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue)

    $listenRows = @(
        foreach ($g in ($tcpListen | Group-Object -Property LocalPort, OwningProcess)) {
            $first = $g.Group[0]
            $port = [int]$first.LocalPort
            $owner = Get-OwnerInfo -ProcessId ([int]$first.OwningProcess)

            $addrs = @($g.Group | ForEach-Object { [string]$_.LocalAddress } | Select-Object -Unique |
                Sort-Object @{ Expression = { if ($_ -match ':') { 1 } else { 0 } } }, @{ Expression = { $_ } })

            $exposure = 'Loopback'
            foreach ($a in $addrs) {
                $sc = Get-AddressScope $a
                if ((Get-ScopeRank $sc) -gt (Get-ScopeRank $exposure)) { $exposure = $sc }
            }

            $verdict = Get-FirewallVerdict -Protocol 'TCP' -Port $port -Owner $owner -Exposure $exposure
            $notes = Get-SensitiveNote -Sensitive ($SensitiveTcpPorts -contains $port) -Exposure $exposure -Verdict $verdict

            [PSCustomObject]@{
                Port           = $port
                Addresses      = $addrs -join ', '
                AddressList    = $addrs
                Exposure       = $exposure
                KnownService   = [string]$KnownTcpServices[$port]
                ProcessId      = $owner.ProcessId
                ProcessName    = $owner.ProcessName
                Services       = $owner.Services
                FirewallStatus = $verdict.Status
                Firewall       = $verdict.Detail
                Notes          = $notes
                BannerStatus   = ''
                Tls            = ''
                Banner         = ''
                Signature      = $owner.Signature
                ProcessPath    = $owner.ProcessPath
            }
        }
    ) | Sort-Object Port, ProcessId
    $listenRows = @($listenRows)

    # --- Hidden ports: open on loopback without a visible listener ----------
    $hiddenRows = @()
    $scannedCount = 0
    $scanTargets = @()
    if ($DoActiveScan) {
        Initialize-VirtualizationHint

        # Ports already explained by a visible listener reachable from loopback.
        # '::' is also counted for IPv4 because dual-stack sockets accept IPv4.
        $v4Reach = New-Object 'System.Collections.Generic.HashSet[int]'
        $v6Reach = New-Object 'System.Collections.Generic.HashSet[int]'
        foreach ($c in $tcpListen) {
            $a = [string]$c.LocalAddress
            $p = [int]$c.LocalPort
            if ($a -eq '0.0.0.0' -or $a -eq '127.0.0.1' -or $a -eq '::') { [void]$v4Reach.Add($p) }
            if ($a -eq '::' -or $a -eq '::1') { [void]$v6Reach.Add($p) }
        }

        if ($FullScan) { $portList = 1..65535 }
        elseif ($ScanPorts) { $portList = @($ScanPorts | Sort-Object -Unique) }
        else { $portList = $DefaultScanPorts }

        $scanTargets = @('127.0.0.1')
        if ($ScanIPv6) { $scanTargets += '::1' }

        foreach ($target in $scanTargets) {
            $reach = $v4Reach
            if ($target -eq '::1') { $reach = $v6Reach }
            $candidates = [int[]]@($portList | Where-Object { -not $reach.Contains([int]$_) })
            if ($candidates.Count -eq 0) { continue }
            $scannedCount += $candidates.Count

            Write-Host ("[*] Hidden-port scan on {0}: {1} ports..." -f $target, $candidates.Count) -ForegroundColor Cyan
            $chunkSize = [Math]::Max(16, [Math]::Ceiling($candidates.Count / ($ThrottleLimit * 4)))
            $chunks = Get-PortChunks -Ports $candidates -ChunkSize $chunkSize
            $open = Invoke-RunspaceBatch -Items $chunks -ScriptBlock $PortScanWorker `
                -Parameters @{ Target = $target; ConnectTimeoutMs = $ScanTimeoutMs } `
                -ThrottleLimit $ThrottleLimit -Activity "Hidden-port scan ($target)"

            foreach ($port in @($open | ForEach-Object { [int]$_ } | Sort-Object -Unique)) {
                $corr = Find-HiddenPortOwner -Target $target -Port $port
                $ownerId = $null; $ownerName = 'Unknown'; $ownerPath = ''; $ownerSig = ''
                if ($null -ne $corr.ProcessId) {
                    $o = Get-OwnerInfo -ProcessId $corr.ProcessId
                    $ownerId = $o.ProcessId; $ownerName = $o.ProcessName; $ownerPath = $o.ProcessPath; $ownerSig = $o.Signature
                }
                $hiddenRows += [PSCustomObject]@{
                    Key          = "H|$target|$port"
                    Port         = $port
                    Target       = $target
                    KnownService = [string]$KnownTcpServices[$port]
                    ProcessId    = $ownerId
                    ProcessName  = $ownerName
                    Correlation  = $corr.Detail
                    BannerStatus = ''
                    Tls          = ''
                    Banner       = ''
                    Signature    = $ownerSig
                    ProcessPath  = $ownerPath
                }
            }
        }
    }

    # --- Banner grabbing: one probe per (port, process) and per hidden port --
    if ($DoBanner -and ($listenRows.Count + $hiddenRows.Count) -gt 0) {
        Write-Host "[*] Grabbing banners (parallel, $ThrottleLimit workers)..." -ForegroundColor Cyan

        $targets = New-Object System.Collections.Generic.List[object]
        foreach ($row in $listenRows) {
            if ($BannerSkipPorts -contains $row.Port) { $row.BannerStatus = 'Skipped (binary protocol)'; continue }
            $targets.Add([PSCustomObject]@{
                Key    = "L|$($row.Port)|$($row.ProcessId)"
                Port   = $row.Port
                Target = Get-BestProbeTarget -Addresses $row.AddressList
                Tls    = ($TlsPorts -contains $row.Port)
                Http   = ($TlsHttpPorts -contains $row.Port)
                ServerFirst = ($ServerFirstPorts -contains $row.Port)
            })
        }
        foreach ($row in $hiddenRows) {
            if ($BannerSkipPorts -contains $row.Port) { $row.BannerStatus = 'Skipped (binary protocol)'; continue }
            $targets.Add([PSCustomObject]@{
                Key    = $row.Key
                Port   = $row.Port
                Target = $row.Target
                Tls    = ($TlsPorts -contains $row.Port)
                Http   = ($TlsHttpPorts -contains $row.Port)
                ServerFirst = ($ServerFirstPorts -contains $row.Port)
            })
        }

        $bannerResults = Invoke-RunspaceBatch -Items $targets.ToArray() -ScriptBlock $BannerWorker `
            -Parameters @{ TimeoutMs = $TimeoutMs; MaxBannerLength = $MaxBannerLength } `
            -ThrottleLimit $ThrottleLimit -Activity 'Banner grabbing'

        $byKey = @{}
        foreach ($b in $bannerResults) { $byKey[$b.Key] = $b }

        foreach ($row in $listenRows) {
            $k = "L|$($row.Port)|$($row.ProcessId)"
            if ($byKey.ContainsKey($k)) {
                $row.BannerStatus = $byKey[$k].Status
                $row.Tls = $byKey[$k].Tls
                $row.Banner = $byKey[$k].Banner
            }
        }
        foreach ($row in $hiddenRows) {
            if ($byKey.ContainsKey($row.Key)) {
                $row.BannerStatus = $byKey[$row.Key].Status
                $row.Tls = $byKey[$row.Key].Tls
                $row.Banner = $byKey[$row.Key].Banner
            }
        }
    }

    # --- UDP endpoints, grouped per port + process (no probing) -------------
    $udpEndpoints = @()
    if (-not $SkipUDP) {
        Write-Host "[*] Enumerating UDP endpoints..." -ForegroundColor Cyan
        $udpEndpoints = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue)
    }
    $udpRows = @(
        foreach ($g in ($udpEndpoints | Group-Object -Property LocalPort, OwningProcess)) {
            $first = $g.Group[0]
            $port = [int]$first.LocalPort
            $owner = Get-OwnerInfo -ProcessId ([int]$first.OwningProcess)

            $addrs = @($g.Group | ForEach-Object { [string]$_.LocalAddress } | Select-Object -Unique |
                Sort-Object @{ Expression = { if ($_ -match ':') { 1 } else { 0 } } }, @{ Expression = { $_ } })

            $exposure = 'Loopback'
            foreach ($a in $addrs) {
                $sc = Get-AddressScope $a
                if ((Get-ScopeRank $sc) -gt (Get-ScopeRank $exposure)) { $exposure = $sc }
            }

            $verdict = Get-FirewallVerdict -Protocol 'UDP' -Port $port -Owner $owner -Exposure $exposure
            $notes = Get-SensitiveNote -Sensitive ($SensitiveUdpPorts -contains $port) -Exposure $exposure -Verdict $verdict

            [PSCustomObject]@{
                Port           = $port
                Addresses      = $addrs -join ', '
                Exposure       = $exposure
                KnownService   = [string]$KnownUdpServices[$port]
                ProcessId      = $owner.ProcessId
                ProcessName    = $owner.ProcessName
                Services       = $owner.Services
                FirewallStatus = $verdict.Status
                Firewall       = $verdict.Detail
                Notes          = $notes
                Signature      = $owner.Signature
                ProcessPath    = $owner.ProcessPath
            }
        }
    ) | Sort-Object Port, ProcessId
    $udpRows = @($udpRows)

    # --- Established connections (grouped by process + remote endpoint) -----
    Write-Host "[*] Enumerating established connections..." -ForegroundColor Cyan
    $established = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue)
    if (-not $IncludeLoopbackConnections) {
        $established = @($established | Where-Object { (Get-AddressScope ([string]$_.RemoteAddress)) -ne 'Loopback' })
    }

    $estRows = @(
        foreach ($g in ($established | Group-Object -Property OwningProcess, RemoteAddress, RemotePort)) {
            $c = $g.Group[0]
            $owner = Get-OwnerInfo -ProcessId ([int]$c.OwningProcess)
            $localPorts = ($g.Group | ForEach-Object { [int]$_.LocalPort } | Sort-Object -Unique) -join ', '
            [PSCustomObject]@{
                ProcessId     = $owner.ProcessId
                ProcessName   = $owner.ProcessName
                RemoteAddress = [string]$c.RemoteAddress
                RemotePort    = [int]$c.RemotePort
                RemoteHost    = ''
                Connections   = $g.Count
                LocalPorts    = $localPorts
                Signature     = $owner.Signature
                ProcessPath   = $owner.ProcessPath
            }
        }
    ) | Sort-Object ProcessName, RemoteAddress, RemotePort
    $estRows = @($estRows)

    if ($ResolveDns -and $estRows.Count -gt 0) {
        Write-Host "[*] Resolving remote hosts..." -ForegroundColor Cyan
        $addresses = @($estRows | ForEach-Object { $_.RemoteAddress } | Sort-Object -Unique)
        $dnsResults = Invoke-RunspaceBatch -Items $addresses -ScriptBlock $DnsWorker `
            -ThrottleLimit $ThrottleLimit -Activity 'Reverse DNS'
        $dnsMap = @{}
        foreach ($d in $dnsResults) { $dnsMap[$d.Address] = $d.HostName }
        foreach ($row in $estRows) { $row.RemoteHost = [string]$dnsMap[$row.RemoteAddress] }
    }

    # --- Per-process summary ------------------------------------------------
    $procIds = @(@($listenRows) + @($udpRows) + @($estRows) + @($hiddenRows) | Where-Object { $null -ne $_.ProcessId } | ForEach-Object { [int]$_.ProcessId } | Sort-Object -Unique)
    $processRows = @(
        foreach ($procId in $procIds) {
            $owner = Get-OwnerInfo -ProcessId $procId
            $tcpL = @($listenRows | Where-Object { $_.ProcessId -eq $procId } | ForEach-Object { $_.Port } | Sort-Object -Unique)
            $udpL = @($udpRows    | Where-Object { $_.ProcessId -eq $procId } | ForEach-Object { $_.Port } | Sort-Object -Unique)
            $estC = ($estRows     | Where-Object { $_.ProcessId -eq $procId } | Measure-Object -Property Connections -Sum).Sum
            $hidL = @($hiddenRows | Where-Object { $_.ProcessId -eq $procId } | ForEach-Object { $_.Port } | Sort-Object -Unique)
            [PSCustomObject]@{
                ProcessId    = $procId
                ProcessName  = $owner.ProcessName
                Services     = $owner.Services
                TcpListening = $tcpL -join ', '
                UdpEndpoints = $udpL -join ', '
                HiddenPorts  = $hidL -join ', '
                TcpCount     = $tcpL.Count
                UdpCount     = $udpL.Count
                HiddenCount  = $hidL.Count
                Established  = [int]$estC
                Signature    = $owner.Signature
                ProcessPath  = $owner.ProcessPath
                CommandLine  = $owner.CommandLine
            }
        }
    ) | Sort-Object @{ Expression = { $_.TcpCount + $_.UdpCount + $_.HiddenCount }; Descending = $true },
                    @{ Expression = { $_.Established }; Descending = $true },
                    ProcessName
    $processRows = @($processRows)

    # --- Scan metadata for the report ---------------------------------------
    $scanInfo = @()
    if ($Passive) { $scanInfo += 'Mode: passive (no connections to local services)' } else { $scanInfo += 'Mode: full' }
    if (-not $DoActiveScan) { $scanInfo += 'Hidden-port scan: disabled' }
    else { $scanInfo += ("Hidden-port scan: {0} ports on {1}" -f $scannedCount, ($scanTargets -join ', ')) }
    if ($SkipUDP) { $scanInfo += 'UDP endpoints: skipped' }
    if (-not $script:NativeAvailable) { $scanInfo += 'Native helper unavailable: protected-process paths and AppContainer detection are approximate' }
    if ($NoFirewallCheck) { $scanInfo += 'Firewall: not checked' }
    elseif ($script:Fw.Available) {
        $fwLine = "Firewall ({0} inbound rules for active profiles) - {1}" -f $script:Fw.Rules.Count, $script:Fw.Summary
        if ($script:Fw.UnresolvedRules -gt 0) { $fwLine += " | $($script:Fw.UnresolvedRules) rules skipped (filters unreadable)" }
        $scanInfo += $fwLine
    }
    else { $scanInfo += "Firewall: query failed ($($script:Fw.Error))" }

    return [PSCustomObject]@{
        TcpListeners                = $listenRows
        HiddenPorts                 = @($hiddenRows)
        UdpEndpoints                = $udpRows
        Established                 = $estRows
        Processes                   = $processRows
        TotalEstablishedConnections = $established.Count
        ScanInfo                    = $scanInfo
    }
}

# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------
function New-HtmlTable {
    param(
        [string]$Title,
        [string]$Id,
        [string]$Description = '',
        [object[]]$Rows,
        [string[]]$Columns,
        [string[]]$MonoColumns = @(),
        [scriptblock]$RowClass
    )

    $sb = New-Object System.Text.StringBuilder
    $count = @($Rows).Count
    [void]$sb.AppendLine("<h2 id='$Id'>$(ConvertTo-SafeHtml $Title) <span class='count'>($count)</span></h2>")
    if ($Description) { [void]$sb.AppendLine("<p class='desc'>$(ConvertTo-SafeHtml $Description)</p>") }

    if ($count -eq 0) {
        [void]$sb.AppendLine("<p class='empty'>No entries.</p>")
        return $sb.ToString()
    }

    [void]$sb.Append("<div class='table-wrap'><table><thead><tr>")
    foreach ($col in $Columns) { [void]$sb.Append("<th>$(ConvertTo-SafeHtml $col)</th>") }
    [void]$sb.AppendLine("</tr></thead><tbody>")

    foreach ($row in $Rows) {
        $cls = ''
        if ($RowClass) { $cls = [string](& $RowClass $row) }
        [void]$sb.Append("<tr class='$cls'>")
        foreach ($col in $Columns) {
            $val = ConvertTo-SafeHtml $row.$col
            if ($MonoColumns -contains $col -and $val) { $val = "<pre class='mono'>$val</pre>" }
            [void]$sb.Append("<td>$val</td>")
        }
        [void]$sb.AppendLine("</tr>")
    }
    [void]$sb.AppendLine("</tbody></table></div>")
    return $sb.ToString()
}

function New-PortHunterReport {
    param([Parameter(Mandatory = $true)]$Data, [Parameter(Mandatory = $true)][string]$Path)

    $generated = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $computer  = ConvertTo-SafeHtml $env:COMPUTERNAME

    $exposed   = @($Data.TcpListeners | Where-Object { $_.Exposure -ne 'Loopback' }).Count
    $reachable = @($Data.TcpListeners | Where-Object { $_.FirewallStatus -eq 'Reachable' }).Count
    $scoped    = @($Data.TcpListeners | Where-Object { $_.FirewallStatus -eq 'Restricted' }).Count
    $sensitive = @(@($Data.TcpListeners) + @($Data.UdpEndpoints) | Where-Object { $_.Notes -clike 'SENSITIVE*' }).Count
    $hidden    = @($Data.HiddenPorts).Count
    $banners   = @(@($Data.TcpListeners) + @($Data.HiddenPorts) | Where-Object { $_.Banner -or $_.Tls }).Count
    $unsigned  = @($Data.Processes | Where-Object { $_.Signature -and $_.Signature -notlike 'Valid*' }).Count
    $sigText   = if ($NoSignatureCheck) { 'not checked' } else { [string]$unsigned }
    $fwText    = if ($NoFirewallCheck) { 'not checked' } else { [string]$reachable }
    $fwScoped  = if ($NoFirewallCheck) { 'not checked' } else { [string]$scoped }

    # Theme: light default, dark via OS preference or toggle (saved in localStorage)
    $css = @'
:root { color-scheme: light; --bg:#f5f5f5; --card:#fff; --fg:#2c3e50; --muted:#7f8c8d; --accent:#3498db; --row:#f8f9fa; --hover:#e8f4f8; --warn:#fdecea; --warnb:#e74c3c; --hid:#fff4e0; --hidb:#e67e22; --mono-bg:#2c3e50; --mono-fg:#ecf0f1; --border:rgba(128,128,128,.25); }
@media (prefers-color-scheme: dark) { :root:not([data-theme="light"]) { color-scheme: dark; --bg:#181818; --card:#222; --fg:#e6e6e6; --muted:#9a9a9a; --accent:#2e86c1; --row:#262626; --hover:#2d3a44; --warn:#3a1f1f; --warnb:#e74c3c; --hid:#3a2c14; --hidb:#e67e22; --mono-bg:#111; --mono-fg:#d0d0d0; --border:rgba(160,160,160,.2); } }
:root[data-theme="dark"] { color-scheme: dark; --bg:#181818; --card:#222; --fg:#e6e6e6; --muted:#9a9a9a; --accent:#2e86c1; --row:#262626; --hover:#2d3a44; --warn:#3a1f1f; --warnb:#e74c3c; --hid:#3a2c14; --hidb:#e67e22; --mono-bg:#111; --mono-fg:#d0d0d0; --border:rgba(160,160,160,.2); }
body { font-family:'Segoe UI',Arial,sans-serif; margin:20px; background:var(--bg); color:var(--fg); transition:background .2s,color .2s; }
a { color:var(--accent); }
.container { max-width:98%; margin:0 auto; background:var(--card); padding:20px; border-radius:8px; box-shadow:0 2px 10px rgba(0,0,0,.1); }
.topbar { display:flex; justify-content:space-between; align-items:flex-start; gap:12px; border-bottom:2px solid var(--accent); margin-bottom:10px; }
h1 { margin:0 0 10px 0; }
.theme-toggle { cursor:pointer; border:1px solid var(--border); background:var(--row); color:var(--fg); border-radius:18px; padding:6px 14px; font-size:14px; white-space:nowrap; }
.theme-toggle:hover { background:var(--hover); }
h2 { margin-top:30px; } .count { color:var(--muted); font-weight:normal; font-size:.8em; }
.meta { color:var(--muted); font-style:italic; text-align:right; margin:2px 0; }
.info { color:var(--muted); font-size:13px; margin:4px 0; }
.desc { color:var(--muted); font-size:13px; margin-top:-8px; }
nav.toc { margin:10px 0; font-size:14px; } nav.toc a { margin-right:14px; }
.summary { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:10px; margin:15px 0; }
.card { background:var(--row); border-radius:6px; padding:12px; } .card b { display:block; font-size:1.6em; }
.card.alert b { color:var(--warnb); } .card.hidden b { color:var(--hidb); }
.table-wrap { overflow-x:auto; }
table { width:100%; border-collapse:collapse; font-size:13px; }
th { background:var(--accent); color:#fff; padding:9px; text-align:left; white-space:nowrap; }
td { padding:8px; border-bottom:1px solid var(--border); vertical-align:top; word-break:break-word; }
tr:nth-child(even) { background:var(--row); } tr:hover { background:var(--hover); }
tr.exposed { background:var(--warn); } tr.exposed td:first-child { border-left:4px solid var(--warnb); }
tr.hidden { background:var(--hid); } tr.hidden td:first-child { border-left:4px solid var(--hidb); }
tr.unsigned td:first-child { border-left:4px solid #f39c12; }
pre.mono { font-family:Consolas,monospace; background:var(--mono-bg); color:var(--mono-fg); padding:6px; border-radius:3px; font-size:12px; max-width:520px; max-height:180px; overflow:auto; white-space:pre-wrap; margin:0; }
.empty { color:var(--muted); }
'@

    # Applied in <head> to avoid a flash of the wrong theme
    $jsHead = @'
(function(){try{var t=localStorage.getItem('porthunter-theme');if(t==='dark'||t==='light'){document.documentElement.setAttribute('data-theme',t);}}catch(e){}})();
'@

    $jsBody = @'
(function(){
  var KEY='porthunter-theme', root=document.documentElement, btn=document.getElementById('themeToggle');
  function current(){
    var t=root.getAttribute('data-theme');
    if(t==='dark'||t==='light'){return t;}
    return (window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches)?'dark':'light';
  }
  function label(){ btn.innerHTML = current()==='dark' ? '&#9728; Light theme' : '&#9790; Dark theme'; }
  btn.addEventListener('click',function(){
    var next=current()==='dark'?'light':'dark';
    root.setAttribute('data-theme',next);
    try{localStorage.setItem(KEY,next);}catch(e){}
    label();
  });
  if(window.matchMedia){
    var mq=window.matchMedia('(prefers-color-scheme: dark)');
    var onChange=function(){ if(!root.getAttribute('data-theme')){label();} };
    if(mq.addEventListener){mq.addEventListener('change',onChange);}else if(mq.addListener){mq.addListener(onChange);}
  }
  label();
})();
'@

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>")
    [void]$sb.AppendLine("<meta name='viewport' content='width=device-width, initial-scale=1'>")
    [void]$sb.AppendLine("<title>PortHunter Report - $computer - $generated</title>")
    [void]$sb.AppendLine("<script>$jsHead</script><style>$css</style></head><body><div class='container'>")

    [void]$sb.AppendLine("<div class='topbar'><h1>&#128737;&#65039; PortHunter - Port Scan Report</h1>")
    [void]$sb.AppendLine("<button id='themeToggle' class='theme-toggle' type='button' aria-label='Toggle light/dark theme'>Theme</button></div>")
    [void]$sb.AppendLine("<p class='meta'>Host: $computer | Generated: $generated</p>")
    [void]$sb.AppendLine("<p class='meta'><a href='https://github.com/Leproide/PortHunter'>https://github.com/Leproide/PortHunter</a> | Author: <a href='https://github.com/Leproide'>https://github.com/Leproide</a> | License: GPL-3.0</p>")
    foreach ($line in $Data.ScanInfo) { [void]$sb.AppendLine("<p class='info'>$(ConvertTo-SafeHtml $line)</p>") }

    [void]$sb.AppendLine("<nav class='toc'><a href='#hidden'>Hidden ports</a><a href='#tcp'>TCP listeners</a><a href='#udp'>UDP endpoints</a><a href='#est'>Established</a><a href='#proc'>Processes</a></nav>")

    [void]$sb.AppendLine("<div class='summary'>")
    [void]$sb.AppendLine("<div class='card$(if ($hidden -gt 0) { ' hidden' })'>Hidden ports (no visible listener)<b>$hidden</b></div>")
    [void]$sb.AppendLine("<div class='card$(if ($sensitive -gt 0) { ' alert' })'>Sensitive ports reachable/exposed<b>$sensitive</b></div>")
    [void]$sb.AppendLine("<div class='card'>TCP listeners (port+process)<b>$($Data.TcpListeners.Count)</b></div>")
    [void]$sb.AppendLine("<div class='card'>Bound to non-loopback<b>$exposed</b></div>")
    [void]$sb.AppendLine("<div class='card'>TCP open to any remote (firewall)<b>$fwText</b></div>")
    [void]$sb.AppendLine("<div class='card'>TCP scoped firewall allow<b>$fwScoped</b></div>")
    [void]$sb.AppendLine("<div class='card'>UDP endpoints (port+process)<b>$($Data.UdpEndpoints.Count)</b></div>")
    [void]$sb.AppendLine("<div class='card'>Established connections<b>$($Data.TotalEstablishedConnections)</b></div>")
    [void]$sb.AppendLine("<div class='card'>Processes with network activity<b>$($Data.Processes.Count)</b></div>")
    [void]$sb.AppendLine("<div class='card'>Banners / TLS info<b>$banners</b></div>")
    [void]$sb.AppendLine("<div class='card$(if ($unsigned -gt 0 -and -not $NoSignatureCheck) { ' alert' })'>Unsigned / invalid binaries<b>$sigText</b></div>")
    [void]$sb.AppendLine("</div>")

    $tcpClass = {
        param($r)
        if ($r.Notes -clike 'SENSITIVE*') { 'exposed' }
        elseif ($r.Signature -and $r.Signature -notlike 'Valid*') { 'unsigned' }
    }
    $unsignedClass = { param($r) if ($r.Signature -and $r.Signature -notlike 'Valid*') { 'unsigned' } }
    $hiddenClass = { param($r) 'hidden' }

    [void]$sb.Append((New-HtmlTable -Title 'Hidden Ports' -Id 'hidden' `
        -Description 'Ports that accept connections on loopback although no process owns a visible listening socket. Typical causes: VPN/WFP redirection, transparent proxies, port forwarding. The owner is identified through the peer socket of a test connection when the traffic is redirected to a local process.' `
        -Rows $Data.HiddenPorts `
        -Columns @('Port', 'Target', 'KnownService', 'ProcessId', 'ProcessName', 'Correlation', 'BannerStatus', 'Tls', 'Banner', 'Signature', 'ProcessPath') `
        -MonoColumns @('Banner') -RowClass $hiddenClass))

    [void]$sb.Append((New-HtmlTable -Title 'TCP Listening Ports' -Id 'tcp' `
        -Description 'Grouped by port and owning process. Firewall evaluation is approximate: enabled inbound rules of the active store for the active profiles (protocol, local port, program, service, package) with block-over-allow precedence, then default inbound action. Rules limited by remote/local address, interface type or interface are shown as scoped; AppContainer rules apply only to AppContainer processes. Edge traversal and IPsec conditions are not evaluated.' `
        -Rows $Data.TcpListeners `
        -Columns @('Port', 'Addresses', 'Exposure', 'KnownService', 'ProcessId', 'ProcessName', 'Services', 'Firewall', 'Notes', 'BannerStatus', 'Tls', 'Banner', 'Signature', 'ProcessPath') `
        -MonoColumns @('Banner') -RowClass $tcpClass))

    [void]$sb.Append((New-HtmlTable -Title 'UDP Endpoints' -Id 'udp' `
        -Description 'Grouped by port and owning process. Not probed: UDP probes are unreliable.' `
        -Rows $Data.UdpEndpoints `
        -Columns @('Port', 'Addresses', 'Exposure', 'KnownService', 'ProcessId', 'ProcessName', 'Services', 'Firewall', 'Notes', 'Signature', 'ProcessPath') `
        -RowClass $tcpClass))

    $estTitle = 'Established TCP Connections'
    if (-not $IncludeLoopbackConnections) { $estTitle += ' (loopback excluded)' }
    [void]$sb.Append((New-HtmlTable -Title $estTitle -Id 'est' `
        -Rows $Data.Established `
        -Columns @('ProcessId', 'ProcessName', 'RemoteAddress', 'RemotePort', 'RemoteHost', 'Connections', 'LocalPorts', 'Signature', 'ProcessPath') `
        -RowClass $unsignedClass))

    [void]$sb.Append((New-HtmlTable -Title 'Process Summary' -Id 'proc' `
        -Rows $Data.Processes `
        -Columns @('ProcessId', 'ProcessName', 'Services', 'TcpListening', 'UdpEndpoints', 'HiddenPorts', 'Established', 'Signature', 'ProcessPath', 'CommandLine') `
        -MonoColumns @('CommandLine') -RowClass $unsignedClass))

    [void]$sb.AppendLine("</div><script>$jsBody</script></body></html>")

    # Write as UTF-8 without BOM
    [System.IO.File]::WriteAllText($Path, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
try {
    $line = '=' * 60
    Write-Host $line -ForegroundColor Magenta
    Write-Host " PortHunter - https://github.com/Leproide/PortHunter" -ForegroundColor Magenta
    Write-Host $line -ForegroundColor Magenta

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $data = Start-PortHunterScan

    # Resolve relative paths against the current PowerShell location
    $reportPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
    Write-Host "[*] Generating HTML report..." -ForegroundColor Cyan
    New-PortHunterReport -Data $data -Path $reportPath
    $stopwatch.Stop()

    Write-Host "`n$line" -ForegroundColor Green
    Write-Host " SCAN COMPLETED in $([Math]::Round($stopwatch.Elapsed.TotalSeconds, 1)) s" -ForegroundColor Green
    Write-Host $line -ForegroundColor Green
    Write-Host ("  TCP listeners          : {0}" -f $data.TcpListeners.Count) -ForegroundColor Cyan
    Write-Host ("  Hidden ports           : {0}" -f $data.HiddenPorts.Count) -ForegroundColor Cyan
    Write-Host ("  UDP endpoints          : {0}" -f $data.UdpEndpoints.Count) -ForegroundColor Cyan
    Write-Host ("  Established connections: {0}" -f $data.TotalEstablishedConnections) -ForegroundColor Cyan
    Write-Host ("  Processes              : {0}" -f $data.Processes.Count) -ForegroundColor Cyan
    Write-Host ("  Report                 : {0}" -f $reportPath) -ForegroundColor Yellow

    # Console output is kept to short fixed-width lines: full details are in the report
    if ($data.HiddenPorts.Count -gt 0) {
        Write-Host "`n[!] Hidden ports (open on loopback, no visible listener):" -ForegroundColor DarkYellow
        foreach ($h in $data.HiddenPorts) {
            $why = ([string]$h.Correlation -split ' \| ')[0]
            if ($why.Length -gt 60) { $why = $why.Substring(0, 57) + '...' }
            Write-Host ("  {0,5}/tcp  {1,-16} {2,-22} {3}" -f $h.Port, $h.KnownService, $h.ProcessName, $why)
        }
    }

    $risky = @(@($data.TcpListeners) + @($data.UdpEndpoints) | Where-Object { $_.Notes -clike 'SENSITIVE*' })
    if ($risky.Count -gt 0) {
        Write-Host "`n[!] Sensitive ports reachable/exposed:" -ForegroundColor Red
        foreach ($r in $risky) {
            $proto = 'tcp'
            if (@($data.UdpEndpoints) -contains $r) { $proto = 'udp' }
            Write-Host ("  {0,5}/{1}  {2,-16} {3,-24} {4}" -f $r.Port, $proto, $r.KnownService, $r.ProcessName, $r.FirewallStatus)
        }
    }

    if ($OpenReport) {
        Start-Process -FilePath $reportPath
    } elseif (-not $NoPrompt) {
        $answer = Read-Host "`nOpen the HTML report now? (Y/N)"
        if ($answer -match '^(y|yes|s|si)$') { Start-Process -FilePath $reportPath }
    }
} catch {
    Write-Error "Script execution failed: $($_.Exception.Message)"
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
    exit 1
}
