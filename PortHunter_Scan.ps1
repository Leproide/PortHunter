<#
PortHunter
leproide@paranoici.org

.SYNOPSIS
    Estabilished connection: Port, Process and Service Scanner with HTML Report
.DESCRIPTION
    Scans all open TCP/UDP ports, correlates with processes, extracts file paths,
    and reads service banners to identify services. Generates a detailed HTML report.
.AUTHOR
    PowerShell Script
.NOTES
    Requires Administrator privileges for complete information
    PowerShell 7+ recommended for parallel processing
#>

# Require Admin privileges
param(
    [switch]$NoAdminCheck = $false
)

# Check for Administrator privileges 
if (-not $NoAdminCheck) {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Warning "This script requires Administrator privileges for complete information!"
        Write-Host "Please run PowerShell as Administrator and execute the script again." -ForegroundColor Yellow
        exit 1
    }
}

# HTML Report Styling
$HTMLHeader = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Port Scan Report - $(Get-Date)</title>
    <style>
        body { 
            font-family: 'Segoe UI', Arial, sans-serif; 
            margin: 20px; 
            background-color: #f5f5f5;
            color: #333;
        }
        .container { 
            max-width: 95%; 
            margin: 0 auto; 
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 { 
            color: #2c3e50; 
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }
        h2 { 
            color: #34495e; 
            margin-top: 25px;
        }
        .summary { 
            background: #ecf0f1; 
            padding: 15px; 
            border-radius: 5px; 
            margin: 15px 0; 
        }
        table { 
            width: 100%; 
            border-collapse: collapse; 
            margin: 15px 0;
            font-size: 14px;
        }
        th { 
            background: #3498db; 
            color: white; 
            padding: 12px; 
            text-align: left;
            font-weight: 600;
        }
        td { 
            padding: 10px; 
            border-bottom: 1px solid #ddd;
            vertical-align: top;
        }
        tr:nth-child(even) { 
            background-color: #f8f9fa; 
        }
        tr:hover { 
            background-color: #e8f4f8; 
        }
        .tcp { 
            border-left: 4px solid #27ae60; 
        }
        .udp { 
            border-left: 4px solid #e74c3c; 
        }
        .warning { 
            background: #fff3cd; 
            border-left: 4px solid #ffc107; 
            padding: 10px;
            margin: 10px 0;
        }
        .banner { 
            font-family: Consolas, monospace; 
            background: #2c3e50; 
            color: #ecf0f1; 
            padding: 8px; 
            border-radius: 3px;
            font-size: 12px;
            max-width: 400px;
            word-break: break-all;
        }
        .timestamp { 
            color: #7f8c8d; 
            font-style: italic;
            text-align: right;
        }
        .section { 
            margin-bottom: 30px; 
        }
        .protocol-badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
            color: white;
        }
        .tcp-badge { background: #27ae60; }
        .udp-badge { background: #e74c3c; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ PortHunter - Active Port Scan Report</h1>
        <div class="timestamp">https://github.com/Leproide/PortHunter</div>
        <div class="timestamp">Generated on: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</div>
"@

$HTMLFooter = @"
    </div>
</body>
</html>
"@

# Banner grabbing function with multiple protocol support
function Get-ServiceBanner {
    param(
        [string]$ComputerName = "127.0.0.1",
        [int]$Port,
        [string]$Protocol = "TCP",
        [int]$TimeoutMs = 3000
    )
    
    $banner = ""
    $maxReadSize = 1024
    
    try {
        if ($Protocol -eq "TCP") {
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $connectAsync = $tcpClient.BeginConnect($ComputerName, $Port, $null, $null)
            
            if ($connectAsync.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
                $tcpClient.EndConnect($connectAsync)
                $stream = $tcpClient.GetStream()
                $stream.ReadTimeout = $TimeoutMs
                
                # Send common protocol-specific probes
                $probes = @{
                    "21" = "SYST`r`n"    # FTP
                    "22" = "SSH-2.0-PowerShellBannerGrab`r`n"  # SSH
                    "25" = "EHLO example.com`r`n"  # SMTP
                    "80" = "HEAD / HTTP/1.1`r`nHost: $ComputerName`r`n`r`n"  # HTTP
                    "110" = "CAPA`r`n"   # POP3
                    "143" = "CAPABILITY`r`n"  # IMAP
                    "443" = "HEAD / HTTP/1.1`r`nHost: $ComputerName`r`n`r`n" # HTTPS
                    "587" = "EHLO example.com`r`n"  # SMTP Submission
                    "993" = "CAPABILITY`r`n"  # IMAPS
                    "995" = "CAPA`r`n"   # POP3S
                    "3389" = ""  # RDP - no probe needed
                }
                
                if ($probes.ContainsKey($Port.ToString())) {
                    $probe = $probes[$Port.ToString()]
                    if ($probe -ne "") {
                        $data = [System.Text.Encoding]::ASCII.GetBytes($probe)
                        $stream.Write($data, 0, $data.Length)
                        $stream.Flush()
                        Start-Sleep -Milliseconds 500
                    }
                } else {
                    # Generic probe for unknown ports
                    $genericProbe = "HELP`r`n"
                    $data = [System.Text.Encoding]::ASCII.GetBytes($genericProbe)
                    $stream.Write($data, 0, $data.Length)
                    $stream.Flush()
                    Start-Sleep -Milliseconds 500
                }
                
                # Read response
                if ($stream.DataAvailable) {
                    $buffer = New-Object byte[] $maxReadSize
                    $bytesRead = $stream.Read($buffer, 0, $buffer.Length)
                    if ($bytesRead -gt 0) {
                        $banner = [System.Text.Encoding]::ASCII.GetString($buffer, 0, $bytesRead)
                        # Clean up the banner
                        $banner = $banner -replace "[^\x20-\x7E\r\n\t]", "?"
                        $banner = $banner.Trim()
                    }
                }
                
                $tcpClient.Close()
            }
        } else {
            # UDP banner grabbing (limited)
            $udpClient = New-Object System.Net.Sockets.UdpClient
            $udpClient.Client.ReceiveTimeout = $TimeoutMs
            
            try {
                # Send empty packet to trigger response
                $udpClient.Connect($ComputerName, $Port)
                $sendBytes = [System.Text.Encoding]::ASCII.GetBytes("")
                $udpClient.Send($sendBytes, $sendBytes.Length) | Out-Null
                
                $remoteEndpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
                $receiveBytes = $udpClient.Receive([ref]$remoteEndpoint)
                $banner = [System.Text.Encoding]::ASCII.GetString($receiveBytes)
                $banner = "UDP Response: " + ($banner -replace "[^\x20-\x7E\r\n\t]", "?").Trim()
            } catch {
                $banner = "UDP: No response or connection refused"
            } finally {
                $udpClient.Close()
            }
        }
    } catch {
        $banner = "Error: $($_.Exception.Message)"
    }
    
    if ([string]::IsNullOrWhiteSpace($banner)) {
        $banner = "No banner received or service didn't respond"
    }
    
    return $banner
}

# Enhanced port scanning function
function Test-PortEnhanced {
    param(
        [string]$ComputerName = "127.0.0.1",
        [int]$Port,
        [string]$Protocol = "TCP",
        [int]$TimeoutMs = 1000
    )
    
    $result = [PSCustomObject]@{
        Port = $Port
        Protocol = $Protocol
        Status = "Closed"
        Banner = ""
        ResponseTime = $null
    }
    
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    
    try {
        if ($Protocol -eq "TCP") {
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $connectAsync = $tcpClient.BeginConnect($ComputerName, $Port, $null, $null)
            
            if ($connectAsync.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
                $tcpClient.EndConnect($connectAsync)
                $result.Status = "Open"
                $stopwatch.Stop()
                $result.ResponseTime = $stopwatch.ElapsedMilliseconds
                
                # Try to get banner
                $result.Banner = Get-ServiceBanner -ComputerName $ComputerName -Port $Port -Protocol TCP -TimeoutMs 2000
                
                $tcpClient.Close()
            } else {
                $result.Status = "Filtered/Timeout"
            }
        } else {
            # UDP testing
            $udpClient = New-Object System.Net.Sockets.UdpClient
            $udpClient.Client.ReceiveTimeout = $TimeoutMs
            
            try {
                $udpClient.Connect($ComputerName, $Port)
                $sendBytes = [System.Text.Encoding]::ASCII.GetBytes("UDP Probe")
                $udpClient.Send($sendBytes, $sendBytes.Length) | Out-Null
                
                $remoteEndpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
                $receiveBytes = $udpClient.Receive([ref]$remoteEndpoint)
                $result.Status = "Open"
                $stopwatch.Stop()
                $result.ResponseTime = $stopwatch.ElapsedMilliseconds
                $result.Banner = "UDP Response received"
            } catch [System.Net.Sockets.SocketException] {
                if ($_.Exception.SocketErrorCode -eq [System.Net.Sockets.SocketError]::TimedOut) {
                    $result.Status = "Open|Filtered"
                } else {
                    $result.Status = "Closed"
                }
            } catch {
                $result.Status = "Error: $($_.Exception.Message)"
            } finally {
                $udpClient.Close()
            }
        }
    } catch {
        $result.Status = "Error: $($_.Exception.Message)"
    }
    
    return $result
}

# Get well-known service names
function Get-ServiceNameByPort {
    param([int]$Port, [string]$Protocol = "TCP")
    
    $commonServices = @{
        "TCP" = @{
            21 = "FTP"; 22 = "SSH"; 23 = "Telnet"; 25 = "SMTP"; 53 = "DNS"; 80 = "HTTP"
            110 = "POP3"; 143 = "IMAP"; 443 = "HTTPS"; 993 = "IMAPS"; 995 = "POP3S"
            1433 = "MSSQL"; 3306 = "MySQL"; 3389 = "RDP"; 5432 = "PostgreSQL"
            5900 = "VNC"; 6379 = "Redis"; 27017 = "MongoDB"
        }
        "UDP" = @{
            53 = "DNS"; 67 = "DHCP Server"; 68 = "DHCP Client"; 69 = "TFTP"; 123 = "NTP"
            161 = "SNMP"; 514 = "Syslog"; 1900 = "UPnP"; 5353 = "mDNS"
        }
    }
    
    return $commonServices[$Protocol][$Port]
}

# Main scanning function
function Start-ComprehensivePortScan {
    Write-Host "🚀 Starting Comprehensive Port Scan..." -ForegroundColor Green
    Write-Host "⏰ This may take several minutes..." -ForegroundColor Yellow
    
    $results = @()
    $totalPortsScanned = 0
    
    # Get current network connections and processes first
    Write-Host "`n📊 Gathering active network connections and processes..." -ForegroundColor Cyan
    
    # TCP Connections with processes
    $tcpConnections = Get-NetTCPConnection -ErrorAction SilentlyContinue | 
        Where-Object { $_.State -eq 'Listen' -or $_.State -eq 'Established' }
    
    $activePorts = @()
    
    foreach ($conn in $tcpConnections) {
        $process = $null
        $processPath = ""
        
        try {
            $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            $processPath = $process.Path
        } catch {
            $processPath = "Access Denied or Process Terminated"
        }
        
        $serviceName = Get-ServiceNameByPort -Port $conn.LocalPort -Protocol "TCP"
        
        $activePorts += [PSCustomObject]@{
            Protocol = "TCP"
            LocalPort = $conn.LocalPort
            State = $conn.State
            ProcessId = $conn.OwningProcess
            ProcessName = if ($process) { $process.ProcessName } else { "N/A" }
            ProcessPath = $processPath
            ServiceName = $serviceName
            Banner = ""
            Source = "NetTCPConnection"
        }
    }
    
    # UDP Connections
    $udpConnections = Get-NetUDPEndpoint -ErrorAction SilentlyContinue
    
    foreach ($conn in $udpConnections) {
        $process = $null
        $processPath = ""
        
        try {
            $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            $processPath = $process.Path
        } catch {
            $processPath = "Access Denied or Process Terminated"
        }
        
        $serviceName = Get-ServiceNameByPort -Port $conn.LocalPort -Protocol "UDP"
        
        $activePorts += [PSCustomObject]@{
            Protocol = "UDP"
            LocalPort = $conn.LocalPort
            State = "Listen"
            ProcessId = $conn.OwningProcess
            ProcessName = if ($process) { $process.ProcessName } else { "N/A" }
            ProcessPath = $processPath
            ServiceName = $serviceName
            Banner = ""
            Source = "NetUDPEndpoint"
        }
    }
    
    Write-Host "✅ Found $($activePorts.Count) active network connections" -ForegroundColor Green
    
    # Scan common ports for additional discovery and banner grabbing
    $commonPorts = @(
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 
        1433, 1723, 3306, 3389, 5432, 5900, 8080, 8443
    )
    
    Write-Host "`n🔍 Scanning common ports for banners and additional services..." -ForegroundColor Cyan
    
    $scanResults = @()
    
    foreach ($port in $commonPorts) {
        Write-Progress -Activity "Port Scanning" -Status "Scanning port $port" -PercentComplete (($commonPorts.IndexOf($port) / $commonPorts.Count) * 100)
        
        # Check if we already have this port in active connections
        $existingPort = $activePorts | Where-Object { $_.LocalPort -eq $port -and $_.Protocol -eq "TCP" }
        
        if (-not $existingPort) {
            $tcpResult = Test-PortEnhanced -Port $port -Protocol "TCP" -TimeoutMs 1500
            $udpResult = Test-PortEnhanced -Port $port -Protocol "UDP" -TimeoutMs 1500
            
            if ($tcpResult.Status -eq "Open") {
                $serviceName = Get-ServiceNameByPort -Port $port -Protocol "TCP"
                $scanResults += [PSCustomObject]@{
                    Protocol = "TCP"
                    LocalPort = $port
                    State = "Open"
                    ProcessId = $null
                    ProcessName = "Unknown"
                    ProcessPath = ""
                    ServiceName = $serviceName
                    Banner = $tcpResult.Banner
                    Source = "PortScan"
                }
            }
            
            if ($udpResult.Status -eq "Open") {
                $serviceName = Get-ServiceNameByPort -Port $port -Protocol "UDP"
                $scanResults += [PSCustomObject]@{
                    Protocol = "UDP"
                    LocalPort = $port
                    State = "Open"
                    ProcessId = $null
                    ProcessName = "Unknown"
                    ProcessPath = ""
                    ServiceName = $serviceName
                    Banner = $udpResult.Banner
                    Source = "PortScan"
                }
            }
        }
        $totalPortsScanned++
    }
    
    # Combine results
    $allResults = $activePorts + $scanResults
    
    # Enhance with banner grabbing for ports without banners
    Write-Host "`n📡 Grabbing service banners..." -ForegroundColor Cyan
    $enhancedResults = @()
    $counter = 0
    
    foreach ($result in $allResults) {
        $counter++
        Write-Progress -Activity "Banner Grabbing" -Status "Port $($result.LocalPort)/$($result.Protocol)" -PercentComplete (($counter / $allResults.Count) * 100)
        
        if ([string]::IsNullOrEmpty($result.Banner) -or $result.Banner -eq "No banner received or service didn't respond") {
            if ($result.State -eq "Listen" -or $result.State -eq "Open") {
                $banner = Get-ServiceBanner -Port $result.LocalPort -Protocol $result.Protocol -TimeoutMs 2000
                $result.Banner = $banner
            }
        }
        $enhancedResults += $result
    }
    
    Write-Progress -Activity "Banner Grabbing" -Completed
    
    return $enhancedResults
}

# Generate HTML Report
function New-PortScanHTMLReport {
    param(
        [array]$ScanResults,
        [string]$OutputPath = "PortScanReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    )
    
    Write-Host "`n📊 Generating HTML Report..." -ForegroundColor Cyan
    
    # Summary Statistics
    $totalPorts = $ScanResults.Count
    $tcpPorts = ($ScanResults | Where-Object { $_.Protocol -eq 'TCP' }).Count
    $udpPorts = ($ScanResults | Where-Object { $_.Protocol -eq 'UDP' }).Count
    $uniqueProcesses = ($ScanResults | Where-Object { $_.ProcessId -ne $null } | Group-Object ProcessId).Count
    $portsWithBanners = ($ScanResults | Where-Object { $_.Banner -ne "" -and $_.Banner -ne "No banner received or service didn't respond" -and $_.Banner -notlike "Error:*" }).Count
    
    $summaryHTML = @"
        <div class="summary">
            <h3>📈 Scan Summary</h3>
            <p><strong>Total Open Ports:</strong> $totalPorts</p>
            <p><strong>TCP Ports:</strong> $tcpPorts</p>
            <p><strong>UDP Ports:</strong> $udpPorts</p>
            <p><strong>Unique Processes:</strong> $uniqueProcesses</p>
            <p><strong>Ports with Banners:</strong> $portsWithBanners</p>
            <p><strong>Report Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
        </div>
"@

    # TCP Ports Table
    $tcpResults = $ScanResults | Where-Object { $_.Protocol -eq 'TCP' } | Sort-Object LocalPort
    $tcpTableHTML = $tcpResults | ConvertTo-Html -Fragment -PreContent "<h3>🔄 TCP Ports</h3>" | Out-String
    $tcpTableHTML = $tcpTableHTML -replace '<table>', '<table class="tcp">'
    $tcpTableHTML = $tcpTableHTML -replace '<td>TCP</td>', '<td><span class="protocol-badge tcp-badge">TCP</span></td>'
    
    # UDP Ports Table
    $udpResults = $ScanResults | Where-Object { $_.Protocol -eq 'UDP' } | Sort-Object LocalPort
    $udpTableHTML = $udpResults | ConvertTo-Html -Fragment -PreContent "<h3>🔊 UDP Ports</h3>" | Out-String
    $udpTableHTML = $udpTableHTML -replace '<table>', '<table class="udp">'
    $udpTableHTML = $udpTableHTML -replace '<td>UDP</td>', '<td><span class="protocol-badge udp-badge">UDP</span></td>'
    
    # Process Summary
    $processSummary = $ScanResults | 
        Where-Object { $_.ProcessId -ne $null } |
        Group-Object ProcessId | 
        ForEach-Object {
            $process = $_.Group[0]
            $ports = $_.Group | ForEach-Object { "$($_.LocalPort)/$($_.Protocol)" }
            [PSCustomObject]@{
                ProcessId = $process.ProcessId
                ProcessName = $process.ProcessName
                ProcessPath = $process.ProcessPath
                Ports = ($ports -join ", ")
                PortCount = $_.Count
            }
        } | Sort-Object PortCount -Descending
    
    $processTableHTML = $processSummary | ConvertTo-Html -Fragment -PreContent "<h3>⚙️ Process Summary</h3>" | Out-String
    
    # Banner Information
    $banners = $ScanResults | 
        Where-Object { $_.Banner -ne "" -and $_.Banner -ne "No banner received or service didn't respond" -and $_.Banner -notlike "Error:*" } |
        Select-Object Protocol, LocalPort, ServiceName, Banner |
        Sort-Object Protocol, LocalPort
    
    $bannerTableHTML = $banners | ConvertTo-Html -Fragment -PreContent "<h3>🚩 Service Banners</h3>" | Out-String
    $bannerTableHTML = $bannerTableHTML -replace '<td>(.*?)</td>', '<td><div class="banner">$1</div></td>'
    
    # Combine all HTML content
    $fullHTML = $HTMLHeader + $summaryHTML + $tcpTableHTML + $udpTableHTML + $processTableHTML + $bannerTableHTML + $HTMLFooter
    
    # Save to file
    $fullHTML | Out-File -FilePath $OutputPath -Encoding UTF8
    
    return $OutputPath
}

# Main execution
try {
    Write-Host "🛡️ COMPREHENSIVE PORT SCANNER" -ForegroundColor Magenta
    Write-Host "=" * 50 -ForegroundColor Magenta
    
    # Perform scan
    $scanResults = Start-ComprehensivePortScan
    
    # Generate report
    $reportPath = New-PortScanHTMLReport -ScanResults $scanResults
    
    # Display summary
    Write-Host "`n✅ SCAN COMPLETED SUCCESSFULLY!" -ForegroundColor Green
    Write-Host "=" * 50 -ForegroundColor Green
    Write-Host "📋 Scan Results Summary:" -ForegroundColor White
    Write-Host "   • Total ports found: $($scanResults.Count)" -ForegroundColor Cyan
    Write-Host "   • TCP ports: $(($scanResults | Where-Object { $_.Protocol -eq 'TCP' }).Count)" -ForegroundColor Cyan
    Write-Host "   • UDP ports: $(($scanResults | Where-Object { $_.Protocol -eq 'UDP' }).Count)" -ForegroundColor Cyan
    Write-Host "   • Unique processes: $(($scanResults | Where-Object { $_.ProcessId -ne $null } | Group-Object ProcessId).Count)" -ForegroundColor Cyan
    Write-Host "   • Report saved: $reportPath" -ForegroundColor Yellow
    
    # Show some interesting findings
    $interestingPorts = $scanResults | Where-Object { 
        $_.LocalPort -in @(21, 22, 23, 80, 443, 3389, 5900) -and 
        ($_.State -eq 'Listen' -or $_.State -eq 'Open') 
    }
    
    if ($interestingPorts) {
        Write-Host "`n🔍 Interesting Ports Found:" -ForegroundColor Yellow
        $interestingPorts | Format-Table Protocol, LocalPort, ServiceName, ProcessName -AutoSize
    }
    
    # Open the report automatically
    $openReport = Read-Host "`nDo you want to open the HTML report now? (Y/N)"
    if ($openReport -eq 'Y' -or $openReport -eq 'y') {
        Start-Process $reportPath
        Write-Host "📂 Opening report in default browser..." -ForegroundColor Green
    }
    
} catch {
    Write-Error "Script execution failed: $($_.Exception.Message)"
    Write-Host "Full error details:" -ForegroundColor Red
    Write-Host $_.Exception.StackTrace -ForegroundColor Red
}

Write-Host "`nScript execution completed." -ForegroundColor Gray
