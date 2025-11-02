<#
PortHunter
leproide@paranoici.org

.SYNOPSIS
    Advanced Port and Process Scanner with Active Connection Analysis
.DESCRIPTION
    Scans open ports and uses multiple advanced techniques to precisely correlate 
    ports with processes, including active connection tracking and handle analysis.
.AUTHOR
    PowerShell Script
.NOTES
    Requires Administrator privileges for complete process correlation
#>

# Require Admin privileges
param(
    [switch]$SkipUDP = $false,
    [switch]$FastScan = $true
)

# Check for Administrator privileges
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Administrator privileges required for accurate process correlation!"
    Write-Host "Some process information may be incomplete without admin rights." -ForegroundColor Yellow
}

# HTML Report Styling
$HTMLHeader = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Advanced Port Process Scanner - $(Get-Date)</title>
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
        .summary { 
            background: #ecf0f1; 
            padding: 15px; 
            border-radius: 5px; 
            margin: 15px 0; 
        }
        .timestamp { 
            color: #7f8c8d; 
            font-style: italic;
            text-align: right;
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
        .critical { 
            background: #f8d7da; 
            border-left: 4px solid #dc3545; 
            padding: 15px;
            margin: 15px 0;
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
        .process-details {
            background: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            margin: 5px 0;
        }
        .confidence-high { color: #27ae60; font-weight: bold; }
        .confidence-medium { color: #f39c12; font-weight: bold; }
        .confidence-low { color: #e74c3c; font-weight: bold; }
        .method-badge {
            display: inline-block;
            padding: 2px 6px;
            border-radius: 8px;
            font-size: 10px;
            background: #95a5a6;
            color: white;
            margin: 1px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ PortHunter - Advanced Port & Process Correlation Report</h1>
        <div class="timestamp">https://github.com/Leproide/PortHunter</div>
        <div class="timestamp">Generated on: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</div>
"@

$HTMLFooter = @"
    </div>
</body>
</html>
"@

# High-risk ports for special attention
$HighRiskPorts = @(21, 22, 23, 25, 53, 135, 139, 443, 445, 993, 995, 1433, 3389, 5900, 6379, 27017)

# Service name mapping
function Get-ServiceNameByPort {
    param([int]$Port, [string]$Protocol = "TCP")
    
    $commonServices = @{
        "TCP" = @{
            21 = "FTP"; 22 = "SSH"; 23 = "Telnet"; 25 = "SMTP"; 53 = "DNS"; 80 = "HTTP"
            110 = "POP3"; 135 = "RPC"; 139 = "NetBIOS"; 143 = "IMAP"; 443 = "HTTPS"; 445 = "SMB"
            993 = "IMAPS"; 995 = "POP3S"; 1433 = "MSSQL"; 1723 = "PPTP"; 3306 = "MySQL"
            3389 = "RDP"; 5432 = "PostgreSQL"; 5900 = "VNC"; 6379 = "Redis"; 27017 = "MongoDB"
            8080 = "HTTP-Alt"; 8443 = "HTTPS-Alt"
        }
        "UDP" = @{
            53 = "DNS"; 67 = "DHCP Server"; 68 = "DHCP Client"; 69 = "TFTP"; 123 = "NTP"
            161 = "SNMP"; 514 = "Syslog"; 1900 = "UPnP"; 5353 = "mDNS"
        }
    }
    
    return $commonServices[$Protocol][$Port]
}

# Advanced process correlation using multiple methods
function Get-ProcessByPortAdvanced {
    param([int]$Port, [string]$Protocol = "TCP")
    
    $results = @{
        ProcessId = $null
        ProcessName = "Unknown"
        ProcessPath = ""
        Confidence = "Low"
        MethodsUsed = @()
        AdditionalInfo = ""
    }
    
    # Method 1: NetStat TCP/UDP connections (Most reliable for listening ports)
    try {
        if ($Protocol -eq "TCP") {
            $tcpConn = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue | 
                       Where-Object { $_.State -eq 'Listen' } | Select-Object -First 1
            if ($tcpConn -and $tcpConn.OwningProcess) {
                $process = Get-Process -Id $tcpConn.OwningProcess -ErrorAction SilentlyContinue
                if ($process) {
                    $results.ProcessId = $process.Id
                    $results.ProcessName = $process.ProcessName
                    $results.ProcessPath = $process.Path
                    $results.Confidence = "High"
                    $results.MethodsUsed += "NetStat"
                    return $results
                }
            }
        } else {
            $udpConn = Get-NetUDPEndpoint -LocalPort $Port -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($udpConn -and $udpConn.OwningProcess) {
                $process = Get-Process -Id $udpConn.OwningProcess -ErrorAction SilentlyContinue
                if ($process) {
                    $results.ProcessId = $process.Id
                    $results.ProcessName = $process.ProcessName
                    $results.ProcessPath = $process.Path
                    $results.Confidence = "High"
                    $results.MethodsUsed += "NetStat"
                    return $results
                }
            }
        }
    } catch { }

    # Method 2: Active connection test (Your suggested method)
    try {
        if ($Protocol -eq "TCP") {
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $connectAsync = $tcpClient.BeginConnect("127.0.0.1", $Port, $null, $null)
            
            if ($connectAsync.AsyncWaitHandle.WaitOne(1000, $false)) {
                $tcpClient.EndConnect($connectAsync)
                
                # Get network connections while our connection is active
                $activeConns = Get-NetTCPConnection -LocalPort $Port -State Established -ErrorAction SilentlyContinue
                $ourConnection = $activeConns | Where-Object { $_.RemotePort -ne $null } | Select-Object -First 1
                
                if ($ourConnection -and $ourConnection.OwningProcess) {
                    $process = Get-Process -Id $ourConnection.OwningProcess -ErrorAction SilentlyContinue
                    if ($process) {
                        $results.ProcessId = $process.Id
                        $results.ProcessName = $process.ProcessName
                        $results.ProcessPath = $process.Path
                        $results.Confidence = "High"
                        $results.MethodsUsed += "ActiveConnection"
                        $results.AdditionalInfo = "Verified via active connection"
                    }
                }
                
                $tcpClient.Close()
                
                if ($results.ProcessId) {
                    return $results
                }
            }
            $tcpClient.Close()
        }
    } catch { }

    # Method 3: Handle analysis (requires admin privileges)
    try {
        if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            # Use netstat with process IDs
            $netstatOutput = netstat -ano | Select-String ":$Port\s+"
            foreach ($line in $netstatOutput) {
                if ($line -match '\s+(\d+)$') {
                    $pidFromNetstat = $matches[1]
                    $process = Get-Process -Id $pidFromNetstat -ErrorAction SilentlyContinue
                    if ($process) {
                        $results.ProcessId = $process.Id
                        $results.ProcessName = $process.ProcessName
                        $results.ProcessPath = $process.Path
                        $results.Confidence = "Medium"
                        $results.MethodsUsed += "HandleAnalysis"
                        return $results
                    }
                }
            }
        }
    } catch { }

    # Method 4: Process port mapping using Get-NetworkStatistics (alternative)
    try {
        $networkStats = Get-NetworkStatistics -ErrorAction SilentlyContinue
        $matchingProc = $networkStats | Where-Object { $_.LocalPort -eq $Port -and $_.Protocol -eq $Protocol } | Select-Object -First 1
        if ($matchingProc -and $matchingProc.ProcessId) {
            $process = Get-Process -Id $matchingProc.ProcessId -ErrorAction SilentlyContinue
            if ($process) {
                $results.ProcessId = $process.Id
                $results.ProcessName = $process.ProcessName
                $results.ProcessPath = $process.Path
                $results.Confidence = "Medium"
                $results.MethodsUsed += "NetworkStatistics"
                return $results
            }
        }
    } catch { }

    return $results
}

# Enhanced banner grabbing - CORRETTA
function Get-ServiceBanner {
    param([int]$Port, [string]$Protocol = "TCP", [int]$TimeoutMs = 3000)
    
    if ($Protocol -ne "TCP") { return "UDP - Banner grabbing not supported" }
    
    $banner = ""
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $connectAsync = $tcpClient.BeginConnect("127.0.0.1", $Port, $null, $null)
        
        if ($connectAsync.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
            $tcpClient.EndConnect($connectAsync)
            $stream = $tcpClient.GetStream()
            $stream.ReadTimeout = $TimeoutMs
            
            # Protocol-specific probes
            $probes = @{
                "21" = "SYST`r`n"
                "22" = "SSH-2.0-PowerShellScanner`r`n"
                "25" = "EHLO localhost`r`n"
                "80" = "HEAD / HTTP/1.1`r`nHost: localhost`r`n`r`n"
                "110" = "CAPA`r`n"
                "143" = "CAPABILITY`r`n"
                "443" = "HEAD / HTTP/1.1`r`nHost: localhost`r`n`r`n"
                "993" = "CAPABILITY`r`n"
                "995" = "CAPA`r`n"
                "3389" = "" # RDP doesn't respond to simple probes
            }
            
            if ($probes.ContainsKey($Port.ToString())) {
                $probe = $probes[$Port.ToString()]
                if ($probe -ne "") {
                    $data = [System.Text.Encoding]::ASCII.GetBytes($probe)
                    $stream.Write($data, 0, $data.Length)
                    $stream.Flush()
                    Start-Sleep -Milliseconds 500
                }
            }
            
            if ($stream.DataAvailable) {
                $buffer = New-Object byte[] 1024
                $bytesRead = $stream.Read($buffer, 0, $buffer.Length)
                if ($bytesRead -gt 0) {
                    $banner = [System.Text.Encoding]::ASCII.GetString($buffer, 0, $bytesRead)
                    $banner = ($banner -replace "[^\x20-\x7E\r\n\t]", "?").Trim()
                }
            }
            
            $tcpClient.Close()
        }
    } catch {
        $banner = "Error: $($_.Exception.Message)"
    }
    
    # CORREZIONE: Return corretto senza errore di sintassi
    if ([string]::IsNullOrWhiteSpace($banner)) {
        return "No banner received"
    } else {
        return $banner
    }
}

# Get-NetworkStatistics function for alternative process correlation - CORRETTA
function Get-NetworkStatistics {
    $properties = 'Protocol','LocalAddress','LocalPort','RemoteAddress','RemotePort','State','ProcessName','ProcessId'
    
    netstat -ano | Select-String -Pattern '\s+(TCP|UDP)' | ForEach-Object {
        $item = $_.line
        
        # CORREZIONE: Regex su una singola riga senza interruzioni
        if ($item -match '\s+(?<Protocol>\S+)\s+[\d\.]+\s+(?<LocalAddress>\S+):(?<LocalPort>\S+)\s+(?<RemoteAddress>\S+):(?<RemotePort>\S+)\s+(?<State>\S+)\s+(?<Pid>\S+)$') {
            $processId = $matches.Pid
            $processName = (Get-Process -Id $processId -ErrorAction SilentlyContinue).ProcessName
            
            New-Object PSObject -Property @{
                Protocol = $matches.Protocol
                LocalAddress = $matches.LocalAddress
                LocalPort = $matches.LocalPort
                RemoteAddress = $matches.RemoteAddress
                RemotePort = $matches.RemotePort
                State = $matches.State
                ProcessName = $processName
                ProcessId = $processId
            } | Select-Object $properties
        }
    }
}

# Main scanning function - CORRETTA
function Start-AdvancedPortScan {
    Write-Host "🔍 Starting Advanced Port & Process Scan..." -ForegroundColor Green
    
    $results = @()
    
    # Get listening ports from system
    Write-Host "`n📊 Gathering listening ports..." -ForegroundColor Cyan
    
    # TCP Ports
    $tcpPorts = Get-NetTCPConnection -ErrorAction SilentlyContinue | 
                Where-Object { $_.State -eq 'Listen' } |
                Select-Object LocalPort, OwningProcess -Unique
    
    # UDP Ports  
    $udpPorts = Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
                Select-Object LocalPort, OwningProcess -Unique
    
    $allPorts = @()
    $tcpPorts | ForEach-Object { $allPorts += [PSCustomObject]@{ Port = $_.LocalPort; Protocol = "TCP"; ProcessId = $_.OwningProcess } }
    if (-not $SkipUDP) {
        $udpPorts | ForEach-Object { $allPorts += [PSCustomObject]@{ Port = $_.LocalPort; Protocol = "UDP"; ProcessId = $_.OwningProcess } }
    }
    
    Write-Host "✅ Found $($allPorts.Count) listening ports" -ForegroundColor Green
    
    # Process each port with advanced correlation
    $counter = 0
    foreach ($portInfo in $allPorts) {
        $counter++
        $percentComplete = ($counter / $allPorts.Count) * 100
        
        # CORREZIONE: Write-Progress su una singola riga
        Write-Progress -Activity "Advanced Port Analysis" -Status "Processing port $($portInfo.Port)/$($portInfo.Protocol)" -PercentComplete $percentComplete
        
        $serviceName = Get-ServiceNameByPort -Port $portInfo.Port -Protocol $portInfo.Protocol
        
        # Use advanced process correlation
        $processInfo = Get-ProcessByPortAdvanced -Port $portInfo.Port -Protocol $portInfo.Protocol
        
        # Get banner for TCP ports
        $banner = ""
        if ($portInfo.Protocol -eq "TCP") {
            $banner = Get-ServiceBanner -Port $portInfo.Port -Protocol "TCP"
        }
        
        $results += [PSCustomObject]@{
            Protocol = $portInfo.Protocol
            LocalPort = $portInfo.Port
            ServiceName = $serviceName
            ProcessId = $processInfo.ProcessId
            ProcessName = $processInfo.ProcessName
            ProcessPath = $processInfo.ProcessPath
            Confidence = $processInfo.Confidence
            MethodsUsed = ($processInfo.MethodsUsed -join ", ")
            Banner = $banner
            AdditionalInfo = $processInfo.AdditionalInfo
        }
    }
    
    Write-Progress -Activity "Advanced Port Analysis" -Completed
    
    return $results
}

# Generate HTML Report - CORRETTA
function New-AdvancedScanHTMLReport {
    param(
        [array]$ScanResults,
        [string]$OutputPath = "AdvancedPortScan_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    )
    
    Write-Host "`n📊 Generating Advanced HTML Report..." -ForegroundColor Cyan
    
    # Statistics
    $totalPorts = $ScanResults.Count
    $tcpPorts = ($ScanResults | Where-Object { $_.Protocol -eq 'TCP' }).Count
    $udpPorts = ($ScanResults | Where-Object { $_.Protocol -eq 'UDP' }).Count
    $highConfidence = ($ScanResults | Where-Object { $_.Confidence -eq 'High' }).Count
    $mediumConfidence = ($ScanResults | Where-Object { $_.Confidence -eq 'Medium' }).Count
    $lowConfidence = ($ScanResults | Where-Object { $_.Confidence -eq 'Low' }).Count
    $highRiskOpen = ($ScanResults | Where-Object { $HighRiskPorts -contains $_.LocalPort }).Count
    
    $summaryHTML = @"
        <div class="summary">
            <h3>📈 Advanced Scan Summary</h3>
            <p><strong>Total Listening Ports:</strong> $totalPorts</p>
            <p><strong>TCP Ports:</strong> $tcpPorts</p>
            <p><strong>UDP Ports:</strong> $udpPorts</p>
            <p><strong>High Confidence Correlations:</strong> <span class="confidence-high">$highConfidence</span></p>
            <p><strong>Medium Confidence Correlations:</strong> <span class="confidence-medium">$mediumConfidence</span></p>
            <p><strong>Low Confidence Correlations:</strong> <span class="confidence-low">$lowConfidence</span></p>
            <p><strong>High-Risk Ports:</strong> $highRiskOpen</p>
            <p><strong>Scan Methods:</strong> NetStat, ActiveConnection, HandleAnalysis, NetworkStatistics</p>
        </div>
"@

    # Main Results Table
    $mainTableHTML = $ScanResults | Sort-Object Protocol, LocalPort | ConvertTo-Html -Fragment -PreContent "<h3>🔍 Detailed Port Analysis</h3>" | Out-String
    
    # Add CSS classes for confidence levels
    $mainTableHTML = $mainTableHTML -replace '<td>High</td>', '<td class="confidence-high">High</td>'
    $mainTableHTML = $mainTableHTML -replace '<td>Medium</td>', '<td class="confidence-medium">Medium</td>'
    $mainTableHTML = $mainTableHTML -replace '<td>Low</td>', '<td class="confidence-low">Low</td>'
    
    # Add protocol styling
    $mainTableHTML = $mainTableHTML -replace '<table>', '<table class="tcp">'
    
# Process Summary - VERSIONE CORRETTA
$processSummary = $ScanResults | 
    Where-Object { $_.ProcessId -ne $null } |
    Group-Object ProcessId | 
    ForEach-Object {
        $process = $_.Group[0]
        $ports = $_.Group | ForEach-Object { 
            $confidenceClass = "confidence-$($_.Confidence.ToLower())"
            "<span class='$confidenceClass'>$($_.LocalPort)/$($_.Protocol)</span>"
        }
        
        [PSCustomObject]@{
            ProcessId = $process.ProcessId
            ProcessName = $process.ProcessName
            ProcessPath = $process.ProcessPath
            Ports = ($ports -join ", ")
            PortCount = $_.Count
            AvgConfidence = ($_.Group | ForEach-Object { 
                switch ($_.Confidence) { "High" { 3 } "Medium" { 2 } "Low" { 1 } }
            } | Measure-Object -Average).Average
        }
    } | Sort-Object AvgConfidence -Descending

    # Generazione manuale della tabella processi per evitare escaping HTML
$processTableHTML = @"
<h3>⚙️ Process Portfolio Summary</h3>
<table class="tcp">
<thead>
<tr>
<th>Process ID</th>
<th>Process Name</th>
<th>Process Path</th>
<th>Ports</th>
<th>Port Count</th>
</tr>
</thead>
<tbody>
"@

foreach ($process in $processSummary) {
    $processTableHTML += @"
<tr>
<td>$($process.ProcessId)</td>
<td>$($process.ProcessName)</td>
<td>$($process.ProcessPath)</td>
<td>$($process.Ports)</td>
<td>$($process.PortCount)</td>
</tr>
"@
}

$processTableHTML += @"
</tbody>
</table>
"@
    
    # High Risk Ports
    $highRiskResults = $ScanResults | Where-Object { $HighRiskPorts -contains $_.LocalPort } | Sort-Object LocalPort
    $highRiskTableHTML = ""
    if ($highRiskResults) {
        $highRiskTableHTML = $highRiskResults | ConvertTo-Html -Fragment -PreContent "<h3>🚨 High-Risk Port Analysis</h3>" | Out-String
    }
    
    # Combine all HTML content
    $fullHTML = $HTMLHeader + $summaryHTML + $mainTableHTML + $highRiskTableHTML + $processTableHTML + $HTMLFooter
    
    # Save to file
    $fullHTML | Out-File -FilePath $OutputPath -Encoding UTF8
    
    return $OutputPath
}

# Main execution - CORRETTA
try {
    Write-Host "🔍 ADVANCED PORT & PROCESS CORRELATION SCANNER" -ForegroundColor Magenta
    Write-Host "=" * 60 -ForegroundColor Magenta
    
    # Perform scan
    $scanResults = Start-AdvancedPortScan
    
    # Generate report
    $reportPath = New-AdvancedScanHTMLReport -ScanResults $scanResults
    
    # Display summary
    Write-Host "`n✅ SCAN COMPLETED SUCCESSFULLY!" -ForegroundColor Green
    Write-Host "=" * 50 -ForegroundColor Green
    Write-Host "📋 Advanced Analysis Results:" -ForegroundColor White
    Write-Host "   • Total listening ports: $($scanResults.Count)" -ForegroundColor Cyan
    Write-Host "   • TCP ports: $(($scanResults | Where-Object { $_.Protocol -eq 'TCP' }).Count)" -ForegroundColor Cyan
    Write-Host "   • UDP ports: $(($scanResults | Where-Object { $_.Protocol -eq 'UDP' }).Count)" -ForegroundColor Cyan
    Write-Host "   • High confidence correlations: $(($scanResults | Where-Object { $_.Confidence -eq 'High' }).Count)" -ForegroundColor Green
    Write-Host "   • Medium confidence correlations: $(($scanResults | Where-Object { $_.Confidence -eq 'Medium' }).Count)" -ForegroundColor Yellow
    Write-Host "   • Low confidence correlations: $(($scanResults | Where-Object { $_.Confidence -eq 'Low' }).Count)" -ForegroundColor Red
    Write-Host "   • Report saved: $reportPath" -ForegroundColor Yellow
    
    # Show confidence summary
    Write-Host "`n🎯 Correlation Confidence Summary:" -ForegroundColor Cyan
    $scanResults | Group-Object Confidence | ForEach-Object {
        $color = switch ($_.Name) { "High" { "Green" } "Medium" { "Yellow" } "Low" { "Red" } }
        Write-Host "   • $($_.Name): $($_.Count) ports" -ForegroundColor $color
    }
    
    # Show high-risk findings
    $highRiskFindings = $scanResults | Where-Object { $HighRiskPorts -contains $_.LocalPort }
    if ($highRiskFindings) {
        Write-Host "`n🚨 HIGH-RISK PORTS FOUND:" -ForegroundColor Red
        $highRiskFindings | Format-Table Protocol, LocalPort, ServiceName, ProcessName, Confidence -AutoSize
    }
    
    # Open the report
    $openReport = Read-Host "`nDo you want to open the HTML report now? (Y/N)"
    if ($openReport -eq 'Y' -or $openReport -eq 'y') {
        Start-Process $reportPath
        Write-Host "📂 Opening advanced report in default browser..." -ForegroundColor Green
    }
    
} catch {
    Write-Error "Script execution failed: $($_.Exception.Message)"
    Write-Host "Full error details:" -ForegroundColor Red
    Write-Host $_.Exception.StackTrace -ForegroundColor Red
}

Write-Host "`nAdvanced port correlation scan completed." -ForegroundColor Gray
