<#
    .DESCRIPTION
        MyPortScanner will scan all ports for all IP addresses in your subnet. 
        Looking for Unauthorized Devices, Ports and Protocols in an environment. 
        Tested Nets Time based on 65535 (MAX) ports
            /24 approx 4 hours
            /22 approx 16 hours

    .OUTPUTS
        Report found under $logPath below, default is c:\COD-Logs\COMPUTERNAME\DATETIME
    
    .EXAMPLE
        1. PowerShell 5.1 Command Prompt (Admin) 
            "powershell -Executionpolicy Bypass -File PATH\FILENAME.ps1"
        2. Powershell 7.2.1 Command Prompt (Admin) 
            "pwsh -Executionpolicy Bypass -File PATH\FILENAME.ps1"

    .NOTES
        Author Perkins
        Last Update 1/7/22
        Updated 1/7/22 Tested and Validated PowerShell 5.1 and 7.2.1
    
        Powershell 5 or higher
        Run as Administrator
    
    .FUNCTIONALITY
        PowerShell Language
        Active Directory
    
    .Link
        https://github.com/COD-Team
        YouTube Video https://youtu.be/4LSMP0gj1IQ
        
    KimConnect did a great job creating Script to execute based on your subnet without input.
    Modified for my requirements. See notes below. 
    https://kimconnect.com/powershell-scan-a-subnet-for-used-and-unused-ips/
#>

#Requires -RunAsAdministrator

$versionMinimum = [Version]'5.1.000.000'
    if ($versionMinimum -gt $PSVersionTable.PSVersion)
    { throw "This script requires PowerShell $versionMinimum" }

# Get Computer Name
$ComputerName = $env:computername

# Path where the results will be written.
$logpath = "C:\COD-Logs\$ComputerName\$(get-date -format "yyyyMMdd-hhmmss")"
    If(!(test-path $logpath))
    {
          New-Item -ItemType Directory -Force -Path $logpath
    }

# Added 1/7/21 PowerShell 7.2.1 Compatibility for Out-File not printing escape characters
if ($PSVersionTable.PSVersion.major -ge 7) {$PSStyle.OutputRendering = 'PlainText'}

# Logfile where all the results are dumped
$OutputFile = "$logpath\PortScanner.log"
$StartTime = (Get-Date)

# Adjust Ports as needed
$portrange = 1..65535

# Slow Nets or WANs, might need to increase
$timeout_ms = 1

# Sets variable for number for jobs. 
$i = 0

# Used for Jobs, 8 is about the Max I have been able to execute, any numbers larger does not
# decrease time. Your computer might be able to handle a few more treads. 
$simultaneousJobs = 8

# Start KimConnect Section - Produces IP Addresses for current subnet. Use $allIps
$cidrBlock=$(
    $interfaceIndex=(Get-CimInstance  -Class Win32_IP4RouteTable | Where-Object { $_.destination -eq '0.0.0.0' -and $_.mask -eq '0.0.0.0'} |  Sort-Object metric1).interfaceindex;
    $interfaceObject=(Get-NetIPAddress -InterfaceIndex $interfaceIndex -AddressFamily ipv4 | Select-object IPAddress,PrefixLength)[0];
    "$($interfaceObject.IPAddress)/$($interfaceObject.PrefixLength)"
) 
    function Get-IPrange
    {
        param ( 
        [string]$start, 
        [string]$end, 
        [string]$ip, 
        [string]$mask, 
        [int]$cidr
        ) 
        function IP-toINT64 () { 
            param ($ip) 

            $octets = $ip.split(".") 
            return [int64]([int64]$octets[0]*16777216 +[int64]$octets[1]*65536 +[int64]$octets[2]*256 +[int64]$octets[3]) 
        } 
        function INT64-toIP() { 
            param ([int64]$int) 

            return (([math]::truncate($int/16777216)).tostring()+"."+([math]::truncate(($int%16777216)/65536)).tostring()+"."+([math]::truncate(($int%65536)/256)).tostring()+"."+([math]::truncate($int%256)).tostring() )
        } 

        if ($ip) {$ipaddr = [Net.IPAddress]::Parse($ip)} 
        if ($cidr) {$maskaddr = [Net.IPAddress]::Parse((INT64-toIP -int ([convert]::ToInt64(("1"*$cidr+"0"*(32-$cidr)),2)))) } 
        if ($mask) {$maskaddr = [Net.IPAddress]::Parse($mask)} 
        if ($ip) {$networkaddr = new-object net.ipaddress ($maskaddr.address -band $ipaddr.address)} 
        if ($ip) {$broadcastaddr = new-object net.ipaddress (([system.net.ipaddress]::parse("255.255.255.255").address -bxor $maskaddr.address -bor $networkaddr.address))} 

        if ($ip) 
        { 
            $startaddr = IP-toINT64 -ip $networkaddr.ipaddresstostring 
            $endaddr = IP-toINT64 -ip $broadcastaddr.ipaddresstostring 
        } 
        else 
        { 
            $startaddr = IP-toINT64 -ip $start
            $endaddr = IP-toINT64 -ip $end
        } 
        for ($i = $startaddr; $i -le $endaddr; $i++) 
        { 
            INT64-toIP -int $i
        }
    }  # End of  Get-IPrange

# Regex values
$regexIP = [regex] "\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
$regexCidr=[regex] "\/(.*)"
$regexFourthOctetValue=[regex] ".+\..+\..+\.(.+)"
    
# Process inputs
$ip=$regexIP.Matches($cidrBlock).Value
$cidr=$regexCidr.Matches($cidrBlock).Groups[1].Value
$allIPs=Get-IPrange -ip $ip -cidr $cidr

# Remove fourth octet values matching 0,1, and 255
if($regexFourthOctetValue.Matches($allIPs[$allIPs.length-1]).Groups[1].Value -eq 255){$allIPs = $allIPs | Where-Object {$_ -ne $allIPs[$allIPs.count-1]}}

# End KimConnect Section - Produces IP Addresses for current subnet. Use $allIps

$ScriptBlock = 
{
    foreach ($port in $Using:portrange)
    {   
        $socket = new-object System.Net.Sockets.TcpClient
        $connect = $socket.BeginConnect($using:ipAddress, $port, $null, $null)
        $tryconnect = $connect.AsyncWaitHandle.WaitOne($timeout_ms, $true)
        $tryconnect | Out-Null
        Write-Host "$Using:ipAddress $port" $Socket.Connected

        IF ($Socket.Connected -eq $true)
        {
            $output = $Using:ipAddress
            $output += " "
            $output += $port
            $output += " "
            $output += $Socket.Connected
            Write-Output $output  | Out-File -Append $Using:OutputFile
        }

        $socket.Close()
        $socket.Dispose()
        $socket = $null
    }
}

foreach ($ipAddress in $allIps)
{
    Write-Host "Testing IP" $ipAddress
    if($i++ -lt $simultaneousJobs)
    {
        Start-Job -ArgumentList $ipAddress -ScriptBlock $ScriptBlock | Out-Null
    }
    do
    {
        Get-Job | Receive-Job          
        get-job -State Completed | remove-job               
        $i=(get-job -state 'Running').count   
    }        
    until($i -lt $simultaneousJobs)
}

Write-Output $StartTime | Out-File -Append $OutputFile
Write-Output (Get-Date) | Out-File -Append $OutputFile

Write-Host " "
Write-Host -fore green "Results saved to: $OutputFile" 
write-Host -fore green "Script Completed"
