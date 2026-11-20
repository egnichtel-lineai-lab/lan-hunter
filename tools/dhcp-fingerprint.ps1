<#
.SYNOPSIS
  Pull every scrap of identifying data the Windows DHCP server holds about one
  client, for the purpose of fingerprinting a device that never sends a hostname.

.DESCRIPTION
  Run this ON a DHCP server (or with the DhcpServer module + admin rights
  remotely) and paste the whole output back. It is READ-ONLY unless you pass
  -ForceRebind.

  Why this works even with no option 12:
    * The lease row still carries the CLIENT IDENTIFIER (DHCP option 61). Its
      format is itself a fingerprint:
        - absent / bare MAC        -> dumb embedded firmware (IoT, modules)
        - 00-<mac>                 -> classic BSD/Unix/older-embedded style
        - ff-00-01-00-01-<time>-<id> RFC 4361/4390 DUID -> modern general-purpose
                                      OS (Windows 8.1+, macOS, Android, ChromeOS)
    * The GRANTED lease interval reveals which policy/class matched, if any.
    * The server's own daily log files record every DISCOVER/REQUEST the device
      has EVER sent, including the Host Name column - so if it ever did offer a
      hostname (or firmware changed), history shows it.
    * Which scope / which of the two split-scope servers owns the lease tells us
      which server's logs to read.

  What this script CANNOT get you: option 55 (Parameter Request List) and
  option 60 (Vendor Class) as the client sent them. Windows does not persist
  those. They only exist on the wire - see the -ForceRebind note at the bottom,
  which makes the device re-broadcast a full DISCOVER that the lan-hunter host
  is already passively capturing.

.NOTES
  Requires: Windows DHCP Server role (or DhcpServer module) + local admin on the
  DHCP server. Nothing is modified unless -ForceRebind is supplied.
#>

[CmdletBinding()]
param(
    [string[]] $DhcpServers = @('localhost'),   # <-- EDIT: your two DCs, e.g. @('DC1','DC2')
    [string]   $TargetMac   = '<insert MAC here>',  # <-- EDIT: the MAC of the device you want to fingerprint
    [string]   $TargetIp    = '<insert IP here>',   # <-- EDIT: the IP of the device you want to fingerprint
    [switch]   $ForceRebind
)

$ErrorActionPreference = 'Continue'
$TargetMacNoSep = ($TargetMac -replace '[:-]', '').ToUpper()

function Section($t) { Write-Host "`n$('=' * 78)`n$t`n$('=' * 78)" -ForegroundColor Cyan }

Section "0. Context"
"PSVersion   : $($PSVersionTable.PSVersion)"
"Computer    : $env:COMPUTERNAME"
"Target MAC  : $TargetMac  (no-sep: $TargetMacNoSep)"
"Target IP   : $TargetIp"
"Time        : $(Get-Date -Format 'o')"
if (-not (Get-Module -ListAvailable DhcpServer)) {
    Write-Host "FATAL: DhcpServer module not present on $(hostname). Run this on a DHCP server." -ForegroundColor Red
    return
}

foreach ($srv in $DhcpServers) {
    Section "1. Scopes served by $srv"
    $scopes = $null
    try {
        $scopes = Get-DhcpServerv4Scope -ComputerName $srv -ErrorAction Stop
        $scopes | Select-Object ScopeId, Name, StartRange, EndRange, SubnetMask,
                                 LeaseDuration, State, MaxPhysicalAddressCount |
                 Format-Table -AutoSize | Out-String -Width 200 | Write-Host
    } catch {
        Write-Host "  cannot enumerate scopes on ${srv}: $($_.Exception.Message)" -ForegroundColor Yellow
        continue
    }

    Section "2. Lease record for $TargetMac on $srv"
    foreach ($sc in $scopes) {
        $lease = $null
        try {
            $lease = Get-DhcpServerv4Lease -ComputerName $srv -ScopeId $sc.ScopeId `
                       -MacAddress $TargetMac -ErrorAction SilentlyContinue
            if (-not $lease) {
                $lease = Get-DhcpServerv4Lease -ComputerName $srv -ScopeId $sc.ScopeId `
                           -IPAddress $TargetIp -ErrorAction SilentlyContinue
            }
        } catch { }
        if ($lease) {
            "--- scope $($sc.ScopeId) ($($sc.Name)) ---"
            $lease | Format-List * | Out-String -Width 200 | Write-Host
            ">>> CLIENT IDENTIFIER (option 61) = '$($lease.ClientId)'"
            ">>> HOSTNAME (option 12)          = '$($lease.HostName)'"
            ">>> ADDRESS STATE                 = '$($lease.AddressState)'"
            ">>> DNS REGISTRATION              = '$($lease.DnsRegistration)'  '$($lease.DnsPtrRegistration)'"
            ">>> LEASE START / EXPIRY          = $($lease.StartTime) / $($lease.LeaseExpiryTime)"
            ">>> DESCRIPTION                   = '$($lease.Description)'"
        }
    }

    Section "3. Policies and vendor classes on $srv (does anything match?)"
    try {
        Get-DhcpServerv4Policy -ComputerName $srv -ErrorAction SilentlyContinue |
            Format-List * | Out-String -Width 200 | Write-Host
    } catch { Write-Host "  (no policies / $($_.Exception.Message))" }
    try {
        "--- vendor classes (custom only; built-ins omitted) ---"
        Get-DhcpServerv4Class -ComputerName $srv -ErrorAction SilentlyContinue |
            Where-Object { -not $_.Builtin } |
            Select-Object Name, Description, MatchOption, VendorClass, Data |
            Format-List * | Out-String -Width 200 | Write-Host
    } catch { Write-Host "  (no custom classes / $($_.Exception.Message))" }

    Section "4. DHCP server settings on $srv (lease duration, conflict detect, DNS)"
    try {
        Get-DhcpServerSetting -ComputerName $srv -ErrorAction Stop |
            Format-List * | Out-String -Width 200 | Write-Host
    } catch { Write-Host "  $($_.Exception.Message)" }
    try {
        Get-DhcpServerDatabase -ComputerName $srv -ErrorAction Stop |
            Format-List * | Out-String -Width 200 | Write-Host
    } catch { Write-Host "  $($_.Exception.Message)" }

    Section "5. Historical DHCP logs on $srv mentioning $TargetMac or $TargetIp"
    # Daily CSV-ish logs; the 'Host Name' column is populated from option 12 when
    # the client sent one. If it is EVER non-blank for this MAC, the device does
    # have a hostname and something is stripping it.
    $logDir = Join-Path $env:SystemRoot 'System32\dhcp'
    if ($srv -ne 'localhost' -and $srv -ne $env:COMPUTERNAME) {
        $unc = "\\$srv\admin`$\System32\dhcp"
        $logDir = $unc
    }
    try {
        $files = Get-ChildItem -Path $logDir -Filter 'DhcpSrvLog-*.log' -ErrorAction Stop |
                 Sort-Object LastWriteTime
        "log files present: $($files.Count)  (oldest: $($files[0].Name), newest: $($files[-1].Name))"
        $header = Get-Content -Path (Join-Path $logDir $files[-1].Name) -TotalCount 1 -ErrorAction SilentlyContinue
        "column header    : $header"
        $total = 0
        foreach ($f in $files) {
            $hits = Select-String -Path $f.FullName -Pattern $TargetMacNoSep, $TargetMac, $TargetIp `
                              -SimpleMatch -ErrorAction SilentlyContinue
            if ($hits) {
                $total += @($hits).Count
                "--- $($f.Name) : $(@($hits).Count) hit(s) ---"
                $hits | Select-Object -First 40 | ForEach-Object { "  $($_.Line)" } | Write-Host
            }
        }
        if ($total -eq 0) { "no log entries found for this MAC/IP in the retained window" }
        else { "TOTAL log hits: $total" }
    } catch {
        Write-Host "  could not read $logDir : $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "  (if remote, use \\$srv\admin`$\System32\dhcp or run locally on that server)"
    }
}

Section "6. Cross-check: is the lease also visible in DNS?"
try {
    $rev = ($TargetIp.Split('.') | Select-Object -Reverse) -join '.'
    Get-DnsServerResourceRecord -ZoneName "$rev.in-addr.arpa" -ErrorAction SilentlyContinue |
        Where-Object { $_.RecordName -like "*$($TargetIp.Split('.')[-1])" } |
        Format-List HostName, RecordType, Timestamp, TimeToLive | Out-String | Write-Host
} catch { Write-Host "  (no reverse zone access / $($_.Exception.Message))" }

if ($ForceRebind) {
    Section "7. FORCING A REBIND (you asked for this)"
    Write-Host "Deleting the lease so the device must rebind. When it wakes it will" -ForegroundColor Yellow
    Write-Host "broadcast a fresh DISCOVER carrying its FULL option set (55/60/61)," -ForegroundColor Yellow
    Write-Host "which the lan-hunter host is passively capturing right now." -ForegroundColor Yellow
    foreach ($srv in $DhcpServers) {
        try {
            Remove-DhcpServerv4Lease -ComputerName $srv -IPAddress $TargetIp -Confirm:$false -ErrorAction Stop
            Write-Host "  lease removed on $srv" -ForegroundColor Green
        } catch { Write-Host "  $srv : $($_.Exception.Message)" }
    }
    Write-Host "`nNow wait for the device to wake; then on the Pi run:" -ForegroundColor Cyan
    Write-Host "  tcpdump -r /var/tmp/lhcap/wlan0-*.pcap -nn -e -vvv port 67 or port 68" -ForegroundColor Cyan
} else {
    Section "NEXT STEP (only way to obtain option 55 / 60)"
    Write-Host "Re-run with -ForceRebind to expire the lease. The device's next" -ForegroundColor Yellow
    Write-Host "rebind is a broadcast DISCOVER (0.0.0.0 -> 255.255.255.255) which IS" -ForegroundColor Yellow
    Write-Host "visible to a normal Wi-Fi client, unlike a unicast RENEW/REQUEST." -ForegroundColor Yellow
    Write-Host "The Pi's tcpdump filter already matches on the MAC, so it will catch it." -ForegroundColor Yellow
}

Section "DONE - paste everything above back"
