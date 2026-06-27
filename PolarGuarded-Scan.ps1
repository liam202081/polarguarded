# ============================================================
# PolarGuarded Security Scanner v1.0
# Canadian Cybersecurity — polarguarded.com
# ============================================================

$ErrorActionPreference = "SilentlyContinue"
$scanDate = Get-Date -Format "MMMM dd, yyyy HH:mm"
$checks = [System.Collections.Generic.List[PSCustomObject]]::new()
$hostname = $env:COMPUTERNAME
$username = $env:USERNAME
$osInfo = Get-CimInstance Win32_OperatingSystem
$osName = $osInfo.Caption
$osVersion = $osInfo.Version

Write-Host ""
Write-Host "  ========================================" -ForegroundColor Cyan
Write-Host "   POLARGUARDED SECURITY SCANNER v1.0" -ForegroundColor Cyan
Write-Host "   polarguarded.com" -ForegroundColor Gray
Write-Host "  ========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Computer : $hostname" -ForegroundColor White
Write-Host "  User     : $username" -ForegroundColor White
Write-Host "  OS       : $osName" -ForegroundColor White
Write-Host "  Date     : $scanDate" -ForegroundColor White
Write-Host ""

function Add-Check {
    param($Category, $Check, $Status, $Detail, $Risk)
    $checks.Add([PSCustomObject]@{
        Category = $Category
        Check    = $Check
        Status   = $Status
        Detail   = $Detail
        Risk     = $Risk
    })
}

# ── 1. WINDOWS DEFENDER ──────────────────────────────────────
Write-Host "  [1/12] Checking Windows Defender..." -ForegroundColor Gray
try {
    $defender = Get-MpComputerStatus
    if ($defender.AntivirusEnabled) {
        if ($defender.RealTimeProtectionEnabled) {
            $sigAge = ((Get-Date) - $defender.AntivirusSignatureLastUpdated).Days
            $sigMsg = if ($sigAge -gt 3) { " WARNING: Virus definitions are $sigAge days old." } else { " Definitions are up to date." }
            Add-Check "Antivirus" "Windows Defender" "PASS" "Real-time protection is active.$sigMsg" "low"
        } else {
            Add-Check "Antivirus" "Windows Defender" "WARN" "Defender is installed but real-time protection is OFF. Enable it immediately." "high"
        }
    } else {
        Add-Check "Antivirus" "Windows Defender" "FAIL" "Windows Defender is DISABLED. Your system is unprotected from malware." "critical"
    }
} catch {
    Add-Check "Antivirus" "Windows Defender" "WARN" "Could not retrieve Windows Defender status." "medium"
}

# ── 2. FIREWALL ──────────────────────────────────────────────
Write-Host "  [2/12] Checking Firewall..." -ForegroundColor Gray
try {
    $fw = Get-NetFirewallProfile
    $offProfiles = ($fw | Where-Object { $_.Enabled -eq $false }).Name
    if ($offProfiles.Count -eq 0) {
        Add-Check "Firewall" "Windows Firewall" "PASS" "Firewall is active on all profiles: Domain, Private, and Public." "low"
    } else {
        Add-Check "Firewall" "Windows Firewall" "FAIL" "Firewall is DISABLED on: $($offProfiles -join ', '). This is a critical security risk." "critical"
    }
} catch {
    Add-Check "Firewall" "Windows Firewall" "WARN" "Could not retrieve firewall status." "medium"
}

# ── 3. WINDOWS UPDATES ───────────────────────────────────────
Write-Host "  [3/12] Checking Windows Updates..." -ForegroundColor Gray
try {
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $pending = $searcher.Search("IsInstalled=0 and Type='Software'")
    $count = $pending.Updates.Count
    if ($count -eq 0) {
        Add-Check "Updates" "Pending Windows Updates" "PASS" "System is fully up to date. No pending updates." "low"
    } elseif ($count -le 5) {
        Add-Check "Updates" "Pending Windows Updates" "WARN" "$count pending update(s). Install soon to stay protected." "medium"
    } else {
        Add-Check "Updates" "Pending Windows Updates" "FAIL" "$count pending updates. Your system is significantly out of date and vulnerable." "high"
    }
} catch {
    Add-Check "Updates" "Pending Windows Updates" "WARN" "Could not check for updates. Run Windows Update manually." "medium"
}

# ── 4. OPEN PORTS ────────────────────────────────────────────
Write-Host "  [4/12] Scanning open ports..." -ForegroundColor Gray
try {
    $riskyPorts = @{
        21   = "FTP — often exploited for unauthorized file access"
        23   = "Telnet — unencrypted, easily intercepted"
        25   = "SMTP — can be used for spam relay"
        135  = "RPC — common target for remote exploits"
        139  = "NetBIOS — exposes file sharing vulnerabilities"
        445  = "SMB — used by WannaCry and other ransomware"
        3389 = "RDP — common target for brute force attacks"
        5900 = "VNC — remote desktop, often misconfigured"
        8080 = "HTTP Alt — proxy servers, often insecure"
    }
    $openPorts = (Get-NetTCPConnection -State Listen).LocalPort | Sort-Object -Unique
    $riskyOpen = $openPorts | Where-Object { $riskyPorts.ContainsKey($_) }
    if ($riskyOpen.Count -eq 0) {
        Add-Check "Network" "Open Ports" "PASS" "No high-risk ports detected. Total open ports: $($openPorts.Count)." "low"
    } else {
        $details = $riskyOpen | ForEach-Object { "Port $_ — $($riskyPorts[$_])" }
        Add-Check "Network" "Open Ports" "FAIL" "High-risk ports open: $($details -join ' | ')" "critical"
    }
} catch {
    Add-Check "Network" "Open Ports" "WARN" "Could not scan open ports." "medium"
}

# ── 5. BITLOCKER ─────────────────────────────────────────────
Write-Host "  [5/12] Checking disk encryption..." -ForegroundColor Gray
try {
    $bl = Get-BitLockerVolume -MountPoint "C:"
    if ($bl.ProtectionStatus -eq "On") {
        Add-Check "Encryption" "BitLocker Drive Encryption" "PASS" "BitLocker is enabled on C: drive. Data is protected if device is lost or stolen." "low"
    } else {
        Add-Check "Encryption" "BitLocker Drive Encryption" "WARN" "BitLocker is NOT enabled. Your data could be accessed if your device is stolen." "high"
    }
} catch {
    Add-Check "Encryption" "BitLocker Drive Encryption" "WARN" "BitLocker not available or not configured. Consider enabling it." "medium"
}

# ── 6. GUEST ACCOUNT ─────────────────────────────────────────
Write-Host "  [6/12] Checking user accounts..." -ForegroundColor Gray
try {
    $guest = Get-LocalUser -Name "Guest"
    if ($guest.Enabled) {
        Add-Check "Accounts" "Guest Account" "FAIL" "Guest account is ENABLED. Disable it to prevent unauthorized local access." "high"
    } else {
        Add-Check "Accounts" "Guest Account" "PASS" "Guest account is disabled. Good." "low"
    }
} catch {
    Add-Check "Accounts" "Guest Account" "PASS" "Guest account not found or disabled." "low"
}

# ── 7. UAC ───────────────────────────────────────────────────
Write-Host "  [7/12] Checking UAC..." -ForegroundColor Gray
try {
    $uac = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System").EnableLUA
    if ($uac -eq 1) {
        Add-Check "Security" "User Account Control (UAC)" "PASS" "UAC is enabled. Programs must request permission before making system changes." "low"
    } else {
        Add-Check "Security" "User Account Control (UAC)" "FAIL" "UAC is DISABLED. Programs can make system changes without your knowledge." "critical"
    }
} catch {
    Add-Check "Security" "User Account Control (UAC)" "WARN" "Could not check UAC status." "medium"
}

# ── 8. PASSWORD POLICY ───────────────────────────────────────
Write-Host "  [8/12] Checking password policy..." -ForegroundColor Gray
try {
    $policy = net accounts
    $minLen = [int](($policy | Select-String "Minimum password length").ToString() -replace "\D", "")
    if ($minLen -ge 12) {
        Add-Check "Accounts" "Password Policy" "PASS" "Minimum password length is $minLen characters. Meets security best practices." "low"
    } elseif ($minLen -ge 8) {
        Add-Check "Accounts" "Password Policy" "WARN" "Minimum password length is $minLen. Recommend increasing to 12 or more." "medium"
    } else {
        Add-Check "Accounts" "Password Policy" "FAIL" "Minimum password length is only $minLen characters. Very weak policy." "high"
    }
} catch {
    Add-Check "Accounts" "Password Policy" "WARN" "Could not retrieve password policy." "medium"
}

# ── 9. STARTUP PROGRAMS ──────────────────────────────────────
Write-Host "  [9/12] Checking startup programs..." -ForegroundColor Gray
try {
    $startup = Get-CimInstance Win32_StartupCommand
    $count = $startup.Count
    if ($count -le 10) {
        Add-Check "Startup" "Startup Programs" "PASS" "$count startup program(s) detected. Normal range." "low"
    } elseif ($count -le 20) {
        Add-Check "Startup" "Startup Programs" "WARN" "$count startup programs found. Review for anything suspicious." "medium"
    } else {
        Add-Check "Startup" "Startup Programs" "FAIL" "$count startup programs found. Excessive — may include unwanted software." "high"
    }
} catch {
    Add-Check "Startup" "Startup Programs" "WARN" "Could not retrieve startup programs." "medium"
}

# ── 10. SUSPICIOUS PROCESSES ─────────────────────────────────
Write-Host "  [10/12] Checking running processes..." -ForegroundColor Gray
try {
    $suspicious = @("mimikatz", "meterpreter", "netcat", "nc", "nmap", "wireshark", "ftp", "telnet", "psexec", "wce", "pwdump")
    $running = Get-Process | Select-Object -ExpandProperty Name
    $found = $running | Where-Object { $suspicious -contains $_.ToLower() }
    if ($found.Count -eq 0) {
        Add-Check "Processes" "Suspicious Processes" "PASS" "No known suspicious processes detected." "low"
    } else {
        Add-Check "Processes" "Suspicious Processes" "FAIL" "Suspicious process(es) detected: $($found -join ', '). Investigate immediately." "critical"
    }
} catch {
    Add-Check "Processes" "Suspicious Processes" "WARN" "Could not scan running processes." "medium"
}

# ── 11. SHARED FOLDERS ───────────────────────────────────────
Write-Host "  [11/12] Checking shared folders..." -ForegroundColor Gray
try {
    $shares = Get-SmbShare | Where-Object { $_.Name -notmatch '^\w+\$' }
    if ($shares.Count -eq 0) {
        Add-Check "Network" "Shared Folders" "PASS" "No non-default shared folders detected." "low"
    } else {
        $shareList = ($shares.Name) -join ", "
        Add-Check "Network" "Shared Folders" "WARN" "Shared folder(s) found: $shareList. Ensure these are intentional and secured." "medium"
    }
} catch {
    Add-Check "Network" "Shared Folders" "WARN" "Could not check shared folders." "medium"
}

# ── 12. REMOTE DESKTOP ───────────────────────────────────────
Write-Host "  [12/12] Checking Remote Desktop..." -ForegroundColor Gray
try {
    $rdp = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server").fDenyTSConnections
    if ($rdp -eq 1) {
        Add-Check "Network" "Remote Desktop (RDP)" "PASS" "Remote Desktop is disabled. Good — RDP is a common attack vector." "low"
    } else {
        Add-Check "Network" "Remote Desktop (RDP)" "WARN" "Remote Desktop is ENABLED. Ensure it is secured with strong passwords and network-level authentication." "high"
    }
} catch {
    Add-Check "Network" "Remote Desktop (RDP)" "WARN" "Could not check Remote Desktop status." "medium"
}

# ── CALCULATE SCORE ──────────────────────────────────────────
$total    = $checks.Count
$passed   = ($checks | Where-Object { $_.Status -eq "PASS" }).Count
$warnings = ($checks | Where-Object { $_.Status -eq "WARN" }).Count
$failed   = ($checks | Where-Object { $_.Status -eq "FAIL" }).Count
$critical = ($checks | Where-Object { $_.Risk -eq "critical" }).Count
$score    = [math]::Round(($passed / $total) * 100)

$grade = if ($score -ge 90) { "A" } elseif ($score -ge 75) { "B" } elseif ($score -ge 60) { "C" } elseif ($score -ge 40) { "D" } else { "F" }

Write-Host ""
Write-Host "  ========================================" -ForegroundColor Cyan
Write-Host "   SCAN COMPLETE" -ForegroundColor Cyan
Write-Host "  ========================================" -ForegroundColor Cyan
Write-Host "   Score  : $score/100 (Grade: $grade)" -ForegroundColor White
Write-Host "   Passed : $passed checks" -ForegroundColor Green
Write-Host "   Warnings: $warnings checks" -ForegroundColor Yellow
Write-Host "   Failed : $failed checks" -ForegroundColor Red
if ($critical -gt 0) {
    Write-Host "   CRITICAL ISSUES: $critical" -ForegroundColor Red
}
Write-Host ""
Write-Host "  Generating HTML report..." -ForegroundColor Gray

# ── BUILD HTML REPORT ────────────────────────────────────────
$statusColors = @{ "PASS" = "#3fd68a"; "WARN" = "#f5a623"; "FAIL" = "#ff4f4f" }
$statusBg     = @{ "PASS" = "rgba(63,214,138,0.08)"; "WARN" = "rgba(245,166,35,0.08)"; "FAIL" = "rgba(255,79,79,0.08)" }
$statusBorder = @{ "PASS" = "rgba(63,214,138,0.2)"; "WARN" = "rgba(245,166,35,0.2)"; "FAIL" = "rgba(255,79,79,0.2)" }
$statusIcon   = @{ "PASS" = "✓"; "WARN" = "⚠"; "FAIL" = "✕" }

$gradeColor = if ($score -ge 90) { "#3fd68a" } elseif ($score -ge 75) { "#5bc8f5" } elseif ($score -ge 60) { "#f5a623" } else { "#ff4f4f" }

$checksHtml = ""
$currentCategory = ""
foreach ($check in $checks) {
    if ($check.Category -ne $currentCategory) {
        if ($currentCategory -ne "") { $checksHtml += "</div>" }
        $checksHtml += "<div class='category'><div class='category-label'>$($check.Category)</div>"
        $currentCategory = $check.Category
    }
    $color  = $statusColors[$check.Status]
    $bg     = $statusBg[$check.Status]
    $border = $statusBorder[$check.Status]
    $icon   = $statusIcon[$check.Status]
    $checksHtml += @"
    <div class='check-item' style='background:$bg;border:1px solid $border;'>
      <div class='check-header'>
        <span class='check-icon' style='color:$color;'>$icon</span>
        <span class='check-name'>$($check.Check)</span>
        <span class='check-badge' style='background:$bg;color:$color;border:1px solid $border;'>$($check.Status)</span>
      </div>
      <div class='check-detail'>$($check.Detail)</div>
    </div>
"@
}
if ($currentCategory -ne "") { $checksHtml += "</div>" }

$html = @"
<!DOCTYPE html>
<html lang='en'>
<head>
<meta charset='UTF-8' />
<meta name='viewport' content='width=device-width, initial-scale=1.0' />
<title>PolarGuarded Security Report — $hostname</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #090d13; color: #e8f0f8; font-family: 'Segoe UI', Arial, sans-serif; font-size: 15px; line-height: 1.6; }
  a { color: #5bc8f5; }

  .header { background: #0e1520; border-bottom: 1px solid #1a2a40; padding: 32px 48px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 20px; }
  .brand { font-size: 1.3rem; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; color: #e8f0f8; }
  .brand span { color: #5bc8f5; }
  .header-meta { font-size: 0.8rem; color: #6b8aaa; font-family: monospace; line-height: 1.8; text-align: right; }

  .score-bar { background: #0e1520; border-bottom: 1px solid #1a2a40; padding: 40px 48px; display: flex; align-items: center; gap: 48px; flex-wrap: wrap; }
  .score-circle { width: 120px; height: 120px; border-radius: 50%; border: 4px solid $gradeColor; display: flex; flex-direction: column; align-items: center; justify-content: center; flex-shrink: 0; box-shadow: 0 0 30px ${gradeColor}33; }
  .score-num { font-size: 2.2rem; font-weight: 700; color: $gradeColor; font-family: monospace; line-height: 1; }
  .score-label { font-size: 0.65rem; color: #6b8aaa; letter-spacing: 0.15em; text-transform: uppercase; margin-top: 4px; }
  .score-grade { font-size: 0.85rem; color: $gradeColor; font-weight: 700; margin-top: 2px; }
  .score-stats { display: flex; gap: 32px; flex-wrap: wrap; }
  .stat-item { text-align: center; }
  .stat-num { font-size: 1.8rem; font-weight: 700; font-family: monospace; line-height: 1; }
  .stat-num.green { color: #3fd68a; }
  .stat-num.yellow { color: #f5a623; }
  .stat-num.red { color: #ff4f4f; }
  .stat-label { font-size: 0.72rem; color: #6b8aaa; letter-spacing: 0.08em; text-transform: uppercase; margin-top: 4px; }

  .system-info { background: #090d13; border-bottom: 1px solid #1a2a40; padding: 20px 48px; display: flex; gap: 40px; flex-wrap: wrap; }
  .sys-item { font-size: 0.8rem; color: #6b8aaa; }
  .sys-item span { color: #e8f0f8; font-family: monospace; }

  .content { max-width: 900px; margin: 0 auto; padding: 40px 48px; }

  .category { margin-bottom: 32px; }
  .category-label { font-size: 0.65rem; letter-spacing: 0.2em; text-transform: uppercase; color: #5bc8f5; font-family: monospace; margin-bottom: 12px; padding-bottom: 8px; border-bottom: 1px solid #1a2a40; }

  .check-item { border-radius: 4px; padding: 16px 20px; margin-bottom: 8px; }
  .check-header { display: flex; align-items: center; gap: 12px; margin-bottom: 6px; }
  .check-icon { font-size: 1rem; font-weight: 700; width: 20px; flex-shrink: 0; }
  .check-name { font-weight: 600; font-size: 0.92rem; flex: 1; }
  .check-badge { font-size: 0.65rem; letter-spacing: 0.1em; padding: 3px 10px; border-radius: 3px; font-family: monospace; font-weight: 700; }
  .check-detail { font-size: 0.82rem; color: #6b8aaa; padding-left: 32px; line-height: 1.6; }

  .cta-box { background: #0e1520; border: 1px solid #1a2a40; border-radius: 6px; padding: 36px; text-align: center; margin-top: 48px; }
  .cta-box h2 { font-size: 1.3rem; font-weight: 700; margin-bottom: 12px; }
  .cta-box p { color: #6b8aaa; font-size: 0.88rem; margin-bottom: 24px; max-width: 500px; margin-left: auto; margin-right: auto; line-height: 1.7; }
  .cta-btn { display: inline-block; background: #5bc8f5; color: #090d13; padding: 14px 36px; border-radius: 4px; font-weight: 700; font-size: 0.95rem; text-decoration: none; letter-spacing: 0.04em; }
  .cta-features { display: flex; gap: 24px; justify-content: center; flex-wrap: wrap; margin-top: 24px; }
  .cta-feature { font-size: 0.8rem; color: #6b8aaa; display: flex; align-items: center; gap: 6px; }
  .cta-feature::before { content: '✓'; color: #5bc8f5; font-weight: 700; }

  .footer-report { border-top: 1px solid #1a2a40; padding: 24px 48px; text-align: center; font-size: 0.75rem; color: #3d5a78; font-family: monospace; }

  @media (max-width: 600px) {
    .header, .score-bar, .system-info, .content, .footer-report { padding-left: 20px; padding-right: 20px; }
    .header { flex-direction: column; }
    .header-meta { text-align: left; }
  }
</style>
</head>
<body>

<div class='header'>
  <div class='brand'>Polar<span>Guarded</span></div>
  <div class='header-meta'>
    SECURITY SCAN REPORT<br>
    Generated: $scanDate<br>
    polarguarded.com
  </div>
</div>

<div class='score-bar'>
  <div class='score-circle'>
    <div class='score-num'>$score</div>
    <div class='score-label'>Score</div>
    <div class='score-grade'>Grade $grade</div>
  </div>
  <div class='score-stats'>
    <div class='stat-item'><div class='stat-num green'>$passed</div><div class='stat-label'>Passed</div></div>
    <div class='stat-item'><div class='stat-num yellow'>$warnings</div><div class='stat-label'>Warnings</div></div>
    <div class='stat-item'><div class='stat-num red'>$failed</div><div class='stat-label'>Failed</div></div>
    <div class='stat-item'><div class='stat-num'>$total</div><div class='stat-label'>Total Checks</div></div>
  </div>
</div>

<div class='system-info'>
  <div class='sys-item'>Computer: <span>$hostname</span></div>
  <div class='sys-item'>User: <span>$username</span></div>
  <div class='sys-item'>OS: <span>$osName</span></div>
  <div class='sys-item'>Version: <span>$osVersion</span></div>
</div>

<div class='content'>
  $checksHtml

  <div class='cta-box'>
    <h2>Stay Protected with PolarGuarded Pro</h2>
    <p>This PC scan is just the start. PolarGuarded Pro gives you unlimited online scans for URLs, files, phone numbers, and emails — plus a built-in VPN to encrypt your connection.</p>
    <a class='cta-btn' href='https://polarguarded.com/pricing.html'>Upgrade to Pro — `$9/mo CAD</a>
    <div class='cta-features'>
      <div class='cta-feature'>Unlimited URL & file scans</div>
      <div class='cta-feature'>Phone scam detection</div>
      <div class='cta-feature'>Email risk checker</div>
      <div class='cta-feature'>PolarGuarded VPN</div>
      <div class='cta-feature'>Cancel anytime</div>
    </div>
  </div>
</div>

<div class='footer-report'>
  PolarGuarded Security Scanner v1.0 &nbsp;·&nbsp; polarguarded.com &nbsp;·&nbsp; Built in Canada 🇨🇦<br>
  This report was generated locally on your device. No data was sent to PolarGuarded servers.
</div>

</body>
</html>
"@

# ── SAVE REPORT ──────────────────────────────────────────────
$desktop = [System.Environment]::GetFolderPath("Desktop")
$reportPath = "$desktop\PolarGuarded-Report-$(Get-Date -Format 'yyyy-MM-dd-HHmm').html"
$html | Out-File -FilePath $reportPath -Encoding UTF8

Write-Host "  Report saved to: $reportPath" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Opening report in browser..." -ForegroundColor Gray
Start-Process $reportPath

Write-Host ""
Write-Host "  ========================================" -ForegroundColor Cyan
Write-Host "   Scan complete! Check your desktop." -ForegroundColor Green
Write-Host "  ========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Visit polarguarded.com for unlimited" -ForegroundColor Gray
Write-Host "  online scanning and Pro features." -ForegroundColor Gray
Write-Host ""
