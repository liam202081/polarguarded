#!/bin/bash
# ============================================================
# PolarGuarded Security Scanner v1.0 — macOS
# Canadian Cybersecurity — polarguarded.com
# ============================================================

SCAN_DATE=$(date "+%B %d, %Y %H:%M")
HOSTNAME=$(hostname)
USERNAME=$(whoami)
OS_NAME=$(sw_vers -productName)
OS_VERSION=$(sw_vers -productVersion)
REPORT_PATH="$HOME/Desktop/PolarGuarded-Report-$(date '+%Y-%m-%d-%H%M').html"

echo ""
echo "  ========================================"
echo "   POLARGUARDED SECURITY SCANNER v1.0"
echo "   polarguarded.com"
echo "  ========================================"
echo ""
echo "  Computer : $HOSTNAME"
echo "  User     : $USERNAME"
echo "  OS       : $OS_NAME $OS_VERSION"
echo "  Date     : $SCAN_DATE"
echo ""

CHECKS_JSON=""

add_check() {
    local category="$1"
    local check="$2"
    local status="$3"
    local detail="$4"
    local risk="$5"
    CHECKS_JSON="${CHECKS_JSON}<CHECK><CATEGORY>${category}</CATEGORY><NAME>${check}</NAME><STATUS>${status}</STATUS><DETAIL>${detail}</DETAIL><RISK>${risk}</RISK></CHECK>"
}

# ── 1. FIREWALL ──────────────────────────────────────────────
echo "  [1/12] Checking Firewall..."
FW=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null)
if echo "$FW" | grep -q "enabled"; then
    add_check "Firewall" "Application Firewall" "PASS" "Firewall is enabled. Incoming connections are being filtered." "low"
else
    add_check "Firewall" "Application Firewall" "FAIL" "Firewall is DISABLED. Enable it in System Settings > Network > Firewall." "critical"
fi

# ── 2. FILEVAULT ─────────────────────────────────────────────
echo "  [2/12] Checking FileVault encryption..."
FV=$(fdesetup status 2>/dev/null)
if echo "$FV" | grep -q "FileVault is On"; then
    add_check "Encryption" "FileVault Disk Encryption" "PASS" "FileVault is ON. Your disk is encrypted and protected if your Mac is lost or stolen." "low"
else
    add_check "Encryption" "FileVault Disk Encryption" "FAIL" "FileVault is OFF. Enable it in System Settings > Privacy & Security > FileVault." "high"
fi

# ── 3. SYSTEM UPDATES ────────────────────────────────────────
echo "  [3/12] Checking system updates..."
UPDATES=$(softwareupdate -l 2>&1)
if echo "$UPDATES" | grep -q "No new software available"; then
    add_check "Updates" "macOS System Updates" "PASS" "Your Mac is fully up to date. No pending updates found." "low"
else
    COUNT=$(echo "$UPDATES" | grep -c "^\*" 2>/dev/null || echo "1")
    add_check "Updates" "macOS System Updates" "WARN" "${COUNT} update(s) available. Install them to stay protected against known vulnerabilities." "medium"
fi

# ── 4. GATEKEEPER ────────────────────────────────────────────
echo "  [4/12] Checking Gatekeeper..."
GK=$(spctl --status 2>/dev/null)
if echo "$GK" | grep -q "assessments enabled"; then
    add_check "Security" "Gatekeeper" "PASS" "Gatekeeper is enabled. Only apps from trusted sources can be installed." "low"
else
    add_check "Security" "Gatekeeper" "FAIL" "Gatekeeper is DISABLED. Any app can be installed regardless of source. Re-enable in System Settings." "critical"
fi

# ── 5. REMOTE LOGIN (SSH) ────────────────────────────────────
echo "  [5/12] Checking Remote Login..."
SSH=$(systemsetup -getremotelogin 2>/dev/null)
if echo "$SSH" | grep -q "Off"; then
    add_check "Network" "Remote Login (SSH)" "PASS" "Remote Login is disabled. Good — SSH access is not exposed." "low"
else
    add_check "Network" "Remote Login (SSH)" "WARN" "Remote Login (SSH) is ENABLED. Disable it in System Settings > General > Sharing if not needed." "high"
fi

# ── 6. REMOTE DESKTOP ────────────────────────────────────────
echo "  [6/12] Checking Remote Desktop..."
RD=$(systemsetup -getremoteappleevents 2>/dev/null)
if echo "$RD" | grep -q "Off"; then
    add_check "Network" "Remote Apple Events" "PASS" "Remote Apple Events are disabled." "low"
else
    add_check "Network" "Remote Apple Events" "WARN" "Remote Apple Events are ENABLED. Disable in System Settings > General > Sharing if not needed." "medium"
fi

# ── 7. SCREEN SHARING ────────────────────────────────────────
echo "  [7/12] Checking Screen Sharing..."
SS=$(launchctl list 2>/dev/null | grep -i "screensharing")
if [ -z "$SS" ]; then
    add_check "Network" "Screen Sharing" "PASS" "Screen Sharing is disabled. Good." "low"
else
    add_check "Network" "Screen Sharing" "WARN" "Screen Sharing appears to be active. Disable in System Settings > General > Sharing if not needed." "medium"
fi

# ── 8. GUEST ACCOUNT ─────────────────────────────────────────
echo "  [8/12] Checking Guest account..."
GUEST=$(defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null)
if [ "$GUEST" = "0" ] || [ -z "$GUEST" ]; then
    add_check "Accounts" "Guest Account" "PASS" "Guest account is disabled. Unauthorized local access is restricted." "low"
else
    add_check "Accounts" "Guest Account" "FAIL" "Guest account is ENABLED. Disable it in System Settings > Users & Groups." "high"
fi

# ── 9. AUTOMATIC LOGIN ───────────────────────────────────────
echo "  [9/12] Checking Automatic Login..."
AL=$(defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null)
if [ -z "$AL" ]; then
    add_check "Accounts" "Automatic Login" "PASS" "Automatic login is disabled. A password is required to log in." "low"
else
    add_check "Accounts" "Automatic Login" "FAIL" "Automatic login is ENABLED for user: $AL. Anyone can access this Mac without a password." "critical"
fi

# ── 10. OPEN PORTS ───────────────────────────────────────────
echo "  [10/12] Scanning open ports..."
RISKY_PORTS="21 23 25 135 139 445 3389 5900 8080"
OPEN_PORTS=$(netstat -an 2>/dev/null | grep LISTEN | awk '{print $4}' | rev | cut -d. -f1 | rev | sort -un)
RISKY_FOUND=""
for port in $RISKY_PORTS; do
    if echo "$OPEN_PORTS" | grep -qw "$port"; then
        RISKY_FOUND="$RISKY_FOUND $port"
    fi
done
if [ -z "$RISKY_FOUND" ]; then
    add_check "Network" "Open Ports" "PASS" "No high-risk ports detected." "low"
else
    add_check "Network" "Open Ports" "FAIL" "High-risk ports open:$RISKY_FOUND. These can be exploited by attackers." "high"
fi

# ── 11. SUSPICIOUS PROCESSES ─────────────────────────────────
echo "  [11/12] Checking running processes..."
SUSPICIOUS="mimikatz meterpreter netcat nmap wireshark psexec"
FOUND_PROCS=""
for proc in $SUSPICIOUS; do
    if pgrep -i "$proc" > /dev/null 2>&1; then
        FOUND_PROCS="$FOUND_PROCS $proc"
    fi
done
if [ -z "$FOUND_PROCS" ]; then
    add_check "Processes" "Suspicious Processes" "PASS" "No known suspicious processes detected." "low"
else
    add_check "Processes" "Suspicious Processes" "FAIL" "Suspicious process(es) detected:$FOUND_PROCS. Investigate immediately." "critical"
fi

# ── 12. SIP STATUS ───────────────────────────────────────────
echo "  [12/12] Checking System Integrity Protection..."
SIP=$(csrutil status 2>/dev/null)
if echo "$SIP" | grep -q "enabled"; then
    add_check "Security" "System Integrity Protection (SIP)" "PASS" "SIP is enabled. Core system files are protected from modification." "low"
else
    add_check "Security" "System Integrity Protection (SIP)" "FAIL" "SIP is DISABLED. Core system files are unprotected. Re-enable via macOS Recovery." "critical"
fi

# ── CALCULATE SCORE ──────────────────────────────────────────
TOTAL=12
PASSED=$(echo "$CHECKS_JSON" | grep -o "<STATUS>PASS</STATUS>" | wc -l | tr -d ' ')
WARNINGS=$(echo "$CHECKS_JSON" | grep -o "<STATUS>WARN</STATUS>" | wc -l | tr -d ' ')
FAILED=$(echo "$CHECKS_JSON" | grep -o "<STATUS>FAIL</STATUS>" | wc -l | tr -d ' ')
SCORE=$(( (PASSED * 100) / TOTAL ))

if [ $SCORE -ge 90 ]; then GRADE="A"
elif [ $SCORE -ge 75 ]; then GRADE="B"
elif [ $SCORE -ge 60 ]; then GRADE="C"
elif [ $SCORE -ge 40 ]; then GRADE="D"
else GRADE="F"
fi

if [ $SCORE -ge 90 ]; then GRADE_COLOR="#3fd68a"
elif [ $SCORE -ge 75 ]; then GRADE_COLOR="#5bc8f5"
elif [ $SCORE -ge 60 ]; then GRADE_COLOR="#f5a623"
else GRADE_COLOR="#ff4f4f"
fi

echo ""
echo "  ========================================"
echo "   SCAN COMPLETE"
echo "  ========================================"
echo "   Score   : $SCORE/100 (Grade: $GRADE)"
echo "   Passed  : $PASSED checks"
echo "   Warnings: $WARNINGS checks"
echo "   Failed  : $FAILED checks"
echo ""
echo "  Generating HTML report..."

# ── BUILD HTML ───────────────────────────────────────────────
build_checks_html() {
    local html=""
    local current_cat=""
    
    while IFS= read -r line; do
        cat=$(echo "$line" | sed 's/.*<CATEGORY>\(.*\)<\/CATEGORY>.*/\1/')
        name=$(echo "$line" | sed 's/.*<NAME>\(.*\)<\/NAME>.*/\1/')
        status=$(echo "$line" | sed 's/.*<STATUS>\(.*\)<\/STATUS>.*/\1/')
        detail=$(echo "$line" | sed 's/.*<DETAIL>\(.*\)<\/DETAIL>.*/\1/')
        
        if [ "$cat" != "$current_cat" ]; then
            if [ -n "$current_cat" ]; then html="${html}</div>"; fi
            html="${html}<div class='category'><div class='category-label'>${cat}</div>"
            current_cat="$cat"
        fi
        
        if [ "$status" = "PASS" ]; then
            color="#3fd68a"; bg="rgba(63,214,138,0.08)"; border="rgba(63,214,138,0.2)"; icon="✓"
        elif [ "$status" = "WARN" ]; then
            color="#f5a623"; bg="rgba(245,166,35,0.08)"; border="rgba(245,166,35,0.2)"; icon="⚠"
        else
            color="#ff4f4f"; bg="rgba(255,79,79,0.08)"; border="rgba(255,79,79,0.2)"; icon="✕"
        fi
        
        html="${html}<div class='check-item' style='background:${bg};border:1px solid ${border};'><div class='check-header'><span class='check-icon' style='color:${color};'>${icon}</span><span class='check-name'>${name}</span><span class='check-badge' style='background:${bg};color:${color};border:1px solid ${border};'>${status}</span></div><div class='check-detail'>${detail}</div></div>"
        
    done < <(echo "$CHECKS_JSON" | grep -o "<CHECK>.*</CHECK>" | sed 's/<\/CHECK><CHECK>/\n/g' | sed 's/<CHECK>//g' | sed 's/<\/CHECK>//g')
    
    if [ -n "$current_cat" ]; then html="${html}</div>"; fi
    echo "$html"
}

CHECKS_HTML=$(build_checks_html)

cat > "$REPORT_PATH" << HTMLEOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>PolarGuarded Security Report — $HOSTNAME</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #090d13; color: #e8f0f8; font-family: -apple-system, 'Segoe UI', Arial, sans-serif; font-size: 15px; line-height: 1.6; }
  .header { background: #0e1520; border-bottom: 1px solid #1a2a40; padding: 32px 48px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 20px; }
  .brand { font-size: 1.3rem; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; color: #e8f0f8; }
  .brand span { color: #5bc8f5; }
  .header-meta { font-size: 0.8rem; color: #6b8aaa; font-family: monospace; line-height: 1.8; text-align: right; }
  .score-bar { background: #0e1520; border-bottom: 1px solid #1a2a40; padding: 40px 48px; display: flex; align-items: center; gap: 48px; flex-wrap: wrap; }
  .score-circle { width: 120px; height: 120px; border-radius: 50%; border: 4px solid $GRADE_COLOR; display: flex; flex-direction: column; align-items: center; justify-content: center; flex-shrink: 0; box-shadow: 0 0 30px ${GRADE_COLOR}33; }
  .score-num { font-size: 2.2rem; font-weight: 700; color: $GRADE_COLOR; font-family: monospace; line-height: 1; }
  .score-label { font-size: 0.65rem; color: #6b8aaa; letter-spacing: 0.15em; text-transform: uppercase; margin-top: 4px; }
  .score-grade { font-size: 0.85rem; color: $GRADE_COLOR; font-weight: 700; margin-top: 2px; }
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
  .platform-badge { display: inline-block; background: rgba(91,200,245,0.1); border: 1px solid #2a6e8a; color: #5bc8f5; font-family: monospace; font-size: 0.65rem; letter-spacing: 0.1em; padding: 3px 10px; border-radius: 3px; margin-left: 8px; }
  @media (max-width: 600px) {
    .header, .score-bar, .system-info, .content, .footer-report { padding-left: 20px; padding-right: 20px; }
    .header { flex-direction: column; }
    .header-meta { text-align: left; }
  }
</style>
</head>
<body>

<div class="header">
  <div class="brand">Polar<span>Guarded</span> <span class="platform-badge">macOS</span></div>
  <div class="header-meta">
    SECURITY SCAN REPORT<br>
    Generated: $SCAN_DATE<br>
    polarguarded.com
  </div>
</div>

<div class="score-bar">
  <div class="score-circle">
    <div class="score-num">$SCORE</div>
    <div class="score-label">Score</div>
    <div class="score-grade">Grade $GRADE</div>
  </div>
  <div class="score-stats">
    <div class="stat-item"><div class="stat-num green">$PASSED</div><div class="stat-label">Passed</div></div>
    <div class="stat-item"><div class="stat-num yellow">$WARNINGS</div><div class="stat-label">Warnings</div></div>
    <div class="stat-item"><div class="stat-num red">$FAILED</div><div class="stat-label">Failed</div></div>
    <div class="stat-item"><div class="stat-num">$TOTAL</div><div class="stat-label">Total Checks</div></div>
  </div>
</div>

<div class="system-info">
  <div class="sys-item">Computer: <span>$HOSTNAME</span></div>
  <div class="sys-item">User: <span>$USERNAME</span></div>
  <div class="sys-item">OS: <span>$OS_NAME $OS_VERSION</span></div>
</div>

<div class="content">
  $CHECKS_HTML

  <div class="cta-box">
    <h2>Stay Protected with PolarGuarded Pro</h2>
    <p>This Mac scan is just the start. PolarGuarded Pro gives you unlimited online scans for URLs, files, phone numbers, and emails — plus a built-in VPN to encrypt your connection on any network.</p>
    <a class="cta-btn" href="https://polarguarded.com/pricing.html">Upgrade to Pro — $9/mo CAD</a>
    <div class="cta-features">
      <div class="cta-feature">Unlimited URL & file scans</div>
      <div class="cta-feature">Phone scam detection</div>
      <div class="cta-feature">Email risk checker</div>
      <div class="cta-feature">PolarGuarded VPN</div>
      <div class="cta-feature">Cancel anytime</div>
    </div>
  </div>
</div>

<div class="footer-report">
  PolarGuarded Security Scanner v1.0 — macOS &nbsp;·&nbsp; polarguarded.com &nbsp;·&nbsp; Built in Canada 🇨🇦<br>
  This report was generated locally on your device. No data was sent to PolarGuarded servers.
</div>

</body>
</html>
HTMLEOF

echo "  Report saved to Desktop"
echo ""
echo "  Opening report..."
open "$REPORT_PATH"

echo ""
echo "  ========================================"
echo "   Scan complete! Check your desktop."
echo "  ========================================"
echo ""
echo "  Visit polarguarded.com for unlimited"
echo "  online scanning and Pro features."
echo ""
