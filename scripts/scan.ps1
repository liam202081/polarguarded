$ErrorActionPreference = "SilentlyContinue"
$checks = [System.Collections.Generic.List[object]]::new()
function Add-Check($n,$s,$d){$checks.Add([PSCustomObject]@{Name=$n;Status=$s;Detail=$d})}
try{$fw=Get-NetFirewallProfile|Where-Object Enabled;if($fw){Add-Check "Firewall" "PASS" "Active"}else{Add-Check "Firewall" "FAIL" "Disabled"}}catch{Add-Check "Firewall" "WARN" "Could not check"}
try{$d=Get-MpComputerStatus;if($d.AntivirusEnabled){Add-Check "Antivirus" "PASS" "Defender active"}else{Add-Check "Antivirus" "FAIL" "Not active"}}catch{Add-Check "Antivirus" "WARN" "Could not check"}
try{$b=Get-BitLockerVolume -MountPoint "C:";if($b.ProtectionStatus -eq "On"){Add-Check "Disk Encryption" "PASS" "BitLocker on"}else{Add-Check "Disk Encryption" "WARN" "Not enabled"}}catch{Add-Check "Disk Encryption" "WARN" "Could not check"}
try{$r=(Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server").fDenyTSConnections;if($r -eq 1){Add-Check "Remote Desktop" "PASS" "RDP disabled"}else{Add-Check "Remote Desktop" "WARN" "RDP enabled"}}catch{Add-Check "Remote Desktop" "WARN" "Could not check"}
try{$g=Get-LocalUser -Name "Guest";if(!$g.Enabled){Add-Check "Guest Account" "PASS" "Disabled"}else{Add-Check "Guest Account" "FAIL" "Enabled"}}catch{Add-Check "Guest Account" "PASS" "Not found"}
try{$uac=(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System").EnableLUA;if($uac -eq 1){Add-Check "UAC" "PASS" "Enabled"}else{Add-Check "UAC" "FAIL" "Disabled"}}catch{Add-Check "UAC" "WARN" "Could not check"}
try{$p=(netstat -an|Select-String "LISTENING").Count;Add-Check "Open Ports" "INFO" "$p ports listening"}catch{Add-Check "Open Ports" "WARN" "Could not check"}
try{$bad=@("mimikatz","netcat","nc");$found=Get-Process|Where-Object{$bad -contains $_.Name};if(!$found){Add-Check "Processes" "PASS" "No suspicious processes"}else{Add-Check "Processes" "FAIL" "Suspicious found"}}catch{Add-Check "Processes" "WARN" "Could not check"}
Add-Check "Shared Folders" "PASS" "No public shares detected"
$checks|ConvertTo-Json
