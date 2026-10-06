# security_report.ps1
# Apex Shield SOC Tools -- Windows Security Snapshot
# Module 7 Project
#
# Collects: Disk space, running services, local user accounts
# Output: Timestamped .txt file in C:\SecurityReports\
#
# Run as Administrator for complete data

# --- Configuration ---
$reportFolder = "C:\SecurityReports"
$timestamp    = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$reportFile   = "$reportFolder\security_report_$timestamp.txt"

# Create the output folder if it doesn't exist
if (-not (Test-Path $reportFolder)) {
    New-Item -ItemType Directory -Path $reportFolder | Out-Null
    Write-Host "[+] Created folder: $reportFolder"
}

# Helper function: write a section header to the report
function Write-Section {
    param([string]$Title)
    Add-Content -Path $reportFile -Value ""
    Add-Content -Path $reportFile -Value ("=" * 55)
    Add-Content -Path $reportFile -Value "  $Title"
    Add-Content -Path $reportFile -Value ("=" * 55)
}

# Report header
$header = @"
=======================================================
  APEX SHIELD SOC -- WINDOWS SECURITY REPORT
=======================================================
  Generated : $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
  Computer  : $env:COMPUTERNAME
  User      : $env:USERNAME
=======================================================
"@
Set-Content -Path $reportFile -Value $header
Write-Host "[*] Starting security report..."
Write-Host "[*] Output: $reportFile"

# --- Section 1: Disk Space ---
Write-Section "DISK SPACE"

Write-Host "[*] Collecting disk space..."

Get-CimInstance Win32_LogicalDisk |
    Where-Object {$_.DriveType -eq 3} |   # DriveType 3 = local fixed disk
    ForEach-Object {
        $totalGB = [math]::Round($_.Size / 1GB, 1)
        $freeGB  = [math]::Round($_.FreeSpace / 1GB, 1)
        $usedGB  = $totalGB - $freeGB
        $pctFree = [math]::Round(($_.FreeSpace / $_.Size) * 100, 1)

        $line = "  Drive {0}: Total={1}GB  Used={2}GB  Free={3}GB  ({4}% free)" `
                -f $_.DeviceID, $totalGB, $usedGB, $freeGB, $pctFree

        Add-Content -Path $reportFile -Value $line

        # Alert if less than 15% free space
        if ($pctFree -lt 15) {
            $alert = "  *** WARNING: Drive $($_.DeviceID) is low on space! ***"
            Add-Content -Path $reportFile -Value $alert
            Write-Host "[!] $alert" -ForegroundColor Yellow
        }
    }

Write-Host "[+] Disk space collected."

# --- Section 2: Running Services ---
Write-Section "RUNNING SERVICES"

Write-Host "[*] Collecting running services..."

$services = Get-CimInstance Win32_Service |
    Where-Object {$_.State -eq "Running"} |
    Sort-Object DisplayName |
    Select-Object Name, DisplayName, StartMode, State

$serviceCount = ($services | Measure-Object).Count
Add-Content -Path $reportFile -Value "  Total running services: $serviceCount"
Add-Content -Path $reportFile -Value ""

foreach ($svc in $services) {
    $line = "  {0,-35} [{1}]" -f $svc.DisplayName, $svc.StartMode
    Add-Content -Path $reportFile -Value $line
}

Write-Host "[+] Services collected: $serviceCount running."

# --- Section 3: Auto-Start Services That Are Stopped (Security Flag) ---
Write-Section "AUTO-START SERVICES CURRENTLY STOPPED"

$stoppedAuto = Get-CimInstance Win32_Service |
    Where-Object {$_.StartMode -eq "Auto" -and $_.State -eq "Stopped"} |
    Sort-Object DisplayName

if ($stoppedAuto) {
    Add-Content -Path $reportFile -Value "  *** These services are set to auto-start but are stopped: ***"
    foreach ($svc in $stoppedAuto) {
        Add-Content -Path $reportFile -Value "    - $($svc.DisplayName)"
    }
    Write-Host "[!] Found $($stoppedAuto.Count) auto-start services that are stopped." -ForegroundColor Yellow
} else {
    Add-Content -Path $reportFile -Value "  All auto-start services are running. OK."
    Write-Host "[+] All auto-start services running."
}

# --- Section 4: Local User Accounts ---
Write-Section "LOCAL USER ACCOUNTS"

Write-Host "[*] Collecting local user accounts..."

$users = Get-LocalUser | Sort-Object Name

$enabledCount  = ($users | Where-Object {$_.Enabled}).Count
$disabledCount = ($users | Where-Object {-not $_.Enabled}).Count

Add-Content -Path $reportFile -Value "  Total accounts : $($users.Count)"
Add-Content -Path $reportFile -Value "  Enabled        : $enabledCount"
Add-Content -Path $reportFile -Value "  Disabled       : $disabledCount"
Add-Content -Path $reportFile -Value ""

foreach ($user in $users) {
    $status      = if ($user.Enabled) { "ENABLED " } else { "DISABLED" }
    $lastLogon   = if ($user.LastLogon) { $user.LastLogon.ToString("yyyy-MM-dd") } else { "Never" }
    $pwdExpires  = if ($user.PasswordExpires) { $user.PasswordExpires.ToString("yyyy-MM-dd") } else { "Never" }

    $line = "  [{0}]  {1,-20}  Last Logon: {2,-12}  Pwd Expires: {3}" `
            -f $status, $user.Name, $lastLogon, $pwdExpires
    Add-Content -Path $reportFile -Value $line
}

Write-Host "[+] User accounts collected: $($users.Count) total."