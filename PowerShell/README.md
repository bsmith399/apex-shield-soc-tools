# PowerShell Security Scripts

## security_report.ps1

Windows security snapshot script designed for SOC auditing and system baselining. 

### Features
* Disk Space Analysis: Scans local fixed drives and alerts if free space drops below 15%.
* Running Services Collection: Enumerates all active Windows services.
* Security Flagging: Detects and flags configured auto-start services that are currently stopped.
* Local User Account Auditing: Reports total, enabled, and disabled accounts along with last logon timestamps and password expiration dates.
* Automated Reporting: Generates a timestamped `.txt` security report saved to `C:\SecurityReports\`.

### Requirements
* Windows OS
* PowerShell 5.1 or higher
* Administrator privileges

### Running the Script

Open your PowerShell terminal as an Administrator, adjust your session execution policy, and execute the script:

```powershell
Set-ExecutionPolicy RemoteSigned -Scope Process
.\security_report.ps1