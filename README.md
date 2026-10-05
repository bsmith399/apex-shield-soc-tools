# Python Security Scripts

## log_analyzer.py

A security log analysis tool that reads authentication logs, identifies
failed login attempts, and generates a formatted report.

### What It Does

- Reads a text-based security log file (SSH/sudo authentication logs)
- Identifies lines containing failed login attempts using keyword matching
- Extracts source IP addresses using regular expressions
- Counts and ranks IPs by number of failed attempts
- Flags IPs with 3 or more failures for investigation
- Writes a formatted analysis report to `analysis_report.txt`

### Usage

```bash
python3 log_analyzer.py
