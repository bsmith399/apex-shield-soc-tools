# log_analyzer.py
# Apex Shield SOC Tools -- Log Analysis Utility
# Module 7 Project
# Reads an authentication log file, identifies failed login attempts,
# and generates a formatted analysis report and email alerts.
#
# Usage: python3 log_analyzer.py [log_file] [--output report.txt] [--verbose]
# Output: analysis_report.txt (or custom file)

import re                          # Regular expressions -- for IP address extraction
from collections import Counter    # Counter -- for counting IP occurrences
from datetime import datetime      # datetime -- for timestamping the report
import argparse                    # argparse -- for command-line arguments
import os                          # os -- for file path validation
import smtplib                     # smtplib -- for sending email alerts
from email.mime.text import MIMEText # MIMEText -- for formatting email content
import statistics                  # statistics -- for mean and stdev calculations


def parse_arguments():
    """
    Parse command-line arguments.
    
    Usage: python3 log_analyzer.py [log_file] [--output report.txt] [--verbose]
    """
    parser = argparse.ArgumentParser(
        description="Apex Shield SOC Log Analyzer -- Detect failed login patterns",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example: python3 log_analyzer.py auth.log --output report.txt"
    )
    
    parser.add_argument(
        "log_file",
        nargs="?",                       # '?' means optional
        default="sample_auth.log",         # default if not provided
        help="Path to the log file to analyze (default: sample_auth.log)"
    )
    
    parser.add_argument(
        "--output", "-o",
        default="analysis_report.txt",
        help="Output report file path (default: analysis_report.txt)"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",               # flag: True if present, False if absent
        help="Show detailed output including all failed login entries"
    )
    
    return parser.parse_args()


def read_log_file(filepath):
    """
    Read a log file and return all lines as a list of strings.
    Returns an empty list and prints an error if the file cannot be read.
    """
    lines = []
    try:
        with open(filepath, "r") as f:
            for line in f:
                clean = line.strip()
                if clean:
                    lines.append(clean)
    except FileNotFoundError:
        print(f"[!] ERROR: Log file not found: {filepath}")
        print(f"[!] Make sure {filepath} exists in the same folder as this script.")
    except PermissionError:
        print(f"[!] ERROR: Permission denied reading: {filepath}")
    return lines


def find_failed_logins(lines):
    """
    Filter a list of log lines to return only failed login attempts.
    """
    failed = []
    for line in lines:
        if "Failed" in line or "authentication failure" in line.lower():
            failed.append(line)
    return failed


def extract_ip_addresses(lines):
    """
    Extract all IP addresses from a list of log lines using regex.
    """
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    
    all_ips = []
    for line in lines:
        matches = ip_pattern.findall(line)
        all_ips.extend(matches)
    
    return all_ips


def flag_anomalies(ip_counts, z_threshold=2.0):
    """
    Identify IP addresses whose failure count is statistically unusual
    compared to the overall distribution.
    
    Uses Z-score: how many standard deviations a value is from the mean.
    A Z-score above z_threshold indicates a statistical outlier.
    
    Parameters:
        ip_counts (Counter): IP addresses and their failure counts
        z_threshold (float): Z-score cutoff for flagging (default: 2.0)
    
    Returns:
        list: Tuples of (ip, count, z_score) for anomalous IPs
    """
    if len(ip_counts) < 2:
        return []   # Need at least 2 data points for statistics
    
    counts = list(ip_counts.values())     # Just the numbers
    mean   = statistics.mean(counts)
    stdev  = statistics.stdev(counts)
    
    if stdev == 0:
        return []   # All counts are equal: no anomaly possible
    
    anomalies = []
    for ip, count in ip_counts.items():
        z_score = (count - mean) / stdev
        if z_score > z_threshold:
            anomalies.append((ip, count, round(z_score, 2)))
    
    return sorted(anomalies, key=lambda x: x[2], reverse=True)


def send_alert_email(ip, count, smtp_server="localhost", port=25):
    """
    Sends an email alert for a potential brute-force IP.
    Includes error handling and clean resource management.
    """
    msg = MIMEText(f"Security Alert: IP {ip} has triggered {count} failed login attempts.")
    msg['Subject'] = '[SOC Alert] Potential Brute-Force Detected'
    msg['From'] = 'soc@apex.local'
    msg['To'] = 'analyst@apex.local'

    try:
        with smtplib.SMTP(smtp_server, port, timeout=5) as server:
            server.send_message(msg)
            print(f"[+] Email alert sent successfully for IP: {ip}")
    except smtplib.SMTPException as e:
        print(f"[!] WARNING: Failed to send SMTP email alert for {ip}: {e}")
    except Exception as e:
        print(f"[!] WARNING: Network error while sending alert for {ip}: {e}")


def generate_report(failed_logins, ip_counts, output_file, log_file):
    """
    Write a formatted analysis report to a text file.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(output_file, "w") as f:
        # Report header
        f.write("=" * 55 + "\n")
        f.write("   APEX SHIELD SOC -- FAILED LOGIN ANALYSIS REPORT\n")
        f.write("=" * 55 + "\n")
        f.write(f"   Generated: {timestamp}\n")
        f.write(f"   Log File:  {log_file}\n")
        f.write("=" * 55 + "\n\n")

        # Summary section
        f.write(f"SUMMARY\n")
        f.write("-" * 30 + "\n")
        f.write(f"Total failed login attempts: {len(failed_logins)}\n")
        f.write(f"Unique source IPs: {len(ip_counts)}\n\n")

        # Top IPs section
        f.write("TOP SOURCE IP ADDRESSES\n")
        f.write("-" * 30 + "\n")
        for ip, count in ip_counts.most_common():
            flag = "  <-- INVESTIGATE" if count >= 3 else ""
            f.write(f"   {ip:<20} {count:>3} attempts{flag}\n")

        # Statistical Anomaly Analysis section
        anomalies = flag_anomalies(ip_counts)
        f.write("\n\nSTATISTICAL ANOMALY ANALYSIS\n")
        f.write("-" * 30 + "\n")
        if anomalies:
            f.write("  IPs with statistically unusual failure rates:\n")
            for ip, count, z_score in anomalies:
                f.write(f"  {ip:<20} {count:>3} failures  Z-score: {z_score}\n")
        else:
            f.write("  No statistical outliers detected in this dataset.\n")
            f.write("  (Note: Small datasets with balanced counts may not surface anomalies)\n")

        # Full failed login log
        f.write("\n\nFULL FAILED LOGIN LOG\n")
        f.write("-" * 30 + "\n")
        for entry in failed_logins:
            f.write(f"   {entry}\n")

    print(f"[+] Report written to: {output_file}")


def main():
    """Main execution function using command-line arguments and automated alerting."""
    args = parse_arguments()
    
    log_file    = args.log_file
    output_file = args.output
    verbose     = args.verbose
    
    # Validate input file exists
    if not os.path.isfile(log_file):
        print(f"[!] Error: File not found: {log_file}")
        print(f"[!] Usage: python log_analyzer.py [log_file]")
        return
    
    print(f"\n[*] Log file: {log_file}")
    print(f"[*] Output:   {output_file}")
    
    lines = read_log_file(log_file)
    if not lines:
        print("[!] No log data loaded. Exiting.")
        return
    
    failed = find_failed_logins(lines)
    ips    = extract_ip_addresses(failed)
    ip_counts = Counter(ips)
    
    if verbose:
        print(f"\n[*] All failed login entries ({len(failed)}):")
        for entry in failed:
            print(f"    {entry}")
    
    print(f"\n[*] Top IPs & Threat Evaluation:")
    for ip, count in ip_counts.most_common(5):
        flag = " <-- INVESTIGATE" if count >= 3 else ""
        print(f"    {ip:<20} {count:>3} failures{flag}")
        
        # Automatically trigger an email alert if the IP hits the threshold
        if count >= 3:
            send_alert_email(ip, count)
    
    generate_report(failed, ip_counts, output_file, log_file)
    print(f"\n[+] Analysis complete. Report saved to: {output_file}\n")


if __name__ == "__main__":
    main()