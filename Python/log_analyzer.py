# log_analyzer.py
# Apex Shield SOC Tools -- Log Analysis Utility
# Module 7 Project
# Reads an authentication log file, identifies failed login attempts,
# and generates a formatted analysis report.
#
# Usage: python3 log_analyzer.py [log_file] [--output report.txt] [--verbose]
# Output: analysis_report.txt (or custom file)

import re                    # Regular expressions -- for IP address extraction
from collections import Counter  # Counter -- for counting IP occurrences
from datetime import datetime   # datetime -- for timestamping the report
import argparse              # argparse -- for command-line arguments
import os                    # os -- for file path validation


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
        nargs="?",                          # '?' means optional
        default="sample_auth.log",          # default if not provided
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


def generate_report(failed_logins, ip_counts, output_file):
    """
    Write a formatted analysis report to a text file.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(output_file, "w") as f:
        # Report header
        f.write("=" * 55 + "\n")
        f.write("  APEX SHIELD SOC -- FAILED LOGIN ANALYSIS REPORT\n")
        f.write("=" * 55 + "\n")
        f.write(f"  Generated: {timestamp}\n")
        f.write(f"  Log File:  sample_auth.log\n")
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
            f.write(f"  {ip:<20} {count:>3} attempts{flag}\n")

        # Full failed login log
        f.write("\n\nFULL FAILED LOGIN LOG\n")
        f.write("-" * 30 + "\n")
        for entry in failed_logins:
            f.write(f"  {entry}\n")

    print(f"[+] Report written to: {output_file}")


def main():
    """Main execution function using command-line arguments."""
    args = parse_arguments()
    
    log_file   = args.log_file
    output_file = args.output
    verbose    = args.verbose
    
    # Validate input file exists
    if not os.path.isfile(log_file):
        print(f"[!] Error: File not found: {log_file}")
        print(f"[!] Usage: python3 log_analyzer.py [log_file]")
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
    
    print(f"\n[*] Top IPs:")
    for ip, count in ip_counts.most_common(5):
        flag = " <-- INVESTIGATE" if count >= 3 else ""
        print(f"    {ip:<20} {count:>3} failures{flag}")
    
    generate_report(failed, ip_counts, output_file)
    print(f"\n[+] Report: {output_file}\n")


if __name__ == "__main__":
    main()