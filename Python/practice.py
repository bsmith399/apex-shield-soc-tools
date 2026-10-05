# Step 1: Read the log file
with open("sample_auth.log", "r") as f:
    lines = f.readlines()

print(f"Loaded {len(lines)} log lines")

# Look at the first three lines
for line in lines[:3]:
    print(line.strip())

# Step 2: Find the failed login lines
failed_logins = []

for line in lines:
    clean = line.strip()
    if "Failed" in clean or "authentication failure" in clean.lower():
        failed_logins.append(clean)

print(f"\nFound {len(failed_logins)} failed login attempts:")
for entry in failed_logins:
    print(f"  {entry}")

    # Step 3: Extract IP addresses from failed login lines
# Each line looks like: ... from 192.168.40.10 port 54321 ...
# We can split by spaces and find the word after "from"

extracted_ips = []

for line in failed_logins:
    parts = line.split()    # Splits the line into a list of words
    if "from" in parts:
        from_index = parts.index("from")   # Find which position "from" is at
        ip = parts[from_index + 1]         # The word right after "from" is the IP
        extracted_ips.append(ip)

print(f"\nExtracted {len(extracted_ips)} IP addresses:")
for ip in extracted_ips:
    print(f"  {ip}")

# Step 4: Count how many times each IP appears
ip_counts = {}

for ip in extracted_ips:
    ip_counts[ip] = ip_counts.get(ip, 0) + 1

# Sort by count (highest first)
sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)

print("\nTop IP Addresses by Failed Attempts:")
for ip, count in sorted_ips:
    print(f"  {ip}: {count} attempts")


# Step 5: Write a formatted report
with open("practice_report.txt", "w") as report:
    report.write("LOG ANALYSIS REPORT\n")
    report.write("=" * 50 + "\n\n")
    report.write(f"Total log lines analyzed: {len(lines)}\n")
    report.write(f"Failed login attempts: {len(failed_logins)}\n\n")
    report.write("Top Source IPs:\n")
    for ip, count in sorted_ips:
        report.write(f"  {ip}: {count} attempts\n")

print("\nReport written to practice_report.txt")