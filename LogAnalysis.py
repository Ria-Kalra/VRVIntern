import re
import csv
from collections import Counter, defaultdict

# Configurable threshold for suspicious activity detection
FAILED_LOGIN_THRESHOLD = 10

# File paths
LOG_FILE = 'sample.log'
OUTPUT_FILE = 'log_analysis_results.csv'

def parse_log_file(file_path):
    """Parse the log file and extract relevant information."""
    ip_requests = Counter()
    endpoint_requests = Counter()
    failed_logins = Counter()

    with open(file_path, 'r') as file:
        for line in file:
            # Extract IP address
            ip_match = re.search(r'^(\d+\.\d+\.\d+\.\d+)', line)
            ip = ip_match.group(0) if ip_match else None

            # Extract endpoint
            endpoint_match = re.search(r'"[A-Z]+\s(\S+)', line)
            endpoint = endpoint_match.group(1) if endpoint_match else None

            # Extract status code
            status_match = re.search(r'"\s(\d{3})\s', line)
            status_code = int(status_match.group(1)) if status_match else None

            if ip:
                ip_requests[ip] += 1
            if endpoint:
                endpoint_requests[endpoint] += 1
            if status_code == 401 and ip:
                failed_logins[ip] += 1

    return ip_requests, endpoint_requests, failed_logins

def save_to_csv(ip_requests, most_accessed_endpoint, failed_logins, output_file):
    """Save the analysis results to a CSV file."""
    with open(output_file, 'w', newline='') as file:
        writer = csv.writer(file)

        # Write IP Requests
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_requests.most_common():
            writer.writerow([ip, count])

        # Write Most Accessed Endpoint
        writer.writerow([])  # Blank row
        writer.writerow(['Most Accessed Endpoint', 'Access Count'])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

        # Write Suspicious Activity
        writer.writerow([])  # Blank row
        writer.writerow(['Suspicious IP Address', 'Failed Login Count'])
        for ip, count in failed_logins.items():
            if count > FAILED_LOGIN_THRESHOLD:
                writer.writerow([ip, count])

def main():
    """Main function to run the log analysis."""
    print("Analyzing log file...")

    # Parse the log file
    ip_requests, endpoint_requests, failed_logins = parse_log_file(LOG_FILE)

    # Identify the most accessed endpoint
    most_accessed_endpoint = endpoint_requests.most_common(1)[0]

    # Display results
    print("Requests per IP Address:")
    for ip, count in ip_requests.most_common():
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    for ip, count in failed_logins.items():
        if count > FAILED_LOGIN_THRESHOLD:
            print(f"{ip:<20} {count}")

    # Save results to CSV
    save_to_csv(ip_requests, most_accessed_endpoint, failed_logins, OUTPUT_FILE)
    print(f"\nResults saved to {OUTPUT_FILE}")

if __name__ == '__main__':
    main()
