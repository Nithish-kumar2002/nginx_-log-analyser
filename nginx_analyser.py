import re
import argparse
from collections import Counter


# Regex pattern for Nginx access log
LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) .*? '
    r'"(?P<method>\S+) (?P<path>\S+) HTTP/[^"]+" '
    r'(?P<status>\d{3}) (?P<size>\d+)'
)


# CLI argument
parser = argparse.ArgumentParser(
    description="Analyse an Nginx access log"
)

parser.add_argument(
    "logfile",
    help="Path to Nginx access log"
)

args = parser.parse_args()


# Counters
ip_counter = Counter()
path_counter = Counter()
status_counter = Counter()


# Read and parse log file
with open(args.logfile, "r") as file:

    for line in file:

        match = LOG_PATTERN.match(line)

        # Skip invalid lines
        if not match:
            continue

        ip = match.group("ip")
        path = match.group("path")
        status = match.group("status")

        # Day 1
        ip_counter[ip] += 1
        path_counter[path] += 1

        # Day 2
        status_counter[status] += 1


# --------------------------------
# OUTPUT
# --------------------------------

print("=" * 40)
print("       NGINX LOG ANALYSER")
print("=" * 40)


# Total requests
total_requests = sum(ip_counter.values())

print(f"\nTotal Requests: {total_requests}")


# Top IPs
print("\nTop 5 IPs:")

for i, (ip, count) in enumerate(
    ip_counter.most_common(5), start=1
):
    print(f"{i}. {ip} -> {count} requests")


# Top Paths
print("\nTop 5 Paths:")

for i, (path, count) in enumerate(
    path_counter.most_common(5), start=1
):
    print(f"{i}. {path} -> {count} requests")


# Status codes
print("\nResponse Codes:")

for status, count in status_counter.most_common():
    print(f"{status} -> {count}")


# Status groups
status_groups = Counter()

for status, count in status_counter.items():

    category = f"{status[0]}xx"

    status_groups[category] += count


print("\nResponse Breakdown:")

for category, count in sorted(status_groups.items()):

    print(f"{category} -> {count}")
