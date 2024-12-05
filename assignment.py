import csv
from collections import Counter
ip_address = []
ep = []
threshold = 10
with open("sample.log", "r") as file:
    lines = file.readlines()

    with open("output_file.csv", "w", newline="") as output_file:

        writer = csv.writer(output_file)

        # 1. COUNT REQUESTS PER IP ADDRESS

        for line in lines:
            ip = line.split()[0]
            ip_address.append(ip)

        ip_count = Counter(ip_address)
        sorted_address = sorted(ip_count.items(), key=lambda x: x[1], reverse=True)

        writer.writerow(["IP Address", "Request Counts"])
        for ip, count in sorted_address:
            writer.writerow([ip, count])

        # 2. MOST FREQUENTLY ACCESSED ENDPOINT

        for line in lines:
            end_point = line.split()[6]
            ep.append(end_point)

        ep_count = Counter(ep)
        most_accessed_ep = max(ep_count.items(), key=lambda x: x[1])
        writer.writerow([])
        writer.writerow(["Most Frequently Accessed Endpoint:"])
        writer.writerow([most_accessed_ep[0], f"(Accessed {most_accessed_ep[1]} times)"])

    # 3. DETECT SUSPICIOUS ACTIVITY

        failed_login_ip = {}
        for line in lines:
            end_point = line.split()[6]
            if end_point == "/login" and "401" in line and "invalid credentials" in line.lower():
                failed_ip = line.split()[0]

                if failed_ip in failed_login_ip:
                    failed_login_ip[failed_ip] = failed_login_ip[failed_ip]+1
                else:
                    failed_login_ip[failed_ip] = 1

        # [(ip_Address, count), (ip2, count2), ....]
        failed_ip_above_threshold = []

        for item in failed_login_ip.items():
            ip = item[0]
            count = item[1]
            # check if the count is greater than threshold
            if count >= threshold:
                failed_ip_above_threshold.append((ip, count))
        writer.writerow([])
        writer.writerow(["Suspicious Activity Detected:"])
        writer.writerow([f"IP Address", "Request Counts"])
        for ip, count in failed_ip_above_threshold:
            writer.writerow([ip, count])
