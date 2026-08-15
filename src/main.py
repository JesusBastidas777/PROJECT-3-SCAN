














import sys

import json

from scanner.discovery import discover_hosts

from scanner.ports import scan_ports


def main():

    if len(sys.argv) != 2:

        print("Usage: python3 src/main.py <network>")

        return

    network = sys.argv[1]

    print("Network Scanner")

    print("")

    print(f"Target Network: {network}")

    active_hosts = discover_hosts(network)

    print()

    scan_results = []

    ports = [

    21,       # FTP
    22,       # SSH
    23,       # Telnet
    25,       # SMTP
    53,       # DNS
    80,       # HTTP
    110,      # POP3
    143,      # IMAP
    443,      # HTTPS
    445,      # SMB
    3389,     # RDP

    ]

    total_open_ports = 0

    total_closed_ports = 0

    for host in active_hosts:

        print()

        print(f"Scanning host: {host}")

        host_result = {

            "host": host,

            "ports": [],

            "open_ports": [],

            "open_count": 0,

            "closed_count": 0

        }


        results = scan_ports(host, ports)

        for result in results:

            host_result["ports"].append(result)

            if result["status"] == "OPEN":

                host_result["open_ports"].append(result["port"])

                host_result["open_count"] += 1

                total_open_ports += 1

            else:

                host_result["closed_count"] += 1

                total_closed_ports += 1

            print(f"{result['port']}/{result['protocol']}\t{result['status']}")

        scan_results.append(host_result)

    scan_data = {

        "network": network,

        "summary": {

            "active_hosts": len(active_hosts),

            "total_open_ports": total_open_ports,

            "total_closed_ports": total_closed_ports

         },

         "hosts": scan_results

    }

    with open("results/scan.json", "w") as file:

        json.dump(scan_data, file, indent=4)

    print()

    print("Results saved to results/scan.json")

    print()

    print("Active Hosts:")

    for host in active_hosts:

        print(host)


if __name__ == "__main__":

    main()


























