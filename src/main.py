










import sys

import json

from scanner.discovery import discover_hosts

from scanner.ports import scan_port

def main():

    if len(sys.argv) != 2 :

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

    21,       #FTP
    22,       #SSH
    23,       #Telnet
    25,       #SMTP
    53,       #DNS
    80,       #HTTP
    110,      #POP3
    143,      #IMAP
    443,      #HTTPS
    445,      #SMB
    3389,     #RDP

    ]

    for host in active_hosts:

        print()

        print(f"Scanning host: {host}")

        for port in ports:

            result = scan_port(host, port)

            scan_results.append({

            "host": host,

            **result

            })

            print(f"{result['port']}/{result['protocol']}\t{result['status']}")

    with open("results/scan.json", "w") as file:

        json.dump(scan_results, file, indent=4)

    print()

    print("Results saved to results/scan.json")

    print()

    print("Active Hosts:")

    for host in active_hosts:

        print(host)

if __name__ == "__main__" :

    main()










