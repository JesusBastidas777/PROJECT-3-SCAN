


import sys

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

    ports = [22, 80, 443]

    for host in active_hosts:

        print()

        print(f"Scanning host: {host}")

        for port in ports:

            if scan_port(host, port):

                print(f"{port}/tcp\tOPEN")

            else:

                print(f"{port}/tcp\tCLOSED")

    print()

    print("Active Hosts:")

    for host in active_hosts:

        print(host)

if __name__ == "__main__" :

    main()






