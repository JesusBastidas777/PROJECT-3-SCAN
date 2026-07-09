


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

    if scan_port("192.168.1.1", 80):

        print("Port 80 is OPEN")

    else:

        print("Port 80 is CLOSED")

    print()

    print("Active Hosts:")

    for host in active_hosts:

        print(host)

if __name__ == "__main__" :

    main()






