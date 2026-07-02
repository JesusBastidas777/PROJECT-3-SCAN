import sys

from scanner.discovery import discover_hosts

def main():

    if len(sys.argv) != 2 :

        print("Usage: python3 src/main.py <network>")

        return

    network = sys.argv[1]

    print("Network Scanner")

    print("")

    print(f"Target Network: {network}")

    discover_hosts(network)

if __name__ == "__main__" :

    main()
