














import socket

from concurrent.futures import ThreadPoolExecutor


def scan_port(ip, port):

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    result = sock.connect_ex((str(ip), port))

    sock.close()

    return {
        "port": port,
        "protocol": "tcp",
        "status": "OPEN" if result == 0 else "CLOSED"
    }


def scan_ports(ip, ports):

    results = []

    with ThreadPoolExecutor(max_workers=10) as executor:

        futures = [

            executor.submit(scan_port, ip, port)

            for port in ports

        ]

        for future in futures:

            results.append(future.result())

    return results


















