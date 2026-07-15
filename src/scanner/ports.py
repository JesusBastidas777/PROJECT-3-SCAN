



import socket


def scan_port(ip, port):

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    result = sock.connect_ex((str(ip), port))

    sock.close()

    return result == 0





