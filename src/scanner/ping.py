
import subprocess


def ping_host(ip):

    print(f"Pinging {ip}")

    result = subprocess.run(
    ["ping", "-c", "1", "-W", "1", str(ip)]
    )

    return result.returncode == 0
