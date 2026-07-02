

import ipaddress

from scanner.ping import ping_host

def discover_hosts(network):

    network_obj = ipaddress.ip_network(network)

    for ip in network_obj.hosts():

        if ping_host(ip):

            print("Host Active")

    return []






