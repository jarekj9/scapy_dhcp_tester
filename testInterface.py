#!/usr/bin/env python3

import socket, struct

def get_network_def():
    """Read the default gateway directly from /proc."""
    output={}
    with open("/proc/net/route") as fh:
        for line in fh:
            fields = line.strip().split()
            if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                continue

            output.update({'defGW': socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))})

    with open("/proc/net/arp") as fh:
        for line in fh:
            if output.get('defGW') in line:
                output.update({'dev': line.split()[5].strip()})
                output.update({'GWmac': line.split()[3]})
    
    with open("/sys/class/net/{}/address".format(output.get('dev'))) as fh:
        for line in fh:
            output.update({'mac': line.strip()})
        return output

print(get_network_def())
