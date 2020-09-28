# scapy_dhcp_tester
My simple tool to test DHCP servers, written with scapy module. Menu has been made with 'curses'.
I have tested it on Linux Mint, Rasbian, Cent OS, Ubuntu.
It uses standard python3 modules, the only additional module to install is scapy (```pip3 install scapy```).

Need to run as root because scapy needs access to interfaces.

![Screenshot](screenshot.png?raw=true "Screenshot")

Program will try to autodetect network interface, but you may specify it with cli arguments:
```
$ sudo ./dhcpTester.py --help
usage: dhcpTester.py [-h] [--dev DEV] [--ip IP] [--mac MAC]

Needs to run as root. Program will try to autodetect network interface, IP and
MAC, but you may specify it with arguments during launch.

optional arguments:
  -h, --help  show this help message and exit
  --dev DEV   Interface name, example: eth0
  --ip IP     Local interface IP address, example: 192.168.1.10
  --mac MAC   Local interface MAC address, example: 84:3a:4b:23:cb:3c
```

Options:


1. DHCP Starve

It will ask for start ip (first ip to request) and limit (number of subsequent ip addresses to request).
Then it will proceed to request for next ip addresses and in the end it will print the addresses, for which it has seen the ACK.
Eventually the DHCP address pool on the server may be depleted.

2. DHCP Spoof

It will start a fake DHCP server (does not hold leases). It will ask for first ip in a fake DHCP pool.
If it sees DHCP DISCOVER, it will OFFER an address to that client. If Client sends the REQUEST, then server will ACK the operation and will listen for next requests.

3. DHCP Discover

It will send DHCP DISCOVER packet (and display response, if it comes)

4. Sniff for DHCP Packets

Display DHCP options for every DHCP packet it sees.




```docker_test_env``` contains setup for testing environment in docker (for DHCP Starve function):
```docker-compose up -d``` in that folder will setup 2 machines:
1. DHCP server with ip ```172.18.1.10``` and pool ```172.18.1.20 - 172.18.1.50```
2. Machine with ```dhcpTester.py```, with ip ```172.18.1.11``` -> can test on the DHCP server

---
28.09.2020 - v0.92 style corrections
16.06.2020 - v0.91 fixed crash for small terminals

10.03.2020 - v0.90 published



