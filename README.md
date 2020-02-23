# scapy_dhcp_tester
My simple tool to test DHCP servers, written with scapy module. Menu has been made with 'curses'.

docker_test_env contains setup for testing environment in docker:
'docker-compose up -d' in that folder will setup 2 machines:
1. DHCP server with ip 172.18.1.10 and pool 172.18.1.20 - 172.18.1.50
2. Machine with dhcpTester.py, with ip 172.18.1.11 -> can test on the DHCP server


Need to run as root because scapy needs access to interfaces.
In progress.

![Screenshot](screenshot.png?raw=true "Screenshot")


