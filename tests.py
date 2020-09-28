#!/usr/bin/env python3
from dhcpTester import *
from scapy import *
import pytest
import curses
from mock import patch
import unittest
from argparse import ArgumentParser

# Constants for testing:
MASK = "255.255.255.0"
CLIENTIP = "192.168.31.30"
BROACASTIP = str(IPv4Network(LOCALIP + "/" + MASK, False).broadcast_address)

DISCOVERPKT = Ether(src=LOCALMAC, dst="ff:ff:ff:ff:ff:ff")
DISCOVERPKT /= IP(src="0.0.0.0", dst="255.255.255.255")
DISCOVERPKT /= UDP(dport=67, sport=68)
DISCOVERPKT /= BOOTP(chaddr=LOCALMACRAW, xid=int(RandInt()))
DISCOVERPKT /= DHCP(options=[("message-type", "discover"), "end"])

REQUESTPKT = Ether(src="ee:ee:ee:ee:ee:ee", dst="ff:ff:ff:ff:ff:ff")
REQUESTPKT /= IP(src="0.0.0.0", dst="255.255.255.255")
REQUESTPKT /= UDP(dport=67, sport=68)
REQUESTPKT /= BOOTP(chaddr=RandString(12, b"0123456789abcdef"), xid=int(RandInt()))
REQUESTPKT /= DHCP(
    options=[
        ("message-type", "request"),
        ("requested_addr", CLIENTIP),
        ("server_id", LOCALIP),
        "end",
    ]
)

OFFERPKT = Ether(src=LOCALMAC, dst=DISCOVERPKT[Ether].src)
OFFERPKT /= IP(src=LOCALIP, dst="255.255.255.255")
OFFERPKT /= UDP(dport=68, sport=67)
OFFERPKT /= BOOTP(
    op=2,
    chaddr=bytes.fromhex(DISCOVERPKT[Ether].src.replace(":", "")),
    yiaddr=CLIENTIP,
    siaddr=LOCALIP,
    giaddr=LOCALIP,
    xid=DISCOVERPKT[BOOTP].xid,
)
OFFERPKT /= DHCP(
    options=[
        ("message-type", "offer"),
        ("server_id", LOCALIP),
        ("lease_time", 43200),
        ("renewal_time", 21600),
        ("rebinding_time", 37800),
        ("subnet_mask", MASK),
        ("broadcast_address", "192.168.56.255"),
        ("router", LOCALIP),
        ("name_server", LOCALIP),
        "end",
    ]
)

ACKPKT = Ether(src=LOCALMAC, dst=REQUESTPKT[Ether].src)
ACKPKT /= IP(src=LOCALIP, dst="255.255.255.255")
ACKPKT /= UDP(dport=68, sport=67)
ACKPKT /= BOOTP(
    op=2,
    chaddr=bytes.fromhex(REQUESTPKT[Ether].src.replace(":", "")),
    yiaddr=CLIENTIP,
    siaddr=LOCALIP,
    giaddr=LOCALIP,
    xid=REQUESTPKT[BOOTP].xid,
)
ACKPKT /= DHCP(
    options=[
        ("message-type", "ack"),
        ("server_id", LOCALIP),
        ("lease_time", 43200),
        ("renewal_time", 21600),
        ("rebinding_time", 37800),
        ("subnet_mask", MASK),
        ("broadcast_address", BROACASTIP),
        ("router", LOCALIP),
        ("name_server", LOCALIP),
        "end",
    ]
)


class Test(unittest.TestCase):
    @pytest.fixture(autouse=True)
    def __inject_fixtures(self, mocker):
        """Without it I cannot use pytest fixtures, because I inherit from unittest.TestCase"""
        self.mocker = mocker

    def test_main(self):
        """main should create Menu object and run curses.wrapper"""
        self.mocker.patch("curses.wrapper")  # pytest way
        menu = Menu(["DHCP Starve", "DHCP Discover", "Sniff for DHCP Packets"])
        curses.wrapper.assert_called()

    @patch("dhcpTester.sniff")  # unittest way
    def test_listen(self, mock_sniff):
        """Listen method should call sniff"""
        DhcpStarve().listen()
        mock_sniff.assert_called()

    def test_handle_dhcp(self):
        """hande_dhcp returns False if gets other packet than dhcp"""
        dhcpPacket = Ether(src=LOCALMAC, dst="ff:ff:ff:ff:ff:ff")
        dhcpPacket /= IP(src="0.0.0.0", dst="255.255.255.255")
        dhcpPacket /= UDP(dport=67, sport=68)
        dhcpPacket /= BOOTP(chaddr=LOCALMACRAW, xid=RandInt())
        dhcpPacket /= DHCP(options=[("message-type", "discover"), "end"])
        assert not DhcpStarve().handle_dhcp(dhcpPacket)

    @patch("builtins.input")
    @patch("dhcpTester.sendp")
    def test_discover(self, mock_sendp, mock_input):
        """should call sendp"""
        DhcpStarve().discover()
        mock_sendp.assert_called()

    @patch("builtins.input")
    @patch("dhcpTester.sendp")
    def test_starve(self, mock_sendp, mock_input):
        """should call sendp 3 times"""
        DhcpStarve().starve("192.168.1.10", 3)
        self.assertEqual(mock_sendp.call_count, 3)

    @patch("builtins.input")
    @patch("dhcpTester.sniff")
    def test_spoofing(self, mock_sniff, mock_input):
        """Should call sniff"""
        DhcpStarve().spoofing("192.168.31.10")
        mock_sniff.assert_called()

    @patch("dhcpTester.sendp")
    def test_offer(self, mock_sendp):
        """Should call sendp with OFFERPKT packet, based on received DISCOVERPKT"""
        DhcpStarve().offer(LOCALIP, CLIENTIP, MASK, DISCOVERPKT)
        mock_sendp.assert_called_with(OFFERPKT, iface=LOCALIFACE)

    @patch("dhcpTester.sendp")
    def test_dhcpack(self, mock_sendp):
        """Should call sendp with ACKPKT packet, based on received REQUESTPKT packet"""
        DhcpStarve().dhcpack(LOCALIP, CLIENTIP, MASK, REQUESTPKT)
        mock_sendp.assert_called_with(ACKPKT, iface=LOCALIFACE)

    def test_nextIP(self):
        """nextIP provides a number of next ip addresses"""
        dhcp = DhcpStarve()
        allAddr = []
        for address in dhcp.nextIP("192.168.250.250", 30):
            allAddr.append(address)
        self.assertEqual(len(allAddr), 30)

    def test_auto_detect_network(self):
        result = auto_detect_network()
        print("Testing test_auto_detect_network: {}".format(result))
        for value in result.values():
            self.assertNotEqual(value, None)
