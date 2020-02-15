#!/usr/bin/env python3
from dhcpTester import *
import pytest
import curses
from mock import patch
import unittest


    
class Test(unittest.TestCase):
    
    @pytest.fixture(autouse=True)
    def __inject_fixtures(self, mocker):
        '''Without it I cannot use pytest fixtures, because I inherit from unittest.TestCase'''
        self.mocker = mocker

    def test_main(self):
        self.mocker.patch('curses.wrapper')   #pytest way    
        menu = Menu(['DHCP Starve', 'DHCP Discover', 'Sniff for DHCP Packets'])
        curses.wrapper.assert_called()
    
    @patch('dhcpTester.sniff')               #unittest way
    def test_listen(self,mock_sniff):
        DhcpStarve().listen()
        mock_sniff.assert_called()
        
    @patch('dhcpTester.sniff')
    def test_handle_dhcp(self,mock_handle_dhcp):
        pass
        
    def test_nextIP(self):
        dhcp = DhcpStarve()
        allAddr=[]
        for address in dhcp.nextIP('192.168.250.250',30):
            allAddr.append(address)
        self.assertEqual(len(allAddr), 30)