#!/usr/bin/env python3
from dhcpTester import *
from scapy import *
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
        '''main should create Menu object and run curses.wrapper'''
        self.mocker.patch('curses.wrapper')   #pytest way    
        menu = Menu(['DHCP Starve', 'DHCP Discover', 'Sniff for DHCP Packets'])
        curses.wrapper.assert_called()
    
    @patch('dhcpTester.sniff')               #unittest way
    def test_listen(self,mock_sniff):
        '''Listen method should call sniff'''
        DhcpStarve().listen()
        mock_sniff.assert_called()
        
    def test_handle_dhcp(self):
        '''hande_dhcp returns False if gets other packet than dhcp'''
        dhcpPacket = Ether(src=LOCALMAC, dst='ff:ff:ff:ff:ff:ff')
        dhcpPacket/= IP(src='0.0.0.0', dst='255.255.255.255')
        dhcpPacket/= UDP(dport=67, sport=68)
        dhcpPacket/= BOOTP(chaddr=LOCALMACRAW,xid=RandInt())
        dhcpPacket/= DHCP(options=[('message-type', 'discover'), 'end'])
        assert not DhcpStarve().handle_dhcp(dhcpPacket)
        
    def test_nextIP(self):
        '''nextIP provides a number of next ip addresses'''
        dhcp = DhcpStarve()
        allAddr=[]
        for address in dhcp.nextIP('192.168.250.250',30):
            allAddr.append(address)
        self.assertEqual(len(allAddr), 30)
    
    @patch('builtins.input')
    @patch('dhcpTester.sendp')
    def test_discover(self,mock_sendp, mock_input):
        '''should call sendp'''
        DhcpStarve().discover()    
        mock_sendp.assert_called()
                
    @patch('builtins.input')    
    @patch('dhcpTester.sendp')    
    def test_starve(self,mock_sendp, mock_input):
        '''should call sendp 3 times'''
        DhcpStarve().starve('192.168.1.10',3)
        self.assertEqual(mock_sendp.call_count,3)
            
    def test_get_network_def(self):
        result=get_network_def()
        print('Testing test_get_network_def: {}'.format(result))
        for value in result.values():
            self.assertNotEqual(value,None)  
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            