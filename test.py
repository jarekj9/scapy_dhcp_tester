#!/usr/bin/env python3
import unittest
from dhcpTester import DhcpStarve

class TestMethods(unittest.TestCase):

    def test_nextIP(self):
        dhcp = DhcpStarve()
        allAddr=[]
        for address in dhcp.nextIP('192.168.250.250',30):
            allAddr.append(address)
        self.assertEqual(len(allAddr), 30)


if __name__ == '__main__':
    unittest.main()