#!/usr/bin/env python
#This program is for scanning networks
import scapy.all as scapy
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_option("-t" "--target", dest="target", help="target IP / IP range")
    options = parser.parse_args()

    if not options.target:
        parser.error("[-] Please specify target IP, use --help for more info")
    return options

# Scans ip and shows result
def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    # Lists ip and mac addresses
    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list

def print_result(results_list):
    print("IP\t\t\tMAC Address\n---------------------------------------")
    for client in results_list:
        print(client ["ip"] + "\t\t" + client["mac"])

scan_result = scan("192.168.182.141/24")
print_result(scan_result)