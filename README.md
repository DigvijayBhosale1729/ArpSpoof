# ArpSpoof
A command line Python Script that can be used to conduct an MITM attack on a local Network.

## Prerequisites
You need to be root to run all parts of the script. Do this by 
```
sudo su
```
Next, follow the commands given below

The first command installs pip3. The second and third install scapy for the root user and regular user
```
sudo apt-get install python3-pip
sudo pip3 install scapy
pip3 install scapy
```
##### The first command installs pip3. The second and third install scapy for the root user and regular user

For the target to be able to actually access the router, packet forwarding should be turned on.

*Packet Forwarding allows your machine to act as a switch and forward packets between the target and router.*
```
echo 1 > /proc/sys/net/ipv4/ip_forward
```
Finally run the script
```
python3 arpSpoof.py [options]
```

## Arguments
```
Usage: arpSpoof.py [options]

Options:
  -h, --help            show this help message and exit
  -t TAR_IP, --target_ip=TAR_IP
                        IP Address of Target
  -m TAR_MAC, --target_mac=TAR_MAC
                        The MAC Address of Target
  -r ROU_IP, --router_ip=ROU_IP
                        The MAC Address of Router
  -a ROU_MAC, --router_mac=ROU_MAC
                        The MAC Address of Router
  -n, --run_netdiscover
                        The Attackers IP Address (your own local IP)
  -s SCAN_IP, --scan=SCAN_IP
                        Scan the local network for IP and MAC addresses
                        (Please enter like 192.168.1.1/24. The /24 is
                        important)
```
### A few things to keep in mind

The ```-m``` and ```-a``` tags are optional. If not provided, the script will find it out for you. 

When running the ```-s``` option, the /24 or /25 gives the subnet to scan. Please give the correct subnet.

