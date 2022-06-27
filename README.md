# RedFrame1.0
RedFrame 1.0 with DNS Sppofing
RedFrame is planned to be a simple Red team enumeration, spoofing, and sniffing tool to be used once access to a target network is achieved. Currently it has two main types of functionality built in.

Simple ARP Spoofer implemented in Python 3 using the PyCharm IDE on a Kali Linux distribution. The host linux machine must be configured to forward ip traffic with the command "echo 1 > /proc/sys/net/ipv4/ip_forward". If this is not done, the traffic between the two target machines will be dropped by the attacker Linux machine.
Simple network traffic sniffer implemented in Python 3 using the PyCharm IDE on a Kali Linux distribution and Scapy. The user must chose a network interface on which to sniff traffic. The sniffer will identify URLs requested as well as clear text potential usernames and passwords configured by adding/removing entried from the "keyword" list. In the coming weeks, addtional functionalty will be added
Simple DNS Spoofing functionality included in preapration for file interception, code injection, and eventually HTTPS bypass
