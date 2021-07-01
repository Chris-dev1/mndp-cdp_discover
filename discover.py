#!/bin/env python3
# :set syntax=python
import socket
import struct
import sys
import datetime


def sock_error(msg):
    # print("Socket error code: %s Message: %s" % (str(msg[0]), msg[1]))
    sys.exit(1)


def to_mac_addr(raw):
    a = raw.hex()
    return "%s:%s:%s:%s:%s:%s" % (a[0:2], a[2:4], a[4:6], a[6:8], a[8:10],
                                  a[10:12])


def eth_head(raw_data):
    dest, src, prototype = struct.unpack('!6s6s2s', raw_data[:14])
    dest = to_mac_addr(dest)
    src = to_mac_addr(src)
    if (prototype[0] == 0):
        raw = True
        end = struct.unpack('!H', prototype)[0]
    else:
        raw = False
        end = socket.ntohs(struct.unpack('!H', prototype)[0])
    raw_data = raw_data[14:]
    return dest, src, raw, end, raw_data

CDPTypes = {1: "Device ID",
            2: "Address",
            3: "Port ID",
            4: "Capabilities",
            5: "Software version",
            6: "Platform"}

MNDPTypes = {1:  "MAC Address",
             5:  "Identity",
             7:  "Version",
             8:  "Platform",
             10: "Uptime",
             11: "Software-ID",
             12: "Board",
             14: "Unpack",
             15: "IPv6 Address",
             16: "Interface",
             17: "IPv4 Address"}


try:
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                         socket.ntohs(0x0003))
except socket.error:
    sock_error(socket.error)
try:
    sock.bind(("br1", 0))  # br1 is interface for listen
except socket.error:
    sock_error(socket.error)

other = 0
try:
    while True:
        packet = sock.recv(65536)
        dest, src, raw, end, raw_data = eth_head(packet)
        other += 1
        if (dest == "01:00:0c:cc:cc:cc"):
            raw_data = raw_data[12:]
            parsed = []
            while (len(raw_data) > 1):
                Vtype, Vlen = struct.unpack('!2s2s', raw_data[:4])
                Vtype = int(struct.unpack('!H', Vtype)[0])
                Vlen = int(struct.unpack('!H', Vlen)[0])
                Value = raw_data[4:Vlen]
                if(Vtype == 2):
                    numOfAddr = int(struct.unpack('!4s', Value[:4])[0].hex(),
                                    base=16)  # maybe need base 16
                    Value = Value[4:]
                    ips = ["Number of Address: " + str(numOfAddr)]
                    while(len(Value) > 0):
                        Ptype, Plen = struct.unpack('!ss', Value[:2])
                        Plen = int(Plen.hex(), base=16)
                        Protocol = Value[2:2+Plen]
                        Adrlen = int((struct.unpack('!2s', Value[2+Plen:4 +
                                                    Plen])[0]).hex(),
                                                            base=16)
                        Address = socket.inet_ntoa(
                                      Value[4+Plen:4+Plen+Adrlen])
                        Value = Value[4+Plen+Adrlen:]
                        ips.append(Address)
                    Value = ips
                elif(Vtype == 4):
                    Value = "0x" + str(Value.hex())
                else:
                    Value = str(Value.decode())
                parsed.append(CDPTypes[Vtype]+": "+str(Value))
                raw_data = raw_data[Vlen:]
            print("\n\033[42mDest: "+str(dest)+" Source: "+str(src) +
                  " CDP\033[0m")
            for i in range(len(parsed)):
                print(parsed[i])
            other = 0
        elif (raw is False and end == 8):
            head_ver_len = raw_data[:1].hex()
            head_lenght = int((int(head_ver_len, base=16) ^
                                ((int(head_ver_len, base=16) >> 4)
                                << 4)) * 32 / 8)
            protocol = raw_data[9:10]
            if (protocol == b"\x11"):
                src_ip = socket.inet_ntoa(raw_data[12:16])
                dest_ip = socket.inet_ntoa(raw_data[16:20])
                raw_data = raw_data[head_lenght:]
                src_port, dest_port = raw_data[:2], raw_data[2:4]
                if (src_port == dest_port and dest_port == b"\x16\x2e"):
                    raw_data = raw_data[12:]
                    parsed = []
                    while(len(raw_data) > 1):
                        Vtype, Vlen = struct.unpack('!2s2s', raw_data[:4])
                        Vtype = int(Vtype.hex(), base=16)
                        Vlen = int(Vlen.hex(), base=16)
                        Value = raw_data[4:4+Vlen]
                        if (Vtype == 1):
                            Value = to_mac_addr(Value)
                        elif (Vtype == 10):
                            Value = Value[::-1]
                            Value = str(datetime.timedelta(seconds=
                                        int(Value.hex(), base=16)))
                        elif (Vtype == 14):
                            Value = "0x" + Value.hex()
                        elif (Vtype == 15):
                            Value = socket.inet_ntop(socket.AF_INET6, Value)
                        elif (Vtype == 17):
                            Value = socket.inet_ntoa(Value)
                        elif (MNDPTypes.get(Vtype) not None):
                            Value = str(Value.decode())
                        Vtype = MNDPTypes.get(Vtype)
                        if (Vtype is None):
                            Vtype = "Unknown"
                        parsed.append(Vtype + " : " + str(Value))
                        raw_data = raw_data[4+Vlen:]
                    print("\n\033[44mDestination ip: " + dest_ip +
                            " Source ip: " + src_ip + " MNDP\033[0m")
                    for i in range(len(parsed)):
                        print(parsed[i])
                    other = 0
        if (other != 0):
            print("\r\033[43mSomething other [x"
                    + str(other) + "]\033[0m", end="", flush=True)
except KeyboardInterrupt:
    print("\nBue!\n")
    sys.exit()
