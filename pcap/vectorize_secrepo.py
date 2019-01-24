# -*- coding: utf-8 -*-
import numpy as np
import os
import re
import h5py
import socket
import struct
from sklearn.preprocessing import normalize

from bitarray import bitarray
import unittest

from pcap.proc.pcap import Pcap
from pcap.proc.rtmp import RTMP

LOG_REGEX = re.compile(r'([^\s]+)\s[^\s]+\s[^\s]+\s\[[^\]]+\]\s"([^\s]*)\s[^"]*"\s([0-9]+)')


def ip2int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]


def test_load():

    prevectors = {
        ip2int("192.187.126.162"): {"protocols": {}, "id": {}, "ttl": {}, "flag": {}, "win": {}, "seq": {}, "ack": {}},
        ip2int("192.187.126.161"): {"protocols": {}, "id": {}, "ttl": {}, "flag": {}, "win": {}, "seq": {}, "ack": {}},
    
    }

    _pcap = Pcap()
    _gen = _pcap.parse("pcap/data/2.pcap")
    for _packet in _gen:
        _mac = _packet.data
        _head = _packet.head
        _net = _mac.data
        _trans = _net.data
        if _trans.__class__.__name__ == "TCP":
            _app = _trans.data
            if _app is not None:
                #1.IP
                ip = ''
                for item in _net.src:
                    ip = ip + '.' + str(item)
                ip = ip2int(ip[1:])
                print('1.IP src:', ip)
                
                #2.protocol
                protocol = _mac.type_desc
                print('2.protocol:', protocol)
                print(type(protocol))
                protocol =  int(protocol[1],16) + (int(protocol[0],16) << 8)

                print(protocol)

                #3.id
                id = _net.id
                print('3.id:',_net.id)

                #4.ttl
                ttl = _net.time_to_live
                print('4.ttl:', ttl)

                #5.flag
                #self.CWR
                flag = _trans.flag.CWR | _trans.flag.ECE | _trans.flag.ACK | _trans.flag.PSH | _trans.flag.RST | _trans.flag.SYN | _trans.flag.FIN
                #print('5.flag:', _trans.flag)
                print('5.flag:', flag)

                #6.win
                win = _trans.wnd_size
                print('6.win:', win)
                #7.seq
                seq = _trans.seq
                print('7.seq:', seq)
                #8.ack
                ack = _trans.ack
                print('8.ack:', ack)

                if ip not in prevectors:
                    if len(prevectors) >= 1000:
                        continue
                    prevectors[ip] = {"protocols": {}, "id": {}, "ttl": {}, "flag": {}, "win": {}, "seq": {}, "ack": {}}
                
                if protocol not in prevectors[ip]["protocols"]:
                    prevectors[ip]['protocols'][protocol] = 0

                prevectors[ip]['protocols'][protocol] += 1

                if id not in prevectors[ip]["id"]:
                    prevectors[ip]['id'][id] = 0

                prevectors[ip]['id'][id] += 1

                if ttl not in prevectors[ip]["ttl"]:
                    prevectors[ip]['ttl'][ttl] = 0

                prevectors[ip]['ttl'][ttl] += 1

                if flag not in prevectors[ip]["flag"]:
                    prevectors[ip]['flag'][flag] = 0

                prevectors[ip]['flag'][flag] += 1

                if win not in prevectors[ip]["win"]:
                    prevectors[ip]['win'][win] = 0

                prevectors[ip]['win'][win] += 1

                if seq not in prevectors[ip]["seq"]:
                    prevectors[ip]['seq'][seq] = 0

                prevectors[ip]['seq'][seq] += 1

                if ack not in prevectors[ip]["ack"]:
                    prevectors[ip]['ack'][ack] = 0

                prevectors[ip]['ack'][ack] += 1

    return prevectors

def get_prevectors():
    data_path = "data/www.secrepo.com/self.logs/"
    # ensure we get the IPs used in the examples
    prevectors = {
        ip2int("192.187.126.162"): {"requests": {}, "responses": {}},
        ip2int("49.50.76.8"): {"requests": {}, "responses": {}},
        ip2int("70.32.104.50"): {"requests": {}, "responses": {}},
    }

    for path in os.listdir(data_path):
        full_path = os.path.join(data_path, path)
        with open(full_path, "r") as f:
            for line in f:
                try:
                    ip, request_type, response_code = LOG_REGEX.findall(line)[0]
                    ip = ip2int(ip)
                except IndexError:
                    continue

                if ip not in prevectors:
                    if len(prevectors) >= 10000:
                        continue
                    prevectors[ip] = {"requests": {}, "responses": {}}

                if request_type not in prevectors[ip]["requests"]:
                    prevectors[ip]['requests'][request_type] = 0

                prevectors[ip]['requests'][request_type] += 1

                if response_code not in prevectors[ip]["responses"]:
                    prevectors[ip]["responses"][response_code] = 0

                prevectors[ip]["responses"][response_code] += 1

    return prevectors


def convert_prevectors_to_vectors(prevectors):
    request_types = [
        "GET",
        "POST",
        "HEAD",
        "OPTIONS",
        "PUT",
        "TRACE"
    ]
    
    response_codes = [
        200,
        404,
        403,
        304,
        301,
        206,
        418,
        416,
        403,
        405,
        503,
        500,
    ]

    vectors = np.zeros((len(prevectors.keys()), len(request_types) + len(response_codes)), dtype=np.float32)
    ips = []

    for index, (k, v) in enumerate(prevectors.items()):
        ips.append(k)
        for ri, r in enumerate(request_types):
            if r in v["requests"]:
                vectors[index, ri] = v["requests"][r]
        for ri, r in enumerate(response_codes):
            if r in v["responses"]:
                vectors[index, len(request_types) + ri] = v["requests"][r]

    return ips, vectors


if __name__ == "__main__":
    test_load()
    # prevectors = get_prevectors()
    # ips, vectors = convert_prevectors_to_vectors(prevectors)
    # vectors = normalize(vectors)

    # with h5py.File("secrepo.h5", "w") as f:
    #     f.create_dataset("vectors", shape=vectors.shape, data=vectors)
    #     f.create_dataset("cluster", shape=(vectors.shape[0],), data=np.zeros((vectors.shape[0],), dtype=np.int32))
    #     f.create_dataset("notes", shape=(vectors.shape[0],), data=np.array(ips))

    # print "Finished prebuilding samples"
