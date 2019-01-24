#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import unittest

from pcap.proc.pcap import Pcap
from pcap.proc.rtmp import RTMP


def callback_rtmp(ins, msg, fr):
    if msg.__class__.__name__ == "str":
        #print(msg)
        if msg=="S1":
            #print("s1 time:%d"%(ins.s1.time))
            pass


class PcapTest(unittest.TestCase):
    """测试"""
    nvts_cn_json = {}
    def test_rtmp(self):
        t = 3
        #print("tt:%s" % bin(t >> 6))

    def test_load(self):
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
                    print(_mac)
                    print(_packet.head)
                    print(_net)
                    print(_trans)
                    #if RTMP.find(_trans, callback_rtmp):
                        # 依次打印网络层、传输层头部
                    #    print("")


if __name__ == "__main__":
    unittest.main()
