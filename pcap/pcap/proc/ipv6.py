#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pcap.proc.util import ProcData


class IPV6(ProcData):
    """ipv6协议"""

    def __init__(self, data, upper):
        super(IPV6, self).__init__(upper)
