#  -*- coding: utf-8 -*-

from NetVisual import NetScan, NetParse, NetClassify

network_xml_result = NetScan().scan()
NetParse().parse(network_xml_result)
NetClassify().classify()











