# -*- coding: utf-8 -*-

import xml.etree.ElementTree as ET
import nmap, json, netifaces, os, subprocess, time
import networkx as nx
import matplotlib.pyplot as plt

class NetConfig:

    def __init__(self):
        self.script_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Store')
        self.xml_results_file_path = os.path.join(self.script_dir, 'Network_XML_Results.xml')
        self.json_parsed_file_path = os.path.join(self.script_dir, 'MacAdddress_Data.json')
        self.json_wlan_file_path = os.path.join(self.script_dir, 'Wlan_Interfaces_Data.json')
        self.gateway = str(netifaces.gateways().get('default', {}).get(netifaces.AF_INET)[0])
        self.network = f'{self.gateway}/24'
        self.current_access_point_ip = None
        self.nm = nmap.PortScanner()
        self.flags = '-sn -R'

class NetScan(NetConfig):

    def __init__(self):
        super().__init__()
    
    def scan(self):
        self.nm.scan(self.network, arguments=self.flags)
        network_xml_result = self.nm.get_nmap_last_output()
        return network_xml_result
    
    print("Scanning finished.")

class NetParse(NetConfig):

    def __init__(self):
        super().__init__()

    def parse(self, network_xml_result):

        with open(self.xml_results_file_path, 'w') as file:
            file.write(network_xml_result.decode('utf-8'))

        with open(self.xml_results_file_path, 'r') as file:
            network_xml_result = file.read()

        root = ET.fromstring(network_xml_result)
        network_map = {}

        for host in root.findall('host'):

            hostname_element = host.find('hostnames/hostname')

            if hostname_element is not None:
                hostname = hostname_element.attrib.get('name')
            else:
                hostname = None

            ipv4_value = None
            mac_value = None
            vendor = None
            srtt = None
            rttvar = None

            for address in host.findall('address'):
                addr_type = address.attrib.get('addrtype')
                addr_value = address.attrib.get('addr')

                if addr_type == 'ipv4':
                    ipv4_value = addr_value

                elif addr_type == 'mac':
                    vendor = address.attrib.get('vendor')
                    mac_value = addr_value
                    segments = mac_value.split(':')  
                    mac_prefix = ':'.join(segments[:3])

            times = host.find('times')
            if times is not None:
                srtt = times.attrib.get('srtt')
                rttvar = times.attrib.get('rttvar')
            else:
                srtt = None
                rttvar = None

            network_map[mac_value] = {
                "name": hostname,
                "ip": ipv4_value,
                "mac": mac_value,
                "mac_prefix": mac_prefix,
                "vendor": vendor,
                "srtt": srtt,
                "rttvar": rttvar,
                "Layer": None,
                "Category": None
            }

        with open(self.json_parsed_file_path, 'w', encoding='utf-8') as file:
            json.dump(network_map, file, indent=4)

        with open(self.json_parsed_file_path, 'r', encoding='utf-8') as file:
            network_map = json.load(file)

        if 'null' in network_map:
            del network_map['null']

        with open(self.json_parsed_file_path, 'w', encoding='utf-8') as file:
            json.dump(network_map, file, indent=4)

        print("Parse finished.")

class NetClassify(NetConfig):

    def __init__(self):
        super().__init__()

    def classify(self):

        def wlan_interfaces():
            result = subprocess.run('netsh wlan show interfaces', shell=True, capture_output=True, text=True)
            raw_lines = result.stdout.splitlines()

            interfaces = []
            current_interface = {}

            for line in raw_lines:
                line = line.strip()
                if not line:
                    if current_interface:
                        interfaces.append(current_interface)
                        current_interface = {}
                    continue
                if ':' in line:
                    key, value = map(str.strip, line.split(':', 1))
                    key = key.replace(" ", "")
                    value = value.replace(" ", "")
                    current_interface[key] = value

            if current_interface:
                interfaces.append(current_interface)

            with open(self.json_wlan_file_path, 'w') as file:
                json.dump(interfaces, file, indent=4)

            print("Conversion finished.")
        
        wlan_interfaces()

        with open(self.json_wlan_file_path, 'r') as file:
            data = json.load(file)

        data = data[1:]

        with open(self.json_wlan_file_path, 'w') as file:
            json.dump(data, file, indent=4)

        with open(self.json_parsed_file_path, 'r') as file:
            macaddress_data = json.load(file)

        with open(self.json_wlan_file_path, 'r') as file:
            data = json.load(file)
            mac_value = data[0]['APBSSID']
            segments = mac_value.split(':')  
            AP_mac_prefix = ':'.join(segments[:3])
            
        keys = 	macaddress_data.keys()
        # Layer0 = []
        # Layer1 = []
        # Layer2 = []

        for k in keys:
            mac_prefix = macaddress_data[k]['mac_prefix']
            vendor = macaddress_data[k]['vendor']

            if mac_prefix == AP_mac_prefix or (vendor == None and mac_prefix == AP_mac_prefix):
                macaddress_data[k]['Category'] = 'Access Point'
                macaddress_data[k]['Layer'] = '1'

            elif vendor == None and mac_prefix != AP_mac_prefix:
                macaddress_data[k]['Category'] = 'Client'
                macaddress_data[k]['Layer'] = '2'

            elif macaddress_data[k]['ip'] == self.gateway:
                macaddress_data[k]['Category'] = 'Router'
                macaddress_data[k]['Layer'] = '0'

            elif vendor != None:
                macaddress_data[k]['Category'] = 'IOT'
                macaddress_data[k]['Layer'] = '2'

            else:
                macaddress_data[k]['Category'] = 'Unknown'
                macaddress_data[k]['Layer'] = None

            # if macaddress_data[k]['Layer'] == 0:
            #     Layer0.append(macaddress_data[k]['mac'])

            # elif macaddress_data[k]['Layer'] == 1:
            #     Layer1.append(macaddress_data[k]['mac'])

            # elif macaddress_data[k]['Layer'] == 2:
            #     Layer2.append(macaddress_data[k]['mac'])

                
        with open(self.json_parsed_file_path, 'w') as file:
            json.dump(macaddress_data, file, indent=4)


        print("Classification finished.")

class NetGraph(NetConfig):

    def __init__(self):
        super().__init__()

    def dotplt_data(self):

        with open(self.json_parsed_file_path, 'r') as file:
            macaddress_data = json.load(file)

        srtt_data = [int(macaddress_data[k]['srtt']) for k in macaddress_data]
        rttvar_data = [int(macaddress_data[k]['rttvar']) for k in macaddress_data]

        return srtt_data, rttvar_data

    number_of_rounds = 100

    srrt = []
    rttvar = []

    script_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Store')
    time_values_file_path = os.path.join(script_dir, 'TimeValues.json')

    for i in range(1, int(number_of_rounds)):
        time.sleep(2)
        network_xml_result = NetScan().scan()
        NetParse().parse(network_xml_result)
        NetClassify().classify()
        srtt_data, rttvar_data = NetGraph().dotplt()

        srrt.extend(srtt_data)
        rttvar.extend(rttvar_data)
        print(f'Round {i} sucessfully finished...')

    values = {
        "rttvar":rttvar, 
        "srrt":srrt
        }

    with open(time_values_file_path, 'w') as file:
        json.dump(values, file, indent=4)


    with open(time_values_file_path, 'r') as file:
        json_data = json.load(file)

    srtt_data = json_data['srrt']
    rttvar_data = json_data['rttvar']


    def dot_stack(data):

        stack = {}

        for x in data:
            stack[x] = stack.get(x, 0) + 1
            yield x, stack[x]


    plt.figure(figsize=(8, 3))

    for x, y in dot_stack(srtt_data):
        plt.plot(x, y, 'ko', markersize=8)

    for x, y in dot_stack(rttvar_data):
        plt.plot(x, y, 'ro', markersize=4) 


    plt.yticks([])
    plt.xlabel("Value")
    plt.title("Dot Plot: srtt (black) vs rttvar (small red)")
    plt.grid(True, axis='x', linestyle='--', alpha=0.5)
    plt.show()


