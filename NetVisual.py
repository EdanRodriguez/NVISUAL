# -*- coding: utf-8 -*-

import xml.etree.ElementTree as ET
import nmap, json, netifaces, os, subprocess

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

            network_map[mac_value] = {
                "name": hostname,
                "ip": ipv4_value,
                "mac": mac_value,
                "mac_prefix": mac_prefix,
                "vendor": vendor,
                "Layer": None,
                "Category": None
            }

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
            mac_value = data[1]['APBSSID']
            segments = mac_value.split(':')  
            AP_mac_prefix = ':'.join(segments[:3])
            
        keys = 	macaddress_data.keys()

        for k in keys:
            mac_prefix = macaddress_data[k]['mac_prefix']
            vendor = macaddress_data[k]['vendor']

            if mac_prefix == AP_mac_prefix or (vendor == None and mac_prefix == AP_mac_prefix):
                macaddress_data[k]['Category'] = 'Access Point'
                macaddress_data[k]['Layer'] = '2'

            elif vendor == None and mac_prefix != AP_mac_prefix:
                macaddress_data[k]['Category'] = 'Client'
                macaddress_data[k]['Layer'] = '3'

            elif macaddress_data[k]['ip'] == self.gateway:
                macaddress_data[k]['Category'] = 'Router'
                macaddress_data[k]['Layer'] = '1'

            elif vendor != None:
                macaddress_data[k]['Category'] = 'IOT'
                macaddress_data[k]['Layer'] = '3'

            else:
                macaddress_data[k]['Category'] = 'Unknown'
                macaddress_data[k]['Layer'] = '0'
                
        with open(self.json_parsed_file_path, 'w') as file:
            json.dump(macaddress_data, file, indent=4)

        print("Classification finished.")