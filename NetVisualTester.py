#  -*- coding: utf-8 -*-

from NetVisual import NetScan, NetParse, NetClassify, NetGraph
import time, os, json, matplotlib.pyplot as plt

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

