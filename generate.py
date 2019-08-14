#!/usr/bin/env python3
from scapy.all import *
import sys
import math
import terminalplot

def write(pkt, write_file_name):
    wrpcap(write_file_name, pkt, append=True)

def get_attack_parameters():
    duration = int(input("Please specify the duration of the attack: "))
    start_time = int(input("Please specify the starting time of the attack: "))
    attack_size = int(input("Please specify the number of attack packets: "))
    return duration, start_time, attack_size

def syn_flood(attack_size, to_file):
    sIPs, dIP = [socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff))) for _ in range(attack_size)], "99.7.186.25"
    for sIP in sIPs:
        attack_p = Ether() / IP(dst=dIP, src=sIP) / UDP(sport=53)/DNS(nscount=1, ns=DNSRR(type=46))
        write(attack_p, to_file)

def slowloris(attack_size, to_file):
    sIPs, dIP = [socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff))) for _ in range(attack_size)], "99.7.186.25"
    sport, dport = 50, 70
    for sIP in sIPs:
        sport += 10
        dport += 10
        attack_p = Ether() / IP(dst=dIP, src=sIP, len=100) / TCP(sport=sport, dport=dport)
        write(attack_p, to_file)

def udp_traffic_assymetry(attack_size, to_file):
    sIPs, dIP = [socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff))) for _ in range(attack_size // 2)], "99.7.186.25"
    sport, dport, dummy_IP = 53, 43, '99.7.186.26'

    for i in range(attack_size):
        attack_p = Ether() / IP(dst= dIP, src=dummy_IP) / UDP(sport=sport, dport=dport)
        write(attack_p, to_file)
    for i in range(attack_size/20):
        attack_p = Ether() / IP(dst=dummy_IP, src=dIP) / UDP(sport=dport, dport=sport)
        write(attack_p, to_file)

def superspreader(attack_size, to_file):
    sIP, dIPs = '99.7.186.25',[socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff))) for _ in range(attack_size)]
    dport = 0
    for dIP in dIPs:
        dport += 1
        p = Ether() / IP(dst=dIP, src=sIP) / TCP(dport=dport, flags='S')
        write(attack_p, to_file)

def dns_tunneling(attack_size, to_file):
    sIPs, dIP = [socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff))) for _ in range(attack_size // 2)], "99.7.186.25"
    ttl = 10
    for sIP in sIPs:
        ttl += 1
        attack_p = Ether() / IP(dst=dIP, src=sIP) / UDP(sport=53) /DNS(qr=1, aa=1, ancount=1,an=DNSRR(rrname='www.thepacketgeek.com',  ttl=ttl, rdata='192.168.1.1'))
        write(attack_p, to_file)

def malicious_domain(attack_size, to_file):
    sIPs, dIP = [socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff))) for _ in range(attack_size // 2)], "99.7.186.25"
    ttl = 10
    for sIP in sIPs:
        ttl += 1
        attack_p = Ether() / IP(dst=dIP, src=sIP) / UDP(sport=53) /DNS(qr=1, aa=1, ancount=1,an=DNSRR(rrname='www.thepacketgeek.com',  ttl=ttl, rdata=sIP))
        write(attack_p, to_file)

attack_kinds = {"syn_flood": syn_flood, "slowloris": slowloris, "udp_traffic_assymetry": udp_traffic_assymetry, "superspreader": superspreader, "dns_tunneling": dns_tunneling, "malicious_domain": malicious_domain}
flow_size, packet_size, attack, bound, gap, exponent, plot = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], int(sys.argv[4]), int(sys.argv[5]), float(sys.argv[6]), sys.argv[7] == "True"

if attack in attack_kinds:
    duration, start_time, attack_size = get_attack_parameters()
else:
    attack = ""
if bound < gap:
    raise Exception('bound should be larger than gap, or there is no group distribution')

flows_info = collections.defaultdict(list)
group_size = bound // gap
pl_total = sum([i ** exponent for i in range(1, group_size + 1)])
group = [i ** exponent * flow_size // pl_total if i ** exponent * flow_size // pl_total  > 0 else 1 for i in range(1, group_size + 1) ]
group_size_range = [[gap * i, gap * (i + 1)] for i in range(group_size)]
flow_size = sum(group)
base_number = 0
if plot:
    print("***********************************")
    print("the distribution of flow as size of flow increase:")
    terminalplot.plot(range(group_size), group)
while(group):
    sIP = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))
    dIP = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))
    protocal = ['udp', 'tcp'][random.randint(0, 1)]
    key = (sIP, dIP, protocal)
    flows_info[key] = [random.randint(group_size_range[-1][0] + 1, group_size_range[-1][1]), 0, 0]
    base_number += flows_info[key][0]
    group[-1] -= 1
    if group[-1] == 0:
        group.pop()
        group_size_range.pop()
print("***********************************")
print("flow size: ", flow_size)
print("group size: ", group_size)
print("***********************************")
output_trace = "synthetic"

if plot:
    group_size_range = [[gap * i, gap * (i + 1)] for i in range(group_size)]
    group = [0] * group_size
    final_group_dist = sorted([i[0] for i in list(flows_info.values())])
    for c in final_group_dist:
        index = c // gap
        if c % gap == 0:
            index -= 1
        group[index] += 1
    print("group size distribution w.r.t gaps")
    terminalplot.plot(range(group_size), group)
    print("distribution for each flow from small to largest")
    terminalplot.plot(range(len(final_group_dist)), final_group_dist)
print("total packets to write: x * ", base_number, "where x is equal to 1 if lower bound of packet size is smaller than base, else round up lowerbound / base_number")
try:
    os.remove(output_trace)
    print("removed the old output file")
    print("writing into file: synthetic")
    print("***********************************")
except:
    print("writing into file: synthetic")
    print("***********************************")

p, keys = 0, []
while(1):
    if attack and p >= start_time and p < start_time + duration:
        attack_kinds[attack](attack_size, output_trace)
    if not keys:
        if p >= packet_size:
            break
        keys = list(flows_info.keys())
    key, packet = random.choice(keys), None
    if key[2] == 'tcp':
        packet = Ether() / IP(dst=key[1], src=key[0]) / TCP()
    else:
        packet = Ether() / IP(dst=key[1], src=key[0]) / UDP()
    write(packet, output_trace)
    flows_info[key][1] += 1
    flows_info[key][2] += 1
    if flows_info[key][1] == flows_info[key][0]:
        keys.remove(key)
        flows_info[key][1] = 0
    p += 1

if plot:
    group_size_range = [[gap * i, gap * (i + 1)] for i in range(group_size)]
    group = [0] * group_size
    final_group_dist = sorted([i[2] for i in list(flows_info.values())])
    for c in final_group_dist:
        index = c // gap
        if c % gap == 0:
            index -= 1
        group[index] += 1
    print("group size distribution w.r.t gaps")
    terminalplot.plot(range(group_size), group)
    print("distribution for each flow from small to largest")
    terminalplot.plot(range(len(final_group_dist)), final_group_dist)
print("done!")


















