#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
traffic_generator_random.py

Chạy trên Python2, khởi tạo Mininet và tạo traffic xen kẽ ngẫu nhiên giữa các loại:
 1. TCP SYN Flood
 2. UDP Benign
 3. UDP Flood
 4. ICMP Flood
 5. Smurf
   -- mỗi lần loop sleep 1.5s
"""
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.node import OVSKernelSwitch, RemoteController
from time import sleep
from random import randrange, choice, shuffle

ITER = 6
DELAY = 1.5

class MyTopo(Topo):
    def build(self):
        switches = []
        for i in range(6):
            s_name = 's%d' % (i+1)
            s = self.addSwitch(s_name,
                               cls=OVSKernelSwitch,
                               protocols='OpenFlow13')
            switches.append(s)
            for j in range(3):
                idx = i*3 + j + 1
                h_name = 'h%d' % idx
                mac    = '00:00:00:00:00:%02x' % idx
                ip     = '10.0.0.%d/24' % idx
                self.addHost(h_name, cpu=1.0/20, mac=mac, ip=ip)
                self.addLink(h_name, s_name)
        for k in range(len(switches)-1):
            self.addLink(switches[k], switches[k+1])

def ip_generator():
    return "10.0.0.%d" % randrange(1,4)

def tcp_flood(net):
    hosts = [ net.get('h%d' % i) for i in range(1,19) ]
    src = choice(hosts)
    dst = choice(hosts)
    while dst == src:
        dst = choice(hosts)
    victim = dst.IP()
    spoof  = ip_generator()
    src.cmd('timeout 5s hping3 -S --flood -a %s %s' % (spoof, victim))


def udp_benign(net):
    hosts = [ net.get('h%d' % i) for i in range(1,19) ]
    src = choice(hosts)
    dst = choice(hosts)
    while dst == src:
        dst = choice(hosts)
    dport     = randrange(1024, 65535)
    pkt_count = randrange(3,6)
    pkt_size  = randrange(60,100)
    src.cmd('hping3 --udp -c %d -d %d -p %d %s' % (
        pkt_count, pkt_size, dport, dst.IP()))


def udp_flood(net):
    hosts = [ net.get('h%d' % i) for i in range(1,19) ]
    src = choice(hosts)
    dst = choice(hosts)
    while dst == src:
        dst = choice(hosts)
    victim = dst.IP()
    spoof  = ip_generator()
    src.cmd('timeout 5s hping3 -2 --flood -a %s %s' % (spoof, victim))


def icmp_flood(net):
    hosts = [ net.get('h%d' % i) for i in range(1,19) ]
    src = choice(hosts)
    dst = choice(hosts)
    while dst == src:
        dst = choice(hosts)
    victim = dst.IP()
    src.cmd('timeout 5s hping3 -1 --flood %s' % victim)


def smurf(net):
    hosts = [ net.get('h%d' % i) for i in range(1,19) ]
    broadcast = '10.0.0.255'
    src   = choice(hosts)
    spoof = ip_generator()
    src.cmd('timeout 5s hping3 -1 --flood -a %s %s' % (spoof, broadcast))

if __name__ == '__main__':
    setLogLevel('info')
    topo = MyTopo()
    net = Mininet(topo=topo,
                  link=TCLink,
                  controller=RemoteController('c0',
                                              ip='192.168.1.62',
                                              port=6653))
    net.start()

    # Tạo danh sách các hàm traffic, mỗi hàm lặp ITER lần
    traffic_funcs = [tcp_flood, udp_benign, udp_flood, icmp_flood, smurf]
    sequence = []
    for func in traffic_funcs:
        sequence.extend([func] * ITER)
    shuffle(sequence)

    try:
        print "\n=== START RANDOM TRAFFIC ==="
        for func in sequence:
            func(net)
            sleep(DELAY)
    finally:
        print "\n=== STOPPING NETWORK ==="
        net.stop()

