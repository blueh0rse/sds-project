from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.link import TCLink

def customTopology():
    net = Mininet(controller=RemoteController, link=TCLink, switch=OVSSwitch)

    print("*** Creating nodes")

    # Controllers
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)

    # Switches
    sLoadBalancer = net.addSwitch('s10')
    sPublicUsers = net.addSwitch('s4')
    sPrivateServers = net.addSwitch('s3')
    sUsers = net.addSwitch('s2')
    sGeneral = net.addSwitch('s1')

    # Users
    h1 = net.addHost('h1', ip='10.0.1.1/16', mac='00:00:00:00:01:01')
    h2 = net.addHost('h2', ip='10.0.1.2/16', mac='00:00:00:00:01:02')
    h3 = net.addHost('h3', ip='10.0.1.3/16', mac='00:00:00:00:01:03')

    # Active Directory
    pad = net.addHost('pad', ip='10.0.2.1/16', mac='00:00:00:00:02:01')

    # DMZ #3 Web Servers
    ws1 = net.addHost('ws1', ip='10.0.3.1/16', mac='00:00:00:00:03:01')
    ws2 = net.addHost('ws2', ip='10.0.3.2/16', mac='00:00:00:00:03:02')

    # Public Users
    pu1 = net.addHost('pu1', ip='10.0.255.1/16', mac='00:00:00:00:ff:01')
    pu2 = net.addHost('pu2', ip='10.0.255.2/16', mac='00:00:00:00:ff:02')

    print("*** Creating links")
    net.addLink(h1, sUsers)
    net.addLink(h2, sUsers)
    net.addLink(h3, sUsers)

    net.addLink(pad, sPrivateServers)

    net.addLink(pu1, sPublicUsers)
    net.addLink(pu2, sPublicUsers)

    net.addLink(ws1, sLoadBalancer)
    net.addLink(ws2, sLoadBalancer)

    net.addLink(sGeneral, sLoadBalancer)
    net.addLink(sGeneral, sUsers)
    net.addLink(sGeneral, sPrivateServers)
    net.addLink(sGeneral, sPublicUsers)

    print("*** Starting network")
    net.build()
    c0.start()
    sGeneral.start([c0])
    sLoadBalancer.start([c0])
    sUsers.start([c0])
    sPrivateServers.start([c0])
    sPublicUsers.start([c0])

    h1.cmd('sysctl -w net.ipv6.conf.all.disable_ipv6=1')
    h2.cmd('sysctl -w net.ipv6.conf.all.disable_ipv6=1')
    h3.cmd('sysctl -w net.ipv6.conf.all.disable_ipv6=1')
    pad.cmd('sysctl -w net.ipv6.conf.all.disable_ipv6=1')
    pu1.cmd('sysctl -w net.ipv6.conf.all.disable_ipv6=1')
    pu2.cmd('sysctl -w net.ipv6.conf.all.disable_ipv6=1')
    ws1.cmd('sysctl -w net.ipv6.conf.all.disable_ipv6=1')
    ws2.cmd('sysctl -w net.ipv6.conf.all.disable_ipv6=1')

    print("*** Running CLI")
    CLI(net)

    print("*** Stopping network")
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    customTopology()
