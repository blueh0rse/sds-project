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
    sGeneral = net.addSwitch('s1')
    sUsers = net.addSwitch('s2')
    sPrivateServers = net.addSwitch('s3')
    sPublicUsers = net.addSwitch('s4')
    sLoadBalancer = net.addSwitch('s10')

    # VLAN #1 - Users
    h1 = net.addHost('h1', ip='10.0.1.1/16', mac='00:00:00:00:01:01')
    h2 = net.addHost('h2', ip='10.0.1.2/16', mac='00:00:00:00:01:02')
    h3 = net.addHost('h3', ip='10.0.1.3/16', mac='00:00:00:00:01:03')

    # VLAN #2 - Workers
    h4 = net.addHost('h4', ip='10.0.2.1/16', mac='00:00:00:00:02:01')
    h5 = net.addHost('h5', ip='10.0.2.2/16', mac='00:00:00:00:02:02')
    h6 = net.addHost('h6', ip='10.0.2.3/16', mac='00:00:00:00:02:03')

    # VLAN #3 - Admins
    h7 = net.addHost('h7', ip='10.0.3.1/16', mac='00:00:00:00:03:01')
    h8 = net.addHost('h8', ip='10.0.3.2/16', mac='00:00:00:00:03:02')
    h9 = net.addHost('h9', ip='10.0.3.3/16', mac='00:00:00:00:03:03')

    # VLAN #4 - Active Directory Server
    ad = net.addHost('ad', ip='10.0.4.1/16', mac='00:00:00:00:04:01')

    # VLAN #5 - Web Servers Pool
    web1 = net.addHost('web1', ip='10.0.5.1/16', mac='00:00:00:00:05:01')
    web2 = net.addHost('web2', ip='10.0.5.2/16', mac='00:00:00:00:05:02')

    # VLAN #6 - Public Users
    pub1 = net.addHost('pub1', ip='10.0.255.1/16', mac='00:00:00:00:ff:01')
    pub2 = net.addHost('pub2', ip='10.0.255.2/16', mac='00:00:00:00:ff:02')

    print("*** Creating links")
    
    net.addLink(h1, sUsers)
    net.addLink(h2, sUsers)
    net.addLink(h3, sUsers)
    net.addLink(h4, sUsers)
    net.addLink(h5, sUsers)
    net.addLink(h6, sUsers)
    net.addLink(h7, sUsers)
    net.addLink(h8, sUsers)
    net.addLink(h9, sUsers)

    net.addLink(ad, sPrivateServers)

    net.addLink(pub1, sPublicUsers)
    net.addLink(pub2, sPublicUsers)

    net.addLink(web1, sLoadBalancer)
    net.addLink(web2, sLoadBalancer)

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

    # Disabling IPv6 for: h1 h2 h3 h4 h5 h6 h7 h8 h9 ad web1 web2 pub1 pub2
    for h in net.hosts:
        h.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")

    print("*** Running CLI")
    CLI(net)

    print("*** Stopping network")
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    customTopology()
