from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.link import TCLink

def customTopology():
    "Create a network from scratch using Open vSwitch."

    net = Mininet(controller=RemoteController, link=TCLink, switch=OVSSwitch)

    print("*** Creating nodes")
    # Controllers
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)

    # Switches
    s1 = net.addSwitch('s1')
    s2 = net.addSwitch('s2')  # Assuming s2 is a load balancer

    # DMZ #1 Users
    h1 = net.addHost('h1', ip='10.0.0.1')
    h2 = net.addHost('h2', ip='10.0.0.2')
    h3 = net.addHost('h3', ip='10.0.0.3')

    # DMZ #2 Active Directory
    h4 = net.addHost('h4', ip='10.0.0.4')

    # Web Servers
    h5 = net.addHost('h5', ip='10.0.0.5')
    h6 = net.addHost('h6', ip='10.0.0.6')

    print("*** Creating links")
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)
    net.addLink(s1, s2)
    net.addLink(h4, s1)
    net.addLink(s2, h5)
    net.addLink(s2, h6)

    print("*** Starting network")
    net.build()
    c0.start()
    s1.start([c0])
    s2.start([c0])

    print("*** Running CLI")
    CLI(net)

    print("*** Stopping network")
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    customTopology()