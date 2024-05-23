# SDS Project

## Sofware-Defined Security Project

### Master of Cybersecurity

The project aims to simulate attacks on a network that resembles an enterprise environment. Acting as attackers, we'll conduct reconnaissance and launch attacks. Meanwhile, in the role of defenders, we'll watch over the network, spotting attacks, and responding automatically with security measures.

## Overview

```
.
├── attacks
│   └── dos.py
├── config
│   ├── SDS-project_SnortRules.rules
│   ├── snort.conf
│   └── telegraf.conf
├── LICENSE
├── network
│   ├── custom_switch.py
│   ├── firewall_controller.py
│   ├── sdn_switch.py
│   └── topology.py
├── README.md
├── requirements.txt
├── scripts
│   ├── add-mirror.sh
│   ├── add-port.sh
│   ├── add-traffic-to-mirror.sh
│   ├── links
│   └── send-ICMP.py
├── setup
│   ├── config-network.sh
│   ├── setup.sh
│   └── start-mininet.sh
├── SimpleAPI
│   └── SimpleAPI.py
└── SimpleSSH
    └── SimpleSSH.py

7 directories, 21 files
```

## Requirements

To be able to run this project you must use an Ubuntu 20.04 VM.

## Instructions

### Setup

1. Clone the repository

```bash
git clone https://github.com/blueh0rse/sds-project
cd sds-project
chmod -R +x ./setup/ ./scripts/
```

2. Create a virtual environment

```bash
python3 -m venv .venv
```

3. Activate the virtual environment

```bash
source .venv/bin/activate
```

4. Install the dependencies

```bash
(.venv)$ pip install -r requirements.txt
or
(.venv)$ python3 -m pip install -r requirements.txt
```

5. Install required software

```bash
(.venv)$ ./setup/setup.sh
```

5. 1. Manually install snort

```bash
(.venv)$ sudo apt install -y snort
```
> [!Important]
> You must specify the interface `ens33`, or related, and the subnetwork `(10.0.0.0/16)`

6. Start the network using `mininet`

```bash
(.venv)$ ./setup/start-mininet.sh
```

8. Check network state

```bash
mininet> net
# VLAN 1 - users
h1 h1-eth0:s2-eth1
h2 h2-eth0:s2-eth2
h3 h3-eth0:s2-eth3
# VLAN 2 - workers
h4 h4-eth0:s2-eth4
h5 h5-eth0:s2-eth5
h6 h6-eth0:s2-eth6
# VLAN 3 - admins
h7 h7-eth0:s2-eth7
h8 h8-eth0:s2-eth8
h9 h9-eth0:s2-eth9
# VLAN 4 - AD
ad ad-eth0:s3-eth1
# VLAN 5 - web servers
web1 web1-eth0:s10-eth1
web2 web2-eth0:s10-eth2
# VLAN 6 - internet
pub1 pub1-eth0:s4-eth1
pub2 pub2-eth0:s4-eth2
# link(s)
s1 lo:  s1-eth1:s10-eth3 s1-eth2:s2-eth10 s1-eth3:s3-eth2 s1-eth4:s4-eth3
s2 lo:  s2-eth1:h1-eth0 s2-eth2:h2-eth0 s2-eth3:h3-eth0 s2-eth4:h4-eth0 s2-eth5:h5-eth0 s2-eth6:h6-eth0 s2-eth7:h7-eth0 s2-eth8:h8-eth0 s2-eth9:h9-eth0 s2-eth10:s1-eth2
s3 lo:  s3-eth1:ad-eth0 s3-eth2:s1-eth3
s4 lo:  s4-eth1:pub1-eth0 s4-eth2:pub2-eth0 s4-eth3:s1-eth4
s10 lo:  s10-eth1:web1-eth0 s10-eth2:web2-eth0 s10-eth3:s1-eth1
# controller(s)
c0
```

8. Configure the network and initialize Ryu and Snort

```bash
(.venv)$ ./setup/config-network.sh
```

### Network test

1. Test hosts can communicate

```bash
mininet> h1 ping h2 -c 3
```

### Setup servers

1. Start private server

```bash
mininet> xterm ad
```
```bash
ad> python3 SimpleSSH/SimpleSSH.py 10.0.4.1 2222
```

2. Start web servers

```bash
mininet> xterm web1 web2
```

```bash
web1> python3 SimpleAPI/SimpleAPI.py 10.0.5.1
```

```bash
web2> python3 SimpleAPI/SimpleAPI.py 10.0.5.2
```

3. Test private server

```bash
mininet> xterm h1
```

```bash
h1> telnet 10.0.4.1 2222
telnet> admin
telnet> admin
```

4. Test web servers

```bash
mininet> xterm pub1
```

```bash
pub1> curl 10.0.0.100
pub1> curl 10.0.0.100:80/about
pub1> curl 10.0.0.100:80/contact
```

### Performing the attacks

1. Port scanning

```bash
mininet> xterm h1
```

```bash
h1> python3 attacks/port_scanning.py 10.0.2.1 0 300
```
```bash
h1> python3 attacks/port_scanning.py 10.0.2.1 10000 20000
```

2. ICMP flooding
```bash
mininet> xterm pu1 [pu2]
```

```bash
pu1> python3 attacks/dos_icmp.py faster 10.0.3.1
```

```bash
pu2> python3 attacks/dos_icmp.py fast 10.0.3.1
```


### TODO List

- [ ] Finish presentation
- [x] Add Load balancer
- [x] Add Monitoring
    - [x] ICMP requests
    - [x] TCP Port Scan
    - [x] SSH attempts
    - [x] HTTP requests
- [ ] Add hacker script
    - [ ] Ping
    - [x] Port scan
    - [ ] SSH brute force
    - [x] DoS
- [x] Implement counter-measures of all the Snort's alerts
- [ ] Add other users?
- [x] Configure [Custom Switch](/network/custom_switch.py) to monitor the network
- [x] Expand the rules of [Snort Rules](/config/SDS-project_SnortRules.rules)
