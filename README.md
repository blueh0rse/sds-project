# SDS Project

## Sofware-Defined Security Project

### Master of Cybersecurity

The project aims to simulate attacks on a network that resembles an enterprise environment. Acting as attackers, we'll conduct reconnaissance and launch attacks. Meanwhile, in the role of defenders, we'll watch over the network, spotting attacks, and responding automatically with security measures.

## Overview

```
.
├── config
│   └── telegraf.conf
├── LICENSE
├── network
│   └── topology.py
├── README.md
├── requirements.txt
├── setup
│   └── setup.sh
└── tools
    └── ryu

5 directories, 6 files
```

## Requirements

To be able to run this project you must use an Ubuntu 20.04 VM.

## Instructions

### Setup

1. Clone the repository

```bash
git clone https://github.com/blueh0rse/sds-project
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
```

5. Start the network using `mininet`

```bash
(.venv)$ sudo python3 setup/network.py
```

6. Check network state

```bash
mininet> net
h1 h1-eth0:s1-eth1
h2 h2-eth0:s1-eth2
h3 h3-eth0:s1-eth3
h4 h4-eth0:s1-eth5
h5 h5-eth0:s2-eth2
h6 h6-eth0:s2-eth3
s1 lo:  s1-eth1:h1-eth0  s1-eth2:h2-eth0  s1-eth3:h3-eth0  s1-eth4:s2-eth1  s1-eth5:h4-eth0
s2 lo:  s2-eth1:s1-eth4  s2-eth2:h5-eth0  s2-eth3:h6-eth0
c0
```

### Network rules

1. Start the controlet using `ryu`

```bash
(.venv)$ sudo ryu-manager --verbose tools/ryu/ryu/app/simple_monitor_13.py
```

2. Test hosts can communicate

```bash
mininet> h1 ping h2 -c 3
```
