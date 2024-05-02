# SDS Project

## Sofware-Defined Security Project

### Master of Cybersecurity

The project aims to simulate attacks on a network that resembles an enterprise environment. Acting as attackers, we'll conduct reconnaissance and launch attacks. Meanwhile, in the role of defenders, we'll watch over the network, spotting attacks, and responding automatically with security measures.

## Overview

```
.
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

6. Start the controlet using `ryu`

```bash
(.venv)$ sudo ryu-manager --verbose ryu.app.example_switch_13
```

7. Test hosts can communicate

```bash
mininet> h1 ping h2 -c 3
```
