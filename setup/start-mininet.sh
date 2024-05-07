#!/bin/bash

# change this
workdir=~/sds/sds-project
cd $workdir

# initialize mininet
sudo mn -c
sudo python3 ./network/topology.py