#!/bin/bash

# change this
workdir=~/sds/sds-project
cd $workdir

# Setup snort
sudo killall -s SIGKILL snort

sudo cp $workdir/config/snort.conf /etc/snort/snort.conf
sudo cp $workdir/config/SDS-project_SnortRules.rules /etc/snort/rules/SDS-project_SnortRules.rules

sudo $workdir/scripts/add-port.sh s2 snort-mirror
sudo $workdir/scripts/add-mirror.sh s2 snort snort-mirror
sudo $workdir/scripts/add-traffic-to-mirror.sh snort s2-eth1 all

sudo snort -i snort-mirror -A unsock -l /tmp -c /etc/snort/snort.conf -q -D > /dev/null 2>&1

# Start Ryu
cd $workdir/tools/ryu/
sudo ryu-manager $workdir/network/sdn_switch.py