#!/bin/bash

# change this
workdir=~/sds/sds-project
cd $workdir

# Setup snort
# sudo killall -s SIGKILL snort
sudo cp $workdir/config/snort.conf /etc/snort/snort.conf
sudo cp $workdir/config/SDS-project_SnortRules.rules /etc/snort/rules/SDS-project_SnortRules.rules
# sudo ovs-vsctl add-port s2 s1-snort
# sudo snort -i s1-snort -A unsock -l /tmp -c /etc/snort/snort.conf -q -D > /dev/null 2>&1
cd $workdir/tools/ryu/
sudo ryu-manager $workdir/network/custom_switch.py