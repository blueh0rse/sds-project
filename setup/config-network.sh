#!/bin/bash

# change this
workdir=~/sds/sds-project
cd $workdir

# Setup snort
sudo ovs-vsctl add-port s1 s1-snort
sudo snort -i s1-snort -A unsock -l /tmp -c /etc/snort/snort.conf -q -D > /dev/null 2>&1
cd $workdir/tools/ryu/
sudo ryu-manager ryu/app/simple_switch_snort.py