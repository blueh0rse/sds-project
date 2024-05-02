#!/bin/bash

# change this
workdir="~/sds/sds-project"

# create directories
cd "$workdir"
mkdir "tools"
mkdir "tmp"

# install ryu
cd "$workdir/tools/"
git clone https://github.com/osrg/ryu.git
cd "$workdir/tools/ryu"
sudo pip3 install ryu

# install influxdb
cd "$workdir/tmp"
wget https://dl.influxdata.com/influxdb/releases/influxdb_1.8.4_amd64.deb
sudo dpkg -i influxdb_1.8.4_amd64.deb
sudo apt update
sudo apt install -y python3-influxdb
rm influxdb_1.8.4_amd64.deb
sudo systemctl start influxdb

# install telegraf
cd "$workdir/tmp"
wget https://dl.influxdata.com/telegraf/releases/telegraf_1.17.3-1_amd64.deb
sudo dpkg -i telegraf_1.17.3-1_amd64.deb
rm telegraf_1.17.3-1_amd64.deb
sudo mv /etc/telegraf/telegraf.conf /etc/telegraf/telegraf.conf.bak
sudo cp "$workdir/config/telegraf.conf" "/etc/telegraf/"
sudo systemctl restart telegraf

# install grafana
cd "$workdir/tmp"
sudo apt install -y libfontconfig1
wget https://dl.grafana.com/oss/release/grafana_7.4.3_amd64.deb
sudo dpkg -i grafana_7.4.3_amd64.deb
rm grafana_7.4.3_amd64.deb
sudo systemctl start grafana-server
