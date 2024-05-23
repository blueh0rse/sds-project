#!/bin/bash

# Set the working directory
workdir=~/sds/sds-project

# Create directories if they don't already exist
mkdir -p "$workdir/tools"
mkdir -p "$workdir/tmp"

# Update the package list
sudo apt update

# Install Ryu if not already installed
if [ ! -d "$workdir/tools/ryu" ]; then
    cd $workdir/tools/
    git clone https://github.com/osrg/ryu.git
    cd ryu
    sudo pip3 install ryu
else
    echo "Ryu is already installed."
fi

# Install InfluxDB if not already installed
if [ ! -f "$workdir/tmp/influxdb_1.8.4_amd64.deb" ]; then
    cd $workdir/tmp
    wget https://dl.influxdata.com/influxdb/releases/influxdb_1.8.4_amd64.deb
fi

sudo dpkg -i $workdir/tmp/influxdb_1.8.4_amd64.deb
sudo apt install -y python3-influxdb
sudo systemctl start influxdb

# Install Telegraf if not already installed
if [ ! -f "$workdir/tmp/telegraf_1.17.3-1_amd64.deb" ]; then
    cd $workdir/tmp
    wget https://dl.influxdata.com/telegraf/releases/telegraf_1.17.3-1_amd64.deb
fi

sudo dpkg -i $workdir/tmp/telegraf_1.17.3-1_amd64.deb

if [ -f "/etc/telegraf/telegraf.conf" ]; then
    sudo mv /etc/telegraf/telegraf.conf /etc/telegraf/telegraf.conf.bak
fi

sudo cp $workdir/config/telegraf.conf /etc/telegraf/
sudo systemctl restart telegraf

# Install Grafana if not already installed
if [ ! -f "$workdir/tmp/grafana_7.4.3_amd64.deb" ]; then
    cd $workdir/tmp
    wget https://dl.grafana.com/oss/release/grafana_7.4.3_amd64.deb
fi

sudo apt install -y libfontconfig1
sudo dpkg -i $workdir/tmp/grafana_7.4.3_amd64.deb
sudo systemctl start grafana-server

echo "Setup script completed."
