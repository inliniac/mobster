#!/bin/bash

MOBSTER_ROOT=/home/mobster; export MOBSTER_ROOT
if [ ! -d /var/run/suricata ]; then
   mkdir /var/run/suricata
fi
#
# apt-get install daemon
#
daemon --env="MOBSTER_ROOT=${MOBSTER_ROOT}" --respawn --output=/var/log/mobster.log --name=mobster /home/randy/mobster/src/mobster
sleep 1
#
# To build suricata see the following:
#
# https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Debian_Installation
#
/usr/bin/suricata -c /etc/suricata/suricata.yaml --disable-detection -i eth0 -D

