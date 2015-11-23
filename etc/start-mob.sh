#!/bin/bash
MOBSTER_ROOT=/home/github/mobster; export MOBSTER_ROOT
if [ ! -d /var/run/suricata ]; then
   mkdir /var/run/suricata
fi
#
# requires daemon; apt-get install daemon
#
daemon --env="MOBSTER_ROOT=${MOBSTER_ROOT}" --respawn --output=/var/log/mobster.log --name=mobster ${MOBSTER_ROOT}/src/mobster
sleep 1
#
# To build suricata on rasberry pi see the following:
#
# https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Debian_Installation
#
/usr/local/bin/suricata -c /etc/suricata/suricata.yaml --disable-detection -i eth0 -D

