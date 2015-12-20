#!/bin/bash
#
# To build suricata on rasberry pi see the following:
#
# https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Debian_Installation
#
/usr/local/bin/suricata -c /etc/suricata/suricata.yaml --disable-detection -i eth0 -D

