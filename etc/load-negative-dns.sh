#!/bin/bash

# script to demonstrate loading bad DNS list into redis 

redis-cli DEL "dns:negative"
wget http://osint.bambenekconsulting.com/feeds/dga-feed.txt -O - | grep ^[^#\;] |  awk -F',' '{print " sadd dns:negative " $1}' | redis-cli

