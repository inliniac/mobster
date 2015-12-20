#!/bin/bash

# script to demonstrate loading bad IP list into redis 

redis-cli DEL "ip:negative" 
wget http://cinsscore.com/list/ci-badguys.txt -o /dev/null -O - | grep ^[^#\;] |  awk -F',' '{print " sadd ip:negative " $1}' | redis-cli

