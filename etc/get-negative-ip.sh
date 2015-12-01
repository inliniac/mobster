#!/bin/bash
MOBSTER_DIR=/home/randy/github/mobster
NEGATIVE_IP_FILE=${MOBSTER_DIR}/ip-negative.lst
wget http://cinsscore.com/list/ci-badguys.txt -O ${NEGATIVE_IP_FILE} -o /dev/null

logger -t mobster Loading negative ip addresses
redis-cli DEL "ip:negative" 
while read ipaddress; do
  #echo $ipaddress
  redis-cli SADD "ip:negative" $ipaddress
done <${NEGATIVE_IP_FILE}

