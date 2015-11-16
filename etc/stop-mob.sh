#!/bin/bash

daemon --name=mobster --stop > /dev/null 2>&1
daemon --name=webdis --stop > /dev/null 2>&1
kill -9 $(pidof suricata) > /dev/null 2>&1

