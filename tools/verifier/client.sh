#!/bin/bash
# Client script
hostname -f > clientinfo.txt
ifconfig virbr0 | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' >> clientinfo.txt
date +"%d-%m-%y" >> clientinfo.txt
date +"%T" >> clientinfo.txt
