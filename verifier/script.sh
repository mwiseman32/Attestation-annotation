#!/bin/bash
# My first script

cd /home/test/Downloads/demo/demo/demo1
tpm2_createprimary -g sha256 -G rsa -c primary.ctx > output.txt
tpm2_createek -c 0x8101000a -G rsa -u ekpub.pem -f pem
tpm2_createak -C 0x81010009 -c 0x8101000a -G rsa -s rsassa -g sha256 -u akpub.pem -f pem -n ak.name
