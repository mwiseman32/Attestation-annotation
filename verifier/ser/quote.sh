#!/bin/bash
# My first script

#cd /home/test/Downloads/demo/demo/demo1
tpm2_quote -c 0x8101000a -l sha256:15,16,22 -q abc123 -m quote.out -s sig.out -o pcrs.out -g sha256 > result
