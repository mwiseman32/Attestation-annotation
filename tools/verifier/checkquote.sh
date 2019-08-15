#!/bin/bash
# My first script

#cd /home/test/Downloads/demo/demo/demo1
tpm2_checkquote -u akpub.pem -m quote.out -s sig.out -f pcrs.out -g sha256 -q abc123 > resque
