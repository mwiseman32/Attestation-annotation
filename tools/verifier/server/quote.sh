#!/bin/bash
# My first script

#cd /home/test/Downloads/demo/demo/demo1
#tpm2_quote -c 0x8101000a -l sha256:15,16,22 -q abc123 -m quote.out -s sig.out -o pcrs.out -g sha256 > result
tpm2_quote -k 0x8101000b -L sha1:16,17,18+sha256:16,17,18 -q 11aa22bb -m quote.out -s sig.out -g sha256 > result
#tpm2_pcrlist -L sha1:16,17,18 > pcr
