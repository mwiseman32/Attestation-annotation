#!/bin/bash
# My first script
cat resque | sed -n 6p > check
cat result | grep sig: > quote
sed -i '1d' quote
diff -u quotenew check
