#!/bin/sh
mkdir result
./tool testfiles/tm > result/sha1256
./tool testfiles/dumpsha1384 > result/sha1384
./tool testfiles/sha256 > result/sha256
./tool testfiles/shaall3 > result/shaall3
./tool testfiles/log1256 > result/log1256
./tool testfiles/log256 > result/log256
./tool testfiles/logall > result/logall
cp result.txt result/
cd result
gedit result.txt & 
