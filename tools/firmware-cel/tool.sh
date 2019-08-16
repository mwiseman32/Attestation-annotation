#!/bin/sh
mkdir result
./tool testfiles/tm > result/sha1256
./tool testfiles/sha256 > result/sha256
./tool testfiles/log1256 > result/log1256
./tool testfiles/log256 > result/log256
cp result.txt result/
cd result
gedit result.txt & 
