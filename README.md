# Attestation-annotation

## Contents
1. [Introduction](#1-introduction)
2. [Why repo?](#2-why-repo)
3. [Steps for centOS-7  kernel upgrade](#3-Steps for centOS-7 kernel upgrade)
4. [Add support for TCG TPM2.0 eventlog](#4-Add support for TCG TPM2.0 eventlog)
5. [Steps to run Utility](#5-Steps to run Utility )
6. [Steps to change EFI setting(optional)](#6-Steps to change EFI setting(optional))
7. [FAQ](#7-faq)


## 1. Introduction
  A collection of references to attestation projects, instructions, application notes, and glue code, hints, requests for new projects, etc.
## 2. Why repo?
- tool.c is the main program which parses the tpm2.- TCG eventlog and generates different outputs based on parameters provided
- tool.sh is a script to run the tests on selected binary dump data for bios_runtime measurements and it generates the report in results.txt file at the end. 


## 3. Steps for CentOS-7 kernel upgrade


- Centos7 latest installed on baremetal system with TPM2.0 (this device will be working as our provisioner/ client) 
- as centos latest kernel-3.10 doesnot have required eventlogs we need to upgrade the kernel to latest linux tree. at the time of writing this latest stable linux is 5.2.2. 
- install all dependancies for kernel upgrade
$ yum install makecache gcc make ncurses-devel bc openssl-devel elfutils-libelf-devel rpm-build 

- download latest linux kernel from https://www.kernel.org tarball and extract (tar xvf ) it. 
- cd  linux-5.2.2
- change the .config to running config on your centos by running "$sudo cp -v /boot/config-* .config" 
- make menuconfig (make changes in the kernel --this step is required for ima patches) 
- save the new .config file 
- ```bash
  $ sudo df -h 
  ```
- to make sure you have atleast 30GB in your root partition 
- $sudo make rpm-pkg  (wait for 2-3 hours based on your processor speed and memory for new kernel rpm generation) 
- above step creats RPMS into /root/rpmbuild/RPMS/x86_64 so cd into that directory as root 
- #rpm -iUv *.rpm (to update the new kernel) 
- #reboot 
- after reboot login to the new kernel and run  "#uname -r " you should see latest kernel version isntalled in centos 


after this steps you have the base kernel required to patch for adding support for TCG specified TPM2.0 eventlog

## 4. Patch the kernel to add support for TCG TPM2.0 eventlog 

- cd /usr/src/kernels
- cp *.patch /root/rpmbuild/BUILD/ 
- cd /root/rpmbuild/BUILD/kernel-5.2.2 
- replace scripts/package/mkspec with the supplied
- $sudo make rpm-pkg and wait for 2-3 hours 
- #cd /root/rpmbuild/RPMS/x86_64
- #rpm -iUv *.rpm this will install patched kernel 
- reboot and login into new kernel 
- #uname -r you will see 5.3.2 kernel version 
- cat /sys/kernel/security/tpm0/binary_bios_measurements > temp 
- hexdump -C temp | more , will show you tpm2.0 eventlogs 

## 5. Steps to run Utility 

- download the supplied Utility folder into some place of your choice and copy temp into it 
- gcc -o tool tool.c -std=c99
- ./tool temp , this will show all events in new TCG eventlog format 
- if you want to have hexdump a utiliy is provided just run it with your binary blob
- if you want to run multiple tests with different blobs create a folder called testfiles and put all the binary blob files into it, we have supplied few blobs for testing
- while you were running ./tool temp tool has creatd results for the test run in result.txt file
- change the binary blob file names into tool.sh for running the utility agenst your blob
- ./tool.sh , will run all the tests and puts the results of each run in results folder 
- it will also open the report.txt on terminal 

## 6. Steps to change EFI setting(optional)

- Hash algorithms are bit mapped as following 
  Bit 0: SHA-1
  Bit 1: SHA-256 
  Bit 2: SHA-384 
so to set it in bios EFI run following command 
- echo 23 b > /sys/class/tpm/tpm0/ppi/request ,where ‘b’ is an integer interpreted as a bitmask 
- reboot 
- while reboot kernel will ask you to confirm Hash algorithm change press F12 for intel bios 
- if you have selected SHA-1 and SHA-256 then you should see two PCR banks when you run 
- tpm2_pcrlist (this step requires tpm2-tss, tpm2-abrmd and tpm2-tools installed) if you don't have it yet run the utility against new blob and you should see events having selected Hashing algorithms
## 7.faq
