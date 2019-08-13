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

## 3. Steps to upgrade CentOS-7 kernel to TOT linux
- Centos7 latest installed on baremetal system with TPM2.0 (this device will be working as our provisioner/ client) 
- as centos latest kernel-3.10 doesnot have required eventlogs we need to upgrade the kernel to latest linux tree. at the time of writing this latest stable linux is 5.2.2. 
- install all dependancies for kernel upgrade
```bash
$ yum install makecache gcc make ncurses-devel bc openssl-devel elfutils-libelf-devel rpm-build flex bison 
```
- download latest linux kernel from https://www.kernel.org tarball and extract (tar xvf ) it. 
```bash 
$ cd  linux-5.2.2
```
- change the .config to running config on your centos by running  
```bash 
$ sudo cp -v /boot/config-3.10.0-957.27.2.el7.x86_64 .config
$ make menuconfig 
```
- make changes in the kernel --this step is required for ima patches
- save the new .config file 
- run following command to make sure you have atleast 30GB in your root partition
```bash
$ sudo df -h 
$ sudo make -j$(nproc) rpm-pkg
```
- wait for 2-3 hours based on your processor speed and memory for new kernel rpm generation.
- above step creats RPMS into /root/rpmbuild/RPMS/x86_64 so cd into that directory as root and run following command 
```bash
$ sudo yum install *.rpm (to update the new kernel) 
$ sudo reboot
```
- after reboot login to the new kernel and run  
```bash 
$ uname -r 
``` 
- you should see latest kernel version isntalled in centos 

- after this steps you have the base kernel required to patch for adding support for TCG specified TPM2.0 eventlog

## 4. Patch the kernel to add support for TCG TPM2.0 eventlog 
- copy the supplied two patches 0011-MGp1.patch and 0011-MGP2.patch rpmbuild/BUILD directory as follow 
```bash
$ cd /location/of/0011-MGP1.patch and 0011-MGP2.patch
$ cp *.patch /root/rpmbuild/SOURCES/ 
$ cd /root/rpmbuild/BUILD/kernel-5.2.2 
```
- replace scripts/package/mkspec with the supplied
```bash
$ cd /usr/src/kernel/kernel-5.2.2/
$ sudo make -j$(nproc) rpm-pkg 
```
- this step can take from 1 to 3 hours depending on your processor and cores. after sucessfully finishing, it should have written new kernel rpms in /root/rpmbuild/RPMS/x86_64. go to that directory and install the new kernel rpms
```bash 
$ cd /root/rpmbuild/RPMS/x86_64
$ sudo yum install *.rpm
```
- above step will install patched kernel and you can reboot and verify the new kernel version
-optional if you have different version name/number and you want to create a boot menu entry run following command to add new created kernel as boot menu item.
```bash 
$ grub2-mkconfig -o /boot/grub2/grub.cfg
````
at this point you can reboot the system.
```bash
$ sudo reboot 
```
- and login into new kernel, run following command to verify your new patched kernel version
```bash 
$ uname -r 
```
- you will see 5.3.2 kernel version.

## 5. Get TCG tpm2.0 spec event log
```bash  
$ cat /sys/kernel/security/tpm0/binary_bios_measurements > temp 
$ hexdump -C temp | more 
```
- will show you tpm2.0 eventlogs 
## 6. Steps to run Utility 

- download the supplied Utility folder into some place of your choice and copy temp into it 
```bash 
$ gcc -o tool tool.c -std=c99
$ ./tool temp
```
- this will show all events in new TCG eventlog format 
- if you want to have hexdump a utiliy is provided just run it with your binary blob
- if you want to run multiple tests with different blobs create a folder called testfiles and put all the binary blob files into it, we have supplied few blobs for testing
- while you were running ./tool temp tool has creatd results for the test run in result.txt file
- change the binary blob file names into tool.sh for running the utility against your blob
```bash 
$ ./tool.sh 
```
- will run all the tests and puts the results of each run in results folder 
- it will also open the report.txt on terminal 

## 7. Steps to change EFI setting(optional)

- Hash algorithms are bit mapped as following 
  Bit 0: SHA-1
  Bit 1: SHA-256 
  Bit 2: SHA-384 
so to set it in bios EFI run following command
```bash
$ sudo echo 23 b > /sys/class/tpm/tpm0/ppi/request 
```
- where ‘b’ is an integer interpreted as a bitmask 
```bash 
$ sudo reboot 
```
- while reboot kernel will ask you to confirm Hash algorithm change press F12 for intel bios 
- if you have selected SHA-1 and SHA-256 then you should see two PCR banks when you run 
```bash
$ tpm2_pcrlist
```
- this step requires tpm2-tss, tpm2-abrmd and tpm2-tools installed. if you don't have it yet, run the utility against supplied sample log blobs in testfiles and you should see events having selected Hashing algorithms
## 8.faq
