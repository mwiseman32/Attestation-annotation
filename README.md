# Patch Fedora30(5.1.9-300) for TCG2.0 Eventlog
# Contents
1. [Introduction](#1-introduction)
2. [Why repo?](#2-why-repo)
3. [Steps for centOS-7  kernel upgrade](#3-Steps for centOS-7 kernel upgrade)
4. [Add support for TCG TPM2.0 eventlog](#4-Add support for TCG TPM2.0 eventlog)
5. [Steps to run Utility](#5-Steps to run Utility )
6. [Steps to change EFI setting(optional)](#6-Steps to change EFI setting(optional))
7. [FAQ](#7-faq)

## 1. Introduction
- since default fedora mainline kernel does not have support for eTCG2.0 eventlogs, we need to patch the kernel to bring TCG TPM2.0 eventlog to the user space. 
- ima TLV support is not supported in mainline linux,  so we provide additional patches for that.
- patches details :
- Eventlog folder contains four patches for tcg tpm2.0 eventlog support and kernel.spec file for building eventlogs standalone.
- Ima-tlv folder contains nine patches for ima-tlv support and kernel.spec file for building ima-tlv standalone.
- if you want to patch the kernel for both eventlog and ima-tlv support then use the kernel.spec file from Attestation-annotation folder and put all the patches (total thirteen= four(eventlog) + nine(ima-tlv)) into ~/rpmbuild/SOURCES/. 
- apply provided patches to kernel in numeric order, rebuild, and install the new kernel. 
- eventlog.c is a example code for parsing and validating TCG-2.0 evenlogs binary bios measurements.
## 2. Why this repo?
The patches we used for providing both the firmware event log and IMA TLV required 5.1.9 as they have both not been upstreamed.
## 3. Steps for kernel Build fedora 30
- Build Part 1: 

-Get the 5.1.9.fc30 from https://koji.fedoraproject.org/koji/buildinfo?buildID=1285871 
Or by follow the instruction from link: https://fedoraproject.org/wiki/Building_a_custom_kernel/Source_RPM 
```bash 
$ rpmdev-setuptree
$ koji download-build --arch=src kernel-5.1.9-300.fc30
$ rpm -Uvh kernel-5.1.9-300.fc30.src.rpm
```
- above command writes the RPM contents into ${HOME}/rpmbuild/SOURCES and ${HOME}/rpmbuild/SPECS
```bash
$ cp /boot/.config-`uname -r` ~/rpmbuild/SOURCES/config-x86_64-generic
$ cd ~/rpmbuild/SPECS/ 
$ rpmbuild -ba --without debug --without doc --without perf -without tools --without debuginfo --without kdump --without bootwrapper --without cross_headers kernel.spec
```
- Wait for rpmbuild to build the kernel and it will create RPMS and SRPM in ~/rpmbuild/RPMS/x86_64/
```bash
$ cd  ~/rpmbuild/RPMS/x86_64/
# yum install kernel-core-5.1.9-300.fc30.x86_64.rpm
# yum install kernel-modules-5.1.9-300.fc30.x86_64.rpm
# yum install kernel-modules-extras-5.1.9-300.fc30.x86_64.rpm
# yum install kernel-5.1.9-300.fc30.x86_64.rpm
# yum install kernel-devel-5.1.9-300.fc30.x86_64.rpm
```
- Build Part 2: 
```bash
$ cd ~/rpmbuild/SPECS
``` 
- replace the file with kernel.spec from the patches folder.
- put all patches (from patches/eventlog and patches/ima-tlv -- total of 13) into ~/rpmbuild/SOURCES/ directory 
- change each .config in ~/rpmbuild/SOURCES/ directory the following (manual operation for now, patch file to do this will be provided later):
```bash
# CONFIG_IMA_LIST_TEMPLATE is not set
CONFIG_IMA_LIST_TLV=y
```
- build the new kernel
```bash
$ cd ~/rpmbuild/SPECS/ 
$ rpmbuild -ba --without debug --without doc --without perf -without tools --without debuginfo --without kdump --without bootwrapper --without cross_headers kernel.spec
```
## 4. Steps to run eventlog utility and script 
- you should get TCG-2 eventlog in temp.txt binary blob. 
```bash
$ cat /sys/kernel/security/tpm0/binary_bios_measurements > temp.txt 
```
- create a folder and copy eventlog.c into it. 
```bash
$ gcc -o eventlog eventlog.c 
$ ./eventlog temp.txt > eventlog.txt
```
- you should get parsed eventlogs in eventlog.txt
- tools.sh is a script provids demo of the eventlog utility features, it takes sample eventlogs from testfiles folder and generates a test run in results folders along with reports.txt for summary of the run results.
## 5. Steps to setup hirs provisioner 
- before you begin this step please check that you have setisfied first three requirements from https://github.com/nsacyber/HIRS/wiki/installation_notes subtopic "Before You Begin".  
- To perform TPM 2.0 provisioning (Centos 7 latest version)
- install below listed dependencies: 
```bash
$ sudo yum install epel-release
$ sudo yum install log4cplus protobuf re2 libcurl procps-ng glib2-devel 
$ sudo yum install openssl-devel
$ sudo yum install dnf
$ sudo dnf builddep tpm2-tools
$ sudo dnf -y update && sudo dnf -y install automake libtool \
autoconf autoconf-archive libstdc++-devel gcc pkg-config \
uriparser-devel libgcrypt-devel dbus-devel glib2-devel \
compat-openssl10-devel libcurl-devel PyYAML
```
- provided HIRS_Provisioner_TPM_2_0-1.0.4-1558547257.cedc93.fc30.x86_64.rpm fedora 30 works with older tcg tpm2.0 intel stack so the older dependencies are also provided in dependancies folder. install all of them along with HIRS_Provisioner and tpm2_module as shown below.
```bash
$ sudo yum install tpm2-abrmd-1.1.0-12.fc28.x86_64.rpm
$ sudo yum install tpm2-abrmd-devel-1.1.0-12.fc28.x86_64.rpm
$ sudo yum install tpm2-tools-3.0.5-1.fc28.x86_64.rpm
$ sudo yum install tpm2-tss-1.4.0-2.el7.x86_64.rpm
$ sudo yum install tpm2-tss-devel-1.4.0-2.el7.x86_64.rpm
$ sudo yum install paccor-*.rpm
$ sudo yum install tpm_module*.rpm 
$ sudo yum install HIRS_Provisioner_TPM_2_0*.rpm
```
- To configure the provisioner, edit the hirs-site.config file in /etc/hirs/hirs-site.config. Edit the file to specify the ACA's fully qualified domain name/ ip address and port 
```bash
#*******************************************
#* HIRS site configuration properties file
#*******************************************
# Client configuration
TPM_ENABLED=true
IMA_ENABLED=true
CLIENT_HOSTNAME=$HOSTNAME
# Site-specific configuration
ATTESTATION_CA_FQDN=192.168.1.1
ATTESTATION_CA_PORT=8443
BROKER_FQDN=192.168.1.1
BROKER_PORT=61616
PORTAL_FQDN=192.168.1.1
PORTAL_PORT=8443
```
- save it and run following to setup SeLinux target policy
```bash 
$ dnf install selinux-policy-devel
$ sudo semodule -i /opt/hirs/extras/aca/tomcat-mysql-hirs.pp
```
- Now, have a box vm client or any centos7 client system and install the ACA client 
```bash 
$ sudo yum install mariadb-server openssl tomcat java-1.8.0 rpmdevtools coreutils initscripts chkconfig sed grep firewalld policycoreutils
$ sudo yum install HIRS_AttestationCA*.rpm
```
- In your browser, navigate to the ACA Portal URL: https://<ACAserveraddress>:8443/HIRS_AttestationCAPortal/
- where <ACAserveraddress> is ip address of ACA client, for our example it 192.168.1.1

- Usage:
- For a device with a TPM 2.0, the command is the same:
```bash 
$ sudo hirs-provisioner -c 
```
- on the device with TPM , issue the following command in a terminal:
```bash
$ sudo tpm_aca_provision
```
- make sure you have tpm2-abrmd started 
```bash
$ sudo -u tss tpm2-abrmd & 
```
- when you run the device provisioner you should see something like following  
```bash 
$ sudo tpm_aca_provision
--> Configuring provisioner
----> Deleting existing key store
----> Downloading truststore
--> Provisioning
----> Removing old attestation credentials, if any
----> Provisioning TPM
--> Provisioning
----> Collecting endorsement credential from TPM
----> Creating attestation key
----> Collecting platform credential from TPM
------> Unable to retrieve platform credential
----> Collecting device information
----> Sending identity claim to Attestation CA
----> Received response. Attempting to decrypt nonce
----> Nonce successfully decrypted. Sending attestation certificate request
----> Storing attestation key certificate
----> Provisioning successful
```




