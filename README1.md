# Patch Fedora30(5.1.9-300) for TCG2.0 Eventlog
## 1. Integration
- since default fedora mainline kernel does not have support for eTCG2.0 eventlogs, we need to patch the kernel to bring TCG TPM2.0 eventlog to the user space. 
- ima TlV support is not supported in mainline linux,  so we provide additional patches for that.
- patches details :
- Eventlog folder contains four patches for tcg tpm2.0 eventlog support and kernel.spec file for building eventlogs standalone.
-Ima-tlv folder contains nine patches for ima-tlv support and kernel.spec file for building ima-tlv standalone.
- if you want to patch the kernel for both eventlog and ima-tlv support then use the kernel.spec file from Attestation-annotation folder and put all the patches (total thirteen= four(eventlog) + nine(ima-tlv)) into ~/rpmbuild/SOURCES/. 
- apply provided patches to kernel in numeric order, rebuild, and install the new kernel. 
- eventlog.c is a example code for parsing and validating TCG-2.0 evenlogs binary bios measurements.
## 2. Steps for kernel Build fedora 30
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
$ cp /boot/config-your-config .config
$ cp .config ~/rpmbuild/SOURCE/config-x86_64-generic
$ cd ~/rpmbuild/SPEC/ 
$ rpmbuild -ba --without debug --without doc --without perf -without tools --without debuginfo --without kdump --without bootwrapper --without cross_headers kernel.spec
```
- Wait for rpmbuild to build the kernel and it will create RPMS and SRPM in ~/rpmbuild/RPMS/x86_64/
```bash
$ cd  ~/rpmbuild/RPMS/x86_64/
# yum install kernel-*.rpm
Or 
# rpm -ivh kernel-*.rpm
```
- Build Part 2: 
```bash
$ cd ~/rpmbuild/SPECS
``` 
- replace the file with provided kernel.spec and put all the patches (total 13) into ~/rpmbuild/SOURCES/ directory 
- change the .config file to have have IMA_LIST_TLV=y and TEMPLATE not set as shown below.
```bash
# CONFIG_IMA_LIST_TEMPLATE is not set
CONFIG_IMA_LIST_TLV=y
```
- build the new kernel
```bash
$ cd ~/rpmbuild/SPECS/ 
$ rpmbuild -ba --without debug --without doc --without perf -without tools --without debuginfo --without kdump --without bootwrapper --without cross_headers kernel.spec
```
## 3. Steps
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