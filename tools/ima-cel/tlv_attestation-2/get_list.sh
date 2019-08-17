#!/bin/bash
# Daemon that copies ima measurement data to a file

#LIST=/sys/kernel/security/ima/tlv_runtime_measurements
LIST=/sys/kernel/security/ima/binary_runtime_measurements
LOG=/var/log/integrity/tlv_runtime_measurements
COUNT=/sys/kernel/security/ima/runtime_measurements_count

# on startup, rotate the measurement log
rm -f $LOG.1
mv $LOG $LOG.1
count=`cat $COUNT`
cat $LIST > $LOG

# loop forever
while :
do
  newcount=`cat $COUNT`
  if [ $newcount -gt $count ]
  then
    count=$newcount
    cat $LIST >> $LOG
  fi
  sleep 5
done
