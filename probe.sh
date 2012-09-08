#!/bin/sh

module="crypto"
device="crypto"
mode="664"
major=250

# Make and exit if unsuccessful
make > /dev/null || exit 1

# Check if module is still loaded and attempt to remove it
(lsmod | grep crypto > /dev/null) && rmmod $module

# Install module
insmod ./$module.ko $* || exit 2

# Don't need object files any more
make clean

# Remove stale node
rm -f /dev/crypto

# Make new node
mknod /dev/${device} c $major 0

# Change file group and permissions
chgrp comp3301 /dev/crypto
chmod $mode /dev/crypto

# Acknowledge with dmesg
dmesg | tail -1
