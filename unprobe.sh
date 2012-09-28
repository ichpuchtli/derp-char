#!/bin/sh

# Check if module is still loaded and attempt to remove it
(lsmod | grep crypto > /dev/null) && rmmod crypto

# Check if cryptodev module is still loaded and attempt to remove it
(lsmod | grep cryptodev > /dev/null) && rmmod cryptodev

