#!/bin/bash

# Define the device name
DEVICE="/dev/asgn2"
MODULE="asgn2"

# Function to display the last few lines of dmesg and exit
function do_exit {
    echo -e "\nShowing recent kernel messages..."
    # dmesg | tail -n 20
    exit 1
}

# Clear the screen and compile the module
clear
echo -e "\nCompiling the kernel module..."
make clean && make || { echo "Compilation failed!"; do_exit; }

# Unload the module if it's already loaded
if lsmod | grep "$MODULE" &> /dev/null; then
    echo -e "\nRemoving the existing module..."
    sudo rmmod $MODULE || { echo "Failed to remove the module!"; do_exit; }
else
    echo -e "\nModule not loaded; no need to remove."
fi

# Insert the module
echo -e "\nInserting the module..."
sudo insmod $MODULE.ko || { echo "Failed to insert the module!"; do_exit; }

# Set permissions for the device
if [ -e "$DEVICE" ]; then
    echo -e "\nSetting permissions for $DEVICE..."
    sudo chown $(whoami):$(whoami) $DEVICE || { echo "Failed to set permissions!"; do_exit; }
else
    echo -e "\nDevice $DEVICE does not exist. Did the module create it?"
    do_exit
fi

