MODULE_NAME = asgn2

# Kernel module files (asgn2.c and gpio.c)
obj-m := $(MODULE_NAME).o
$(MODULE_NAME)-objs = asgn2_skel.o  # List all source files that are part of the module

# Define the user-space application
USER_APP = data_generator

# Define paths for the kernel build system and current directory
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

# Build kernel module and user-space application
all: module userapp

# Kernel module target
module:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# User-space application target
userapp: $(USER_APP)

# Compile user-space application using GCC
$(USER_APP): data_generator.c
	gcc -o $(USER_APP) data_generator.c

# Clean both kernel module and user-space application
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f $(USER_APP)

# Help target for kernel module
help:
	$(MAKE) -C $(KDIR) M=$(PWD) help

# Install kernel module
install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
